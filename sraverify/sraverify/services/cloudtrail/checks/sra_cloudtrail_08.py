"""
SRA-CLOUDTRAIL-08: Organization CloudTrail S3 Delivery.
"""
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.cloudtrail.base import CloudTrailCheck


class SRA_CLOUDTRAIL_08(CloudTrailCheck):
    """Check if organization trails are publishing logs to destination S3 bucket."""

    meta = CheckMeta(
        check_id="SRA-CLOUDTRAIL-08",
        title="Organization trail is publishing logs to destination S3 bucket",
        description=(
            "This check verifies that last attempt to send CloudTrail logs to S3 bucket was successful. "
            "CloudTrail log files are an audit log of actions taken by an IAM identity or an AWS service. "
            "The integrity, completeness and availability of these logs is crucial for forensic and auditing purposes. "
            "By logging to a dedicated and centralized Amazon S3 bucket, you can enforce strict security controls, "
            "access, and segregation of duties."
        ),
        check_logic=(
            "Check if organization trails have LatestDeliveryTime within the last 24 hours."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="CloudTrail",
        resource_type="AWS::CloudTrail::Trail",
        remediation=Remediation(
            text=(
                "Confirm the trail is logging and that its S3 bucket policy allows "
                "CloudTrail to write objects, then verify a recent delivery time."
            ),
            cli=(
                "aws cloudtrail start-logging --name <trail-name> --region <home-region>\n"
                "aws cloudtrail get-trail-status --name <trail-name> --region <home-region>"
            ),
            console=(
                "CloudTrail console, Trails, select the organization trail, and review "
                "the S3 delivery status. Then check the destination bucket policy in "
                "the S3 console."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per organization trail, or one Finding when none exist.
        """
        # Get organization trails
        org_response = self.get_organization_trails()

        if "Error" in org_response:
            error = org_response['Error']
            if self.is_not_configured(error):
                yield self.failed(
                    region="global",
                    resource_id=f"organization/{self.account_id}",
                    actual_value="No CloudTrail trail exists for this account, so no organization trail is configured",
                )
            else:
                yield self.error(
                    region="global",
                    resource_id=f"organization/{self.account_id}",
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
            return

        org_trails = org_response.get('trailList', [])

        if not org_trails:
            yield self.failed(
                region="global",
                resource_id=f"organization/{self.account_id}",
                checked_value="LatestDeliveryTime: within last 24 hours",
                actual_value="No organization trails found",
                remediation=(
                    "Create an organization trail in the management account using the AWS CLI command: "
                    f"aws cloudtrail create-trail --name org-trail --is-organization-trail --s3-bucket-name cloudtrail-logs-{self.account_id} "
                    f"--is-multi-region-trail --region {self.regions[0] if self.regions else 'us-east-1'} && "
                    f"aws cloudtrail start-logging --name org-trail --region {self.regions[0] if self.regions else 'us-east-1'}"
                ),
            )
            return

        # Check each organization trail for S3 delivery
        for trail in org_trails:
            trail_name = trail.get('Name', 'Unknown')
            trail_arn = trail.get('TrailARN', 'Unknown')
            home_region = trail.get('HomeRegion', 'Unknown')
            s3_bucket_name = trail.get('S3BucketName', 'Unknown')

            # Get trail status to check S3 delivery
            status_response = self.get_trail_status(home_region, trail_arn)

            # Inside the per-trail loop, so one undetermined trail costs one row
            # rather than the whole check's output.
            if "Error" in status_response:
                error = status_response['Error']
                if self.is_not_configured(error):
                    yield self.failed(
                        region=home_region,
                        resource_id=trail_arn,
                        actual_value=(
                            f"Trail {trail_arn} does not exist"
                        ),
                    )
                else:
                    yield self.error(
                        region=home_region,
                        resource_id=trail_arn,
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            trail_status = status_response
            latest_delivery_time_str = trail_status.get('LatestDeliveryTime', None)
            latest_delivery_error = trail_status.get('LatestDeliveryError', None)

            # Check if delivery time exists and is within the last 24 hours
            if latest_delivery_time_str:
                latest_delivery_time = self.parse_delivery_time(latest_delivery_time_str)
                now = datetime.now(timezone.utc)
                if latest_delivery_time is None:
                    # AWS returned a timestamp this scanner cannot parse.
                    # A shape problem in the response, reported as the
                    # finding it is rather than caught as an exception --
                    # no `except` may appear inside execute().
                    yield self.failed(
                        region="global",
                        resource_id=trail_arn,
                        checked_value="LatestDeliveryTime: within last 24 hours",
                        actual_value=f"Organization trail '{trail_name}' has an invalid delivery time format: {latest_delivery_time_str}",
                        remediation=(
                            f"Check the CloudTrail configuration and S3 bucket permissions. Ensure the trail is active using: "
                            f"aws cloudtrail start-logging --name {trail_name} --region {home_region}"
                        ),
                    )
                    continue

                # Check if delivery was within the last 24 hours
                if now - latest_delivery_time < timedelta(hours=24):
                    # Trail is delivering logs to S3 within the last 24 hours
                    yield self.passed(
                        region="global",
                        resource_id=trail_arn,
                        checked_value="LatestDeliveryTime: within last 24 hours",
                        actual_value=f"Organization trail '{trail_name}' is publishing logs to S3 bucket '{s3_bucket_name}', latest delivery time: {latest_delivery_time_str}",
                    )
                else:
                    # Trail has not delivered logs to S3 within the last 24 hours
                    yield self.failed(
                        region="global",
                        resource_id=trail_arn,
                        checked_value="LatestDeliveryTime: within last 24 hours",
                        actual_value=f"Organization trail '{trail_name}' has not published logs to S3 bucket '{s3_bucket_name}' within the last 24 hours, latest delivery time: {latest_delivery_time_str}",
                        remediation=(
                            f"Check the CloudTrail configuration and S3 bucket permissions. Ensure the trail is active using: "
                            f"aws cloudtrail start-logging --name {trail_name} --region {home_region}"
                        ),
                    )
            else:
                # No delivery time found
                yield self.failed(
                    region="global",
                    resource_id=trail_arn,
                    checked_value="LatestDeliveryTime: within last 24 hours",
                    actual_value=f"Organization trail '{trail_name}' has no record of delivering logs to S3 bucket '{s3_bucket_name}'",
                    remediation=(
                        f"Check the CloudTrail configuration and S3 bucket permissions. Ensure the trail is active using: "
                        f"aws cloudtrail start-logging --name {trail_name} --region {home_region}"
                    ),
                )
