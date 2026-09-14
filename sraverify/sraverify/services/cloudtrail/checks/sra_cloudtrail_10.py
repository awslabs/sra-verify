"""
SRA-CLOUDTRAIL-10: Organization CloudTrail Log File Validation Digest Delivery.
"""
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.cloudtrail.base import CloudTrailCheck


class SRA_CLOUDTRAIL_10(CloudTrailCheck):
    """Check if organization trails are delivering log file validation digest files."""

    meta = CheckMeta(
        check_id="SRA-CLOUDTRAIL-10",
        title="Organization trail is configured to deliver Log file validation digest files to destination bucket",
        description=(
            "This check verifies that log file validation digest files are being successfully delivered to a S3 bucket."
        ),
        check_logic=(
            "Check if organization trails have LatestDigestDeliveryTime within the last 24 hours."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.MANAGEMENT,
        service="CloudTrail",
        resource_type="AWS::CloudTrail::Trail",
        remediation=Remediation(
            text=(
                "Enable log file validation on the organization trail and confirm the "
                "destination bucket policy allows CloudTrail to write digest files."
            ),
            cli=(
                "aws cloudtrail update-trail --name <trail-name> "
                "--enable-log-file-validation --region <home-region>\n"
                "aws cloudtrail start-logging --name <trail-name> --region <home-region>"
            ),
            console=(
                "CloudTrail console, Trails, select the organization trail, Edit "
                "Additional settings, set Log file validation to Enabled, then review "
                "the digest delivery status."
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
        org_trails = self.get_organization_trails()

        if not org_trails:
            yield self.failed(
                region="global",
                resource_id=f"organization/{self.account_id}",
                checked_value="LatestDigestDeliveryTime: within last 24 hours",
                actual_value="No organization trails found",
                remediation=(
                    "Create an organization trail with log file validation in the management account using the AWS CLI command: "
                    f"aws cloudtrail create-trail --name org-trail --is-organization-trail --s3-bucket-name cloudtrail-logs-{self.account_id} "
                    f"--enable-log-file-validation --is-multi-region-trail --region {self.regions[0] if self.regions else 'us-east-1'}"
                ),
            )
            return

        # Check each organization trail for digest delivery
        for trail in org_trails:
            trail_name = trail.get('Name', 'Unknown')
            trail_arn = trail.get('TrailARN', 'Unknown')
            home_region = trail.get('HomeRegion', 'Unknown')
            log_file_validation_enabled = trail.get('LogFileValidationEnabled', False)
            s3_bucket_name = trail.get('S3BucketName', 'Unknown')

            # Skip trails without log file validation enabled
            if not log_file_validation_enabled:
                yield self.failed(
                    region="global",
                    resource_id=trail_arn,
                    checked_value="LatestDigestDeliveryTime: within last 24 hours",
                    actual_value=f"Organization trail '{trail_name}' does not have log file validation enabled",
                    remediation=(
                        f"Enable log file validation for the organization trail '{trail_name}' using the AWS CLI command: "
                        f"aws cloudtrail update-trail --name {trail_name} --enable-log-file-validation --region {home_region}"
                    ),
                )
                continue

            # Get trail status to check digest delivery
            trail_status = self.get_trail_status(home_region, trail_arn)
            latest_digest_delivery_time_str = trail_status.get('LatestDigestDeliveryTime', None)
            latest_digest_delivery_error = trail_status.get('LatestDigestDeliveryError', None)

            # Use the trail ARN with digest info as the resource ID
            resource_id = f"cloudtrail arn of digest within 24 hrs = true"

            # Check if digest delivery time exists and is within the last 24 hours
            if latest_digest_delivery_time_str:
                try:
                    # Convert string to datetime object
                    if isinstance(latest_digest_delivery_time_str, str):
                        latest_delivery_time = datetime.fromisoformat(latest_digest_delivery_time_str.replace('Z', '+00:00'))
                    else:
                        # Assume it's already a datetime object
                        latest_delivery_time = latest_digest_delivery_time_str

                    # Get current time in UTC
                    now = datetime.now(timezone.utc)

                    # Check if delivery was within the last 24 hours
                    if now - latest_delivery_time < timedelta(hours=24):
                        # Trail is delivering digest files within the last 24 hours
                        yield self.passed(
                            region="global",
                            resource_id=resource_id,
                            checked_value="LatestDigestDeliveryTime: within last 24 hours",
                            actual_value=f"Organization trail '{trail_name}' is delivering log file validation digest files to S3 bucket '{s3_bucket_name}', latest delivery time: {latest_digest_delivery_time_str}",
                        )
                    else:
                        # Trail has not delivered digest files within the last 24 hours
                        yield self.failed(
                            region="global",
                            resource_id=resource_id,
                            checked_value="LatestDigestDeliveryTime: within last 24 hours",
                            actual_value=f"Organization trail '{trail_name}' has not delivered log file validation digest files to S3 bucket '{s3_bucket_name}' within the last 24 hours, latest delivery time: {latest_digest_delivery_time_str}",
                            remediation=(
                                f"Check the CloudTrail configuration and S3 bucket permissions. Ensure the trail is active using: "
                                f"aws cloudtrail start-logging --name {trail_name} --region {home_region}"
                            ),
                        )
                except (ValueError, TypeError) as e:
                    # Error parsing delivery time
                    yield self.failed(
                        region="global",
                        resource_id=trail_arn,
                        checked_value="LatestDigestDeliveryTime: within last 24 hours",
                        actual_value=f"Organization trail '{trail_name}' has an invalid digest delivery time format: {latest_digest_delivery_time_str}, error: {str(e)}",
                        remediation=(
                            f"Check the CloudTrail configuration and S3 bucket permissions. Ensure the trail is active using: "
                            f"aws cloudtrail start-logging --name {trail_name} --region {home_region}"
                        ),
                    )
            else:
                # No digest delivery time found
                yield self.failed(
                    region="global",
                    resource_id=trail_arn,
                    checked_value="LatestDigestDeliveryTime: within last 24 hours",
                    actual_value=f"Organization trail '{trail_name}' has no record of delivering log file validation digest files to S3 bucket '{s3_bucket_name}'",
                    remediation=(
                        f"Check the CloudTrail configuration and S3 bucket permissions. Ensure the trail is active and log file validation is enabled using: "
                        f"aws cloudtrail update-trail --name {trail_name} --enable-log-file-validation --region {home_region} && "
                        f"aws cloudtrail start-logging --name {trail_name} --region {home_region}"
                    ),
                )
