"""
SRA-CLOUDTRAIL-09: Organization CloudTrail CloudWatch Logs Delivery.
"""
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.cloudtrail.base import CloudTrailCheck


class SRA_CLOUDTRAIL_09(CloudTrailCheck):
    """Check if organization trails are publishing logs to CloudWatch Logs."""

    meta = CheckMeta(
        check_id="SRA-CLOUDTRAIL-09",
        title="Organization trail is publishing logs to CloudWatch Logs",
        description=(
            "This check verifies that last attempt to send CloudTrail logs to CloudWatch Logs was successful. "
            "Successful delivery of CloudTrails logs to CloudWatch ensures later availability for monitoring. "
            "CloudTrail requires right permission to send log events to CloudWatch Logs."
        ),
        check_logic=(
            "Check if organization trails have LatestCloudWatchLogsDeliveryTime within the last 24 hours."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.MANAGEMENT,
        service="CloudTrail",
        resource_type="AWS::CloudTrail::Trail",
        remediation=Remediation(
            text=(
                "Configure the organization trail with a CloudWatch Logs log group and "
                "role, and confirm the role can call CreateLogStream and PutLogEvents "
                "on that log group."
            ),
            cli=(
                "aws cloudtrail update-trail --name <trail-name> "
                "--cloud-watch-logs-log-group-arn <log-group-arn> "
                "--cloud-watch-logs-role-arn <role-arn> --region <home-region>"
            ),
            console=(
                "CloudTrail console, Trails, select the organization trail, Edit "
                "CloudWatch Logs, enable it, and supply a log group and an IAM role."
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
                checked_value="LatestCloudWatchLogsDeliveryTime: within last 24 hours",
                actual_value="No organization trails found",
                remediation=(
                    "Create an organization trail with CloudWatch Logs delivery in the management account using the AWS CLI command: "
                    f"aws cloudtrail create-trail --name org-trail --is-organization-trail --s3-bucket-name cloudtrail-logs-{self.account_id} "
                    f"--cloud-watch-logs-log-group-arn arn:aws:logs:{self.regions[0] if self.regions else 'us-east-1'}:{self.account_id}:log-group:CloudTrail/Logs:* "
                    f"--cloud-watch-logs-role-arn arn:aws:iam::{self.account_id}:role/CloudTrail_CloudWatchLogs_Role "
                    f"--is-multi-region-trail --region {self.regions[0] if self.regions else 'us-east-1'}"
                ),
            )
            return

        # Check each organization trail for CloudWatch Logs delivery
        for trail in org_trails:
            trail_name = trail.get('Name', 'Unknown')
            trail_arn = trail.get('TrailARN', 'Unknown')
            home_region = trail.get('HomeRegion', 'Unknown')
            cloudwatch_logs_group_arn = trail.get('CloudWatchLogsLogGroupArn', '')

            # Skip trails without CloudWatch Logs configuration
            if not cloudwatch_logs_group_arn:
                yield self.failed(
                    region="global",
                    resource_id=trail_arn,
                    checked_value="LatestCloudWatchLogsDeliveryTime: within last 24 hours",
                    actual_value=f"Organization trail '{trail_name}' is not configured to deliver logs to CloudWatch Logs",
                    remediation=(
                        f"Configure CloudTrail '{trail_name}' to use CloudWatch Logs using the AWS CLI command: "
                        f"aws cloudtrail update-trail --name {trail_name} "
                        f"--cloud-watch-logs-log-group-arn arn:aws:logs:{home_region}:{self.account_id}:log-group:CloudTrail/Logs:* "
                        f"--cloud-watch-logs-role-arn arn:aws:iam::{self.account_id}:role/CloudTrail_CloudWatchLogs_Role "
                        f"--region {home_region}"
                    ),
                )
                continue

            # Get trail status to check CloudWatch Logs delivery
            trail_status = self.get_trail_status(home_region, trail_arn)
            latest_cloudwatch_logs_delivery_time_str = trail_status.get('LatestCloudWatchLogsDeliveryTime', None)
            latest_cloudwatch_logs_delivery_error = trail_status.get('LatestCloudWatchLogsDeliveryError', None)

            # Check if delivery time exists and is within the last 24 hours
            if latest_cloudwatch_logs_delivery_time_str:
                try:
                    # Convert string to datetime object
                    if isinstance(latest_cloudwatch_logs_delivery_time_str, str):
                        latest_delivery_time = datetime.fromisoformat(latest_cloudwatch_logs_delivery_time_str.replace('Z', '+00:00'))
                    else:
                        # Assume it's already a datetime object
                        latest_delivery_time = latest_cloudwatch_logs_delivery_time_str

                    # Get current time in UTC
                    now = datetime.now(timezone.utc)

                    # Use the delivery time as the resource ID
                    resource_id = f"cloudtrail arn delivery to CloudWatch logs within 24 hrs = true"

                    # Check if delivery was within the last 24 hours
                    if now - latest_delivery_time < timedelta(hours=24):
                        # Trail is delivering logs to CloudWatch Logs within the last 24 hours
                        yield self.passed(
                            region="global",
                            resource_id=resource_id,
                            checked_value="LatestCloudWatchLogsDeliveryTime: within last 24 hours",
                            actual_value=f"Organization trail '{trail_name}' is publishing logs to CloudWatch Logs, latest delivery time: {latest_cloudwatch_logs_delivery_time_str}",
                        )
                    else:
                        # Trail has not delivered logs to CloudWatch Logs within the last 24 hours
                        yield self.failed(
                            region="global",
                            resource_id=resource_id,
                            checked_value="LatestCloudWatchLogsDeliveryTime: within last 24 hours",
                            actual_value=f"Organization trail '{trail_name}' has not published logs to CloudWatch Logs within the last 24 hours, latest delivery time: {latest_cloudwatch_logs_delivery_time_str}",
                            remediation=(
                                f"Check the CloudTrail configuration and CloudWatch Logs permissions. Ensure the trail is active using: "
                                f"aws cloudtrail start-logging --name {trail_name} --region {home_region}"
                            ),
                        )
                except (ValueError, TypeError) as e:
                    # Error parsing delivery time
                    yield self.failed(
                        region="global",
                        resource_id=trail_arn,
                        checked_value="LatestCloudWatchLogsDeliveryTime: within last 24 hours",
                        actual_value=f"Organization trail '{trail_name}' has an invalid CloudWatch Logs delivery time format: {latest_cloudwatch_logs_delivery_time_str}, error: {str(e)}",
                        remediation=(
                            f"Check the CloudTrail configuration and CloudWatch Logs permissions. Ensure the trail is active using: "
                            f"aws cloudtrail start-logging --name {trail_name} --region {home_region}"
                        ),
                    )
            else:
                # No CloudWatch Logs delivery time found
                yield self.failed(
                    region="global",
                    resource_id=trail_arn,
                    checked_value="LatestCloudWatchLogsDeliveryTime: within last 24 hours",
                    actual_value=f"Organization trail '{trail_name}' has no record of delivering logs to CloudWatch Logs",
                    remediation=(
                        f"Check the CloudTrail configuration and CloudWatch Logs permissions. Ensure the trail is active using: "
                        f"aws cloudtrail start-logging --name {trail_name} --region {home_region}"
                    ),
                )
