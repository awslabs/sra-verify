"""
SRA-CLOUDTRAIL-05: CloudTrail CloudWatch Logs Configuration.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.cloudtrail.base import CloudTrailCheck


class SRA_CLOUDTRAIL_05(CloudTrailCheck):
    """Check if trails have CloudWatch Logs configuration."""

    meta = CheckMeta(
        check_id="SRA-CLOUDTRAIL-05",
        title="CloudTrail has CloudWatch Logs configuration",
        description=(
            "This check verifies that CloudTrail has CloudWatch Logs configuration. "
            "CloudWatch Logs enables you to centralize the CloudTrail logs from all your AWS accounts and "
            "regions in the AWS Organization, to a single, highly scalable service. You can then easily "
            "view them, search them for specific error codes or patterns, filter them based on specific "
            "fields, or archive them securely for future analysis."
        ),
        check_logic=(
            "Check if trails have CloudWatchLogsLogGroupArn and CloudWatchLogsRoleArn configured."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.MANAGEMENT,
        service="CloudTrail",
        resource_type="AWS::CloudTrail::Trail",
        remediation=Remediation(
            text=(
                "Set both CloudWatchLogsLogGroupArn and CloudWatchLogsRoleArn on the "
                "trail so that events are also delivered to CloudWatch Logs."
            ),
            cli=(
                "aws cloudtrail update-trail --name <trail-name> "
                "--cloud-watch-logs-log-group-arn <log-group-arn> "
                "--cloud-watch-logs-role-arn <role-arn> --region <home-region>"
            ),
            console=(
                "CloudTrail console, Trails, select the trail, Edit CloudWatch Logs, "
                "enable it, and supply a log group and an IAM role."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per trail, or one Finding when no trail exists.
        """
        # Get all trails
        trails_response = self.describe_trails()

        if "Error" in trails_response:
            error = trails_response['Error']
            if self.is_not_configured(error):
                yield self.failed(
                    region="global",
                    resource_id="cloudtrail:global",
                    actual_value="No CloudTrail trail exists for this account, so no organization trail is configured",
                )
            else:
                yield self.error(
                    region="global",
                    resource_id="cloudtrail:global",
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
            return

        all_trails = trails_response.get('trailList', [])

        if not all_trails:
            yield self.failed(
                region="global",
                resource_id="cloudtrail:global",
                checked_value="CloudWatchLogsLogGroupArn and CloudWatchLogsRoleArn: configured",
                actual_value="No CloudTrail trails found",
                remediation=(
                    "Create a CloudTrail trail with CloudWatch Logs configuration using the AWS CLI command: "
                    f"aws cloudtrail create-trail --name trail-with-cloudwatch --s3-bucket-name cloudtrail-logs-{self.account_id} "
                    f"--cloud-watch-logs-log-group-arn arn:aws:logs:{self.regions[0] if self.regions else 'us-east-1'}:{self.account_id}:log-group:CloudTrail/Logs:* "
                    f"--cloud-watch-logs-role-arn arn:aws:iam::{self.account_id}:role/CloudTrail_CloudWatchLogs_Role"
                ),
            )
            return

        # Check each trail for CloudWatch Logs configuration
        for trail in all_trails:
            trail_name = trail.get('Name', 'Unknown')
            trail_arn = trail.get('TrailARN', 'Unknown')
            cloudwatch_logs_group_arn = trail.get('CloudWatchLogsLogGroupArn', '')
            cloudwatch_logs_role_arn = trail.get('CloudWatchLogsRoleArn', '')

            # Get the home region from the trail
            home_region = trail.get('HomeRegion', self.regions[0] if self.regions else 'us-east-1')

            if cloudwatch_logs_group_arn and cloudwatch_logs_role_arn:
                # Trail has CloudWatch Logs configuration
                resource_id = f"{cloudwatch_logs_group_arn},{cloudwatch_logs_role_arn}"

                yield self.passed(
                    region="global",
                    resource_id=resource_id,
                    checked_value="CloudWatchLogsLogGroupArn and CloudWatchLogsRoleArn: configured",
                    actual_value=(
                        f"CloudTrail '{trail_name}' has CloudWatch Logs configuration: "
                        f"CloudWatch Logs Group ARN: {cloudwatch_logs_group_arn}, "
                        f"CloudWatch Logs Role ARN: {cloudwatch_logs_role_arn}"
                    ),
                )
            else:
                # Trail does not have CloudWatch Logs configuration
                yield self.failed(
                    region="global",
                    resource_id=trail_arn,
                    checked_value="CloudWatchLogsLogGroupArn and CloudWatchLogsRoleArn: configured",
                    actual_value=f"CloudTrail '{trail_name}' does not have CloudWatch Logs configuration",
                    remediation=(
                        f"Configure CloudTrail '{trail_name}' to use CloudWatch Logs using the AWS CLI command: "
                        f"aws cloudtrail update-trail --name {trail_name} "
                        f"--cloud-watch-logs-log-group-arn arn:aws:logs:{home_region}:{self.account_id}:log-group:CloudTrail/Logs:* "
                        f"--cloud-watch-logs-role-arn arn:aws:iam::{self.account_id}:role/CloudTrail_CloudWatchLogs_Role"
                    ),
                )
