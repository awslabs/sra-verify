"""
SRA-CT-5: CloudTrail CloudWatch Logs Configuration.
"""
from typing import List, Dict, Any
from sraverify.services.cloudtrail.base import CloudTrailCheck
from sraverify.core.logging import logger


class SRA_CT_5(CloudTrailCheck):
    """Check if trails have CloudWatch Logs configuration."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-CT-5"
        self.check_name = "CloudTrail has CloudWatch Logs configuration"
        self.account_type = "management"
        self.severity = "MEDIUM"
        self.description = (
            "This check verifies that CloudTrail has CloudWatch Logs configuration. "
            "CloudWatch Logs enables you to centralize the CloudTrail logs from all your AWS accounts and "
            "regions in the AWS Organization, to a single, highly scalable service. You can then easily "
            "view them, search them for specific error codes or patterns, filter them based on specific "
            "fields, or archive them securely for future analysis."
        )
        self.check_logic = (
            "Check if trails have CloudWatchLogsLogGroupArn and CloudWatchLogsRoleArn configured."
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        # Get all trails
        all_trails = self.describe_trails()
        
        if not all_trails:
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    account_id=account_id,
                    resource_id="cloudtrail:global",
                    checked_value="CloudWatchLogsLogGroupArn and CloudWatchLogsRoleArn: configured",
                    actual_value="No CloudTrail trails found",
                    remediation=(
                        "Create a CloudTrail trail with CloudWatch Logs configuration using the AWS CLI command: "
                        f"aws cloudtrail create-trail --name trail-with-cloudwatch --s3-bucket-name cloudtrail-logs-{account_id} "
                        f"--cloud-watch-logs-log-group-arn arn:aws:logs:{self.regions[0] if self.regions else 'us-east-1'}:{account_id}:log-group:CloudTrail/Logs:* "
                        f"--cloud-watch-logs-role-arn arn:aws:iam::{account_id}:role/CloudTrail_CloudWatchLogs_Role"
                    )
                )
            )
            return findings
        
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
                
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region="global",
                        account_id=account_id,
                        resource_id=resource_id,
                        checked_value="CloudWatchLogsLogGroupArn and CloudWatchLogsRoleArn: configured",
                        actual_value=(
                            f"CloudTrail '{trail_name}' has CloudWatch Logs configuration: "
                            f"CloudWatch Logs Group ARN: {cloudwatch_logs_group_arn}, "
                            f"CloudWatch Logs Role ARN: {cloudwatch_logs_role_arn}"
                        ),
                        remediation="No remediation needed"
                    )
                )
            else:
                # Trail does not have CloudWatch Logs configuration
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region="global",
                        account_id=account_id,
                        resource_id=trail_arn,
                        checked_value="CloudWatchLogsLogGroupArn and CloudWatchLogsRoleArn: configured",
                        actual_value=f"CloudTrail '{trail_name}' does not have CloudWatch Logs configuration",
                        remediation=(
                            f"Configure CloudTrail '{trail_name}' to use CloudWatch Logs using the AWS CLI command: "
                            f"aws cloudtrail update-trail --name {trail_name} "
                            f"--cloud-watch-logs-log-group-arn arn:aws:logs:{home_region}:{account_id}:log-group:CloudTrail/Logs:* "
                            f"--cloud-watch-logs-role-arn arn:aws:iam::{account_id}:role/CloudTrail_CloudWatchLogs_Role"
                        )
                    )
                )
        
        return findings
