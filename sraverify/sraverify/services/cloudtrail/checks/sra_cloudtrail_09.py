"""
SRA-CLOUDTRAIL-09: Organization CloudTrail CloudWatch Logs Delivery.
"""
from typing import List, Dict, Any
from datetime import datetime, timedelta, timezone
from sraverify.services.cloudtrail.base import CloudTrailCheck
from sraverify.core.logging import logger


class SRA_CLOUDTRAIL_09(CloudTrailCheck):
    """Check if organization trails are publishing logs to CloudWatch Logs."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-CLOUDTRAIL-09"
        self.check_name = "Organization trail is publishing logs to CloudWatch Logs"
        self.account_type = "management"
        self.severity = "MEDIUM"
        self.description = (
            "This check verifies that last attempt to send CloudTrail logs to CloudWatch Logs was successful. "
            "Successful delivery of CloudTrails logs to CloudWatch ensures later availability for monitoring. "
            "CloudTrail requires right permission to send log events to CloudWatch Logs."
        )
        self.check_logic = (
            "Check if organization trails have LatestCloudWatchLogsDeliveryTime within the last 24 hours."
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        
        # Get organization trails
        org_trails = self.get_organization_trails()
        
        if not org_trails:
            findings.append(
                self.create_finding(
                    status="FAIL",
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
                    )
                )
            )
            return findings
        
        # Check each organization trail for CloudWatch Logs delivery
        for trail in org_trails:
            trail_name = trail.get('Name', 'Unknown')
            trail_arn = trail.get('TrailARN', 'Unknown')
            home_region = trail.get('HomeRegion', 'Unknown')
            cloudwatch_logs_group_arn = trail.get('CloudWatchLogsLogGroupArn', '')
            
            # Skip trails without CloudWatch Logs configuration
            if not cloudwatch_logs_group_arn:
                findings.append(
                    self.create_finding(
                        status="FAIL",
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
                        )
                    )
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
                        findings.append(
                            self.create_finding(
                                status="PASS",
                                region="global",
                                resource_id=resource_id,
                                checked_value="LatestCloudWatchLogsDeliveryTime: within last 24 hours",
                                actual_value=f"Organization trail '{trail_name}' is publishing logs to CloudWatch Logs, latest delivery time: {latest_cloudwatch_logs_delivery_time_str}",
                                remediation="No remediation needed"
                            )
                        )
                    else:
                        # Trail has not delivered logs to CloudWatch Logs within the last 24 hours
                        findings.append(
                            self.create_finding(
                                status="FAIL",
                                region="global",
                                resource_id=resource_id,
                                checked_value="LatestCloudWatchLogsDeliveryTime: within last 24 hours",
                                actual_value=f"Organization trail '{trail_name}' has not published logs to CloudWatch Logs within the last 24 hours, latest delivery time: {latest_cloudwatch_logs_delivery_time_str}",
                                remediation=(
                                    f"Check the CloudTrail configuration and CloudWatch Logs permissions. Ensure the trail is active using: "
                                    f"aws cloudtrail start-logging --name {trail_name} --region {home_region}"
                                )
                            )
                        )
                except (ValueError, TypeError) as e:
                    # Error parsing delivery time
                    findings.append(
                        self.create_finding(
                            status="FAIL",
                            region="global",
                            resource_id=trail_arn,
                            checked_value="LatestCloudWatchLogsDeliveryTime: within last 24 hours",
                            actual_value=f"Organization trail '{trail_name}' has an invalid CloudWatch Logs delivery time format: {latest_cloudwatch_logs_delivery_time_str}, error: {str(e)}",
                            remediation=(
                                f"Check the CloudTrail configuration and CloudWatch Logs permissions. Ensure the trail is active using: "
                                f"aws cloudtrail start-logging --name {trail_name} --region {home_region}"
                            )
                        )
                    )
            else:
                # No CloudWatch Logs delivery time found
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region="global",
                        resource_id=trail_arn,
                        checked_value="LatestCloudWatchLogsDeliveryTime: within last 24 hours",
                        actual_value=f"Organization trail '{trail_name}' has no record of delivering logs to CloudWatch Logs",
                        remediation=(
                            f"Check the CloudTrail configuration and CloudWatch Logs permissions. Ensure the trail is active using: "
                            f"aws cloudtrail start-logging --name {trail_name} --region {home_region}"
                        )
                    )
                )
        
        return findings
