"""
SRA-CT-8: Organization CloudTrail S3 Delivery.
"""
from typing import List, Dict, Any
from datetime import datetime, timedelta, timezone
from sraverify.services.cloudtrail.base import CloudTrailCheck
from sraverify.core.logging import logger


class SRA_CT_8(CloudTrailCheck):
    """Check if organization trails are publishing logs to destination S3 bucket."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-CT-8"
        self.check_name = "Organization trail is publishing logs to destination S3 bucket"
        self.account_type = "management"
        self.severity = "HIGH"
        self.description = (
            "This check verifies that last attempt to send CloudTrail logs to S3 bucket was successful. "
            "CloudTrail log files are an audit log of actions taken by an IAM identity or an AWS service. "
            "The integrity, completeness and availability of these logs is crucial for forensic and auditing purposes. "
            "By logging to a dedicated and centralized Amazon S3 bucket, you can enforce strict security controls, "
            "access, and segregation of duties."
        )
        self.check_logic = (
            "Check if organization trails have LatestDeliveryTime within the last 24 hours."
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        # Get organization trails
        org_trails = self.get_organization_trails()
        
        if not org_trails:
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    account_id=account_id,
                    resource_id=f"organization/{account_id}",
                    checked_value="LatestDeliveryTime: within last 24 hours",
                    actual_value="No organization trails found",
                    remediation=(
                        "Create an organization trail in the management account using the AWS CLI command: "
                        f"aws cloudtrail create-trail --name org-trail --is-organization-trail --s3-bucket-name cloudtrail-logs-{account_id} "
                        f"--is-multi-region-trail --region {self.regions[0] if self.regions else 'us-east-1'} && "
                        f"aws cloudtrail start-logging --name org-trail --region {self.regions[0] if self.regions else 'us-east-1'}"
                    )
                )
            )
            return findings
        
        # Check each organization trail for S3 delivery
        for trail in org_trails:
            trail_name = trail.get('Name', 'Unknown')
            trail_arn = trail.get('TrailARN', 'Unknown')
            home_region = trail.get('HomeRegion', 'Unknown')
            s3_bucket_name = trail.get('S3BucketName', 'Unknown')
            
            # Get trail status to check S3 delivery
            trail_status = self.get_trail_status(home_region, trail_arn)
            latest_delivery_time_str = trail_status.get('LatestDeliveryTime', None)
            latest_delivery_error = trail_status.get('LatestDeliveryError', None)
            
            # Check if delivery time exists and is within the last 24 hours
            if latest_delivery_time_str:
                try:
                    # Convert string to datetime object
                    if isinstance(latest_delivery_time_str, str):
                        latest_delivery_time = datetime.fromisoformat(latest_delivery_time_str.replace('Z', '+00:00'))
                    else:
                        # Assume it's already a datetime object
                        latest_delivery_time = latest_delivery_time_str
                    
                    # Get current time in UTC
                    now = datetime.now(timezone.utc)
                    
                    # Check if delivery was within the last 24 hours
                    if now - latest_delivery_time < timedelta(hours=24):
                        # Trail is delivering logs to S3 within the last 24 hours
                        findings.append(
                            self.create_finding(
                                status="PASS",
                                region="global",
                                account_id=account_id,
                                resource_id=trail_arn,
                                checked_value="LatestDeliveryTime: within last 24 hours",
                                actual_value=f"Organization trail '{trail_name}' is publishing logs to S3 bucket '{s3_bucket_name}', latest delivery time: {latest_delivery_time_str}",
                                remediation=""
                            )
                        )
                    else:
                        # Trail has not delivered logs to S3 within the last 24 hours
                        findings.append(
                            self.create_finding(
                                status="FAIL",
                                region="global",
                                account_id=account_id,
                                resource_id=trail_arn,
                                checked_value="LatestDeliveryTime: within last 24 hours",
                                actual_value=f"Organization trail '{trail_name}' has not published logs to S3 bucket '{s3_bucket_name}' within the last 24 hours, latest delivery time: {latest_delivery_time_str}",
                                remediation=(
                                    f"Check the CloudTrail configuration and S3 bucket permissions. Ensure the trail is active using: "
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
                            account_id=account_id,
                            resource_id=trail_arn,
                            checked_value="LatestDeliveryTime: within last 24 hours",
                            actual_value=f"Organization trail '{trail_name}' has an invalid delivery time format: {latest_delivery_time_str}, error: {str(e)}",
                            remediation=(
                                f"Check the CloudTrail configuration and S3 bucket permissions. Ensure the trail is active using: "
                                f"aws cloudtrail start-logging --name {trail_name} --region {home_region}"
                            )
                        )
                    )
            else:
                # No delivery time found
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region="global",
                        account_id=account_id,
                        resource_id=trail_arn,
                        checked_value="LatestDeliveryTime: within last 24 hours",
                        actual_value=f"Organization trail '{trail_name}' has no record of delivering logs to S3 bucket '{s3_bucket_name}'",
                        remediation=(
                            f"Check the CloudTrail configuration and S3 bucket permissions. Ensure the trail is active using: "
                            f"aws cloudtrail start-logging --name {trail_name} --region {home_region}"
                        )
                    )
                )
        
        return findings
