"""
SRA-CT-10: Organization CloudTrail Log File Validation Digest Delivery.
"""
from typing import List, Dict, Any
from datetime import datetime, timedelta, timezone
from sraverify.services.cloudtrail.base import CloudTrailCheck
from sraverify.core.logging import logger


class SRA_CT_10(CloudTrailCheck):
    """Check if organization trails are delivering log file validation digest files."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-CT-10"
        self.check_name = "Organization trail is configured to deliver Log file validation digest files to destination bucket"
        self.account_type = "management"
        self.severity = "MEDIUM"
        self.description = (
            "This check verifies that log file validation digest files are being successfully delivered to a S3 bucket."
        )
        self.check_logic = (
            "Check if organization trails have LatestDigestDeliveryTime within the last 24 hours."
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
                    checked_value="LatestDigestDeliveryTime: within last 24 hours",
                    actual_value="No organization trails found",
                    remediation=(
                        "Create an organization trail with log file validation in the management account using the AWS CLI command: "
                        f"aws cloudtrail create-trail --name org-trail --is-organization-trail --s3-bucket-name cloudtrail-logs-{account_id} "
                        f"--enable-log-file-validation --is-multi-region-trail --region {self.regions[0] if self.regions else 'us-east-1'}"
                    )
                )
            )
            return findings
        
        # Check each organization trail for digest delivery
        for trail in org_trails:
            trail_name = trail.get('Name', 'Unknown')
            trail_arn = trail.get('TrailARN', 'Unknown')
            home_region = trail.get('HomeRegion', 'Unknown')
            log_file_validation_enabled = trail.get('LogFileValidationEnabled', False)
            s3_bucket_name = trail.get('S3BucketName', 'Unknown')
            
            # Skip trails without log file validation enabled
            if not log_file_validation_enabled:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region="global",
                        account_id=account_id,
                        resource_id=trail_arn,
                        checked_value="LatestDigestDeliveryTime: within last 24 hours",
                        actual_value=f"Organization trail '{trail_name}' does not have log file validation enabled",
                        remediation=(
                            f"Enable log file validation for the organization trail '{trail_name}' using the AWS CLI command: "
                            f"aws cloudtrail update-trail --name {trail_name} --enable-log-file-validation --region {home_region}"
                        )
                    )
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
                        findings.append(
                            self.create_finding(
                                status="PASS",
                                region="global",
                                account_id=account_id,
                                resource_id=resource_id,
                                checked_value="LatestDigestDeliveryTime: within last 24 hours",
                                actual_value=f"Organization trail '{trail_name}' is delivering log file validation digest files to S3 bucket '{s3_bucket_name}', latest delivery time: {latest_digest_delivery_time_str}",
                                remediation="No remediation needed"
                            )
                        )
                    else:
                        # Trail has not delivered digest files within the last 24 hours
                        findings.append(
                            self.create_finding(
                                status="FAIL",
                                region="global",
                                account_id=account_id,
                                resource_id=resource_id,
                                checked_value="LatestDigestDeliveryTime: within last 24 hours",
                                actual_value=f"Organization trail '{trail_name}' has not delivered log file validation digest files to S3 bucket '{s3_bucket_name}' within the last 24 hours, latest delivery time: {latest_digest_delivery_time_str}",
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
                            checked_value="LatestDigestDeliveryTime: within last 24 hours",
                            actual_value=f"Organization trail '{trail_name}' has an invalid digest delivery time format: {latest_digest_delivery_time_str}, error: {str(e)}",
                            remediation=(
                                f"Check the CloudTrail configuration and S3 bucket permissions. Ensure the trail is active using: "
                                f"aws cloudtrail start-logging --name {trail_name} --region {home_region}"
                            )
                        )
                    )
            else:
                # No digest delivery time found
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region="global",
                        account_id=account_id,
                        resource_id=trail_arn,
                        checked_value="LatestDigestDeliveryTime: within last 24 hours",
                        actual_value=f"Organization trail '{trail_name}' has no record of delivering log file validation digest files to S3 bucket '{s3_bucket_name}'",
                        remediation=(
                            f"Check the CloudTrail configuration and S3 bucket permissions. Ensure the trail is active and log file validation is enabled using: "
                            f"aws cloudtrail update-trail --name {trail_name} --enable-log-file-validation --region {home_region} && "
                            f"aws cloudtrail start-logging --name {trail_name} --region {home_region}"
                        )
                    )
                )
        
        return findings
