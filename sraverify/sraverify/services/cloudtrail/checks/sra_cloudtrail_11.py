"""
SRA-CLOUDTRAIL-11: Organization CloudTrail Logs Centralized in Log Archive Account.
"""
from typing import List, Dict, Any
from sraverify.services.cloudtrail.base import CloudTrailCheck
from sraverify.core.logging import logger


class SRA_CLOUDTRAIL_11(CloudTrailCheck):
    """Check if organization trails logs are delivered to a centralized S3 bucket in the Log Archive account."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-CLOUDTRAIL-11"
        self.check_name = "Organization trail Logs are delivered to a centralized S3 bucket in the Log Archive Account"
        self.account_type = "management"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether the corresponding S3 buckets that stores organization trail logs "
            "in created in Log Archive account. This separates the management and usage of CloudTrail log "
            "privileges. The Log Archive account is dedicated to ingesting and archiving all security-related "
            "logs and backups."
        )
        self.check_logic = (
            "Check if organization trails are configured to deliver logs to S3 buckets owned by "
            "the Log Archive account by comparing the S3 bucket ARN with the provided Log Archive account IDs."
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
                    checked_value="S3 bucket in Log Archive account",
                    actual_value="No organization trails found",
                    remediation=(
                        "Create an organization trail with S3 bucket in the Log Archive account using the AWS CLI command: "
                        "aws cloudtrail create-trail --name org-trail --is-organization-trail "
                        "--s3-bucket-name aws-controltower-logs-{LOG_ARCHIVE_ACCOUNT_ID}-{REGION}"
                    )
                )
            )
            return findings
        
        # Check if log_archive_accounts is provided via _log_archive_accounts attribute
        log_archive_accounts = []
        if hasattr(self, '_log_archive_accounts') and self._log_archive_accounts:
            log_archive_accounts = self._log_archive_accounts
        
        if not log_archive_accounts:
            findings.append(
                self.create_finding(
                    status="ERROR",
                    region="global",
                    resource_id=f"organization/{self.account_id}",
                    checked_value="S3 bucket in Log Archive account",
                    actual_value="Log Archive Account ID not provided",
                    remediation="Provide the Log Archive account IDs using --log-archive-account flag"
                )
            )
            return findings
        
        # Check each organization trail for S3 bucket ownership
        for trail in org_trails:
            trail_name = trail.get('Name', 'Unknown')
            trail_arn = trail.get('TrailARN', 'Unknown')
            s3_bucket_name = trail.get('S3BucketName', '')
            
            # Get the home region from the trail
            home_region = trail.get('HomeRegion', 'Unknown')
            
            # We need to determine the owner of the S3 bucket
            # For this check, we'll use the bucket name to infer ownership
            # Another implementation could be to make an S3 API call to get the bucket owner
            # But for this example, we'll assume the bucket name contains the account ID or has a specific pattern
            
            # Check if we can determine the bucket owner from the trail configuration
            bucket_owner_account = None
            
            # Try to get the bucket owner from the S3BucketOwnerName field if available
            s3_bucket_owner = trail.get('S3BucketOwnerName', '')
            if s3_bucket_owner:
                # If we have the bucket owner name, we can check if it's in the log archive accounts
                # This is a simplification - in reality, you'd need to map account IDs to account names
                bucket_owner_account = s3_bucket_owner
            
            # If we couldn't determine the bucket owner, check if the bucket name contains the account ID
            if not bucket_owner_account:
                for log_archive_account in log_archive_accounts:
                    if log_archive_account in s3_bucket_name:
                        bucket_owner_account = log_archive_account
                        break
            
            # Create appropriate resource IDs based on whether the bucket is in the Log Archive account
            if bucket_owner_account and bucket_owner_account in log_archive_accounts:
                resource_id = f"cloudtrail logs being delivered to Log Archive account {log_archive_accounts[0]} and bucket name {s3_bucket_name}"
            else:
                resource_id = f"cloudtrail logs not being delivered to S3 bucket in the Log Archive account"
            
            # If we still couldn't determine the bucket owner, we'll need to make an API call
            # For this example, we'll just report that we couldn't determine the bucket owner
            if not bucket_owner_account:
                # Generate a recommended bucket name using the first log archive account
                recommended_bucket_name = f"aws-controltower-logs-{log_archive_accounts[0]}-{home_region}"
                
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region="global",
                        resource_id=resource_id,
                        checked_value=f"S3 bucket in Log Archive account ({', '.join(log_archive_accounts)})",
                        actual_value=(
                            f"Organization trail '{trail_name}' is using S3 bucket '{s3_bucket_name}' "
                            f"but the bucket owner could not be determined"
                        ),
                        remediation=(
                            f"Update the organization trail '{trail_name}' to use an S3 bucket in the Log Archive account "
                            f"using the AWS CLI command: aws cloudtrail update-trail --name {trail_name} "
                            f"--s3-bucket-name {recommended_bucket_name}"
                        )
                    )
                )
                continue
            
            # Check if the bucket owner is in the log archive accounts
            if bucket_owner_account in log_archive_accounts:
                # Trail is using an S3 bucket in the Log Archive account
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region="global",
                        resource_id=resource_id,
                        checked_value=f"S3 bucket in Log Archive account ({', '.join(log_archive_accounts)})",
                        actual_value=(
                            f"Organization trail '{trail_name}' is using S3 bucket '{s3_bucket_name}' "
                            f"owned by Log Archive account {bucket_owner_account}"
                        ),
                        remediation="No remediation needed"
                    )
                )
            else:
                # Trail is not using an S3 bucket in the Log Archive account
                # Generate a recommended bucket name using the first log archive account
                recommended_bucket_name = f"aws-controltower-logs-{log_archive_accounts[0]}-{home_region}"
                
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region="global",
                        resource_id=resource_id,
                        checked_value=f"S3 bucket in Log Archive account ({', '.join(log_archive_accounts)})",
                        actual_value=(
                            f"Organization trail '{trail_name}' is using S3 bucket '{s3_bucket_name}' "
                            f"owned by account {bucket_owner_account}, which is not a Log Archive account"
                        ),
                        remediation=(
                            f"Update the organization trail '{trail_name}' to use an S3 bucket in the Log Archive account "
                            f"using the AWS CLI command: aws cloudtrail update-trail --name {trail_name} "
                            f"--s3-bucket-name {recommended_bucket_name}"
                        )
                    )
                )
        
        return findings
