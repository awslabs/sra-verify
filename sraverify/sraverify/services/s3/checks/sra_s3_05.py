"""
SRA-S3-05: S3 restrict public bucket is enabled.
"""
from typing import List, Dict, Any
from sraverify.services.s3.base import S3Check
from sraverify.core.logging import logger


class SRA_S3_05(S3Check):
    """Check if S3 restrict public bucket is enabled for the account."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-S3-05"
        self.check_name = "S3 restrict public bucket is enabled"
        self.account_type = "application"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether S3 should restrict public policies for S3 buckets. "
            "Setting this restricts access to this bucket to only AWS service principals and authorized users "
            "within this account if the bucket has a public policy."
        )
        self.check_logic = (
            "Check if RestrictPublicBuckets is set to true in the account's public access block configuration."
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        # Get public access block configuration using the base class method
        # This will use the cache if available or make API calls if needed
        public_access_config = self.get_public_access()
        
        # Check if the configuration exists and RestrictPublicBuckets is enabled
        if not public_access_config:
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",  # S3 public access block is a global setting
                    account_id=account_id,
                    resource_id=account_id,
                    checked_value="RestrictPublicBuckets: true",
                    actual_value="No public access block configuration found",
                    remediation=(
                        "Enable S3 Block Public Access at the account level using the AWS CLI command: "
                        f"aws s3control put-public-access-block --account-id {account_id} "
                        "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
                        "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                    )
                )
            )
            return findings
        
        restrict_public_buckets = public_access_config.get('RestrictPublicBuckets', False)
        
        if restrict_public_buckets:
            findings.append(
                self.create_finding(
                    status="PASS",
                    region="global",  # S3 public access block is a global setting
                    account_id=account_id,
                    resource_id=account_id,
                    checked_value="RestrictPublicBuckets: true",
                    actual_value="RestrictPublicBuckets setting is true",
                    remediation="No remediation needed"
                )
            )
        else:
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",  # S3 public access block is a global setting
                    account_id=account_id,
                    resource_id=account_id,
                    checked_value="RestrictPublicBuckets: true",
                    actual_value="RestrictPublicBuckets setting is false",
                    remediation=(
                        "Enable S3 Restrict Public Buckets at the account level using the AWS CLI command: "
                        f"aws s3control put-public-access-block --account-id {account_id} "
                        "--public-access-block-configuration RestrictPublicBuckets=true"
                    )
                )
            )
        
        return findings
