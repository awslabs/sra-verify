"""
SRA-S3-04: S3 block public policy is enabled.
"""
from typing import List, Dict, Any
from sraverify.services.s3.base import S3Check
from sraverify.core.logging import logger


class SRA_S3_04(S3Check):
    """Check if S3 block public policy is enabled for the account."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-S3-04"
        self.check_name = "S3 block public policy is enabled"
        self.account_type = "application"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether S3 should block public bucket policies for buckets. "
            "Setting this causes Amazon S3 to reject calls that attaches a public access bucket policy to a S3 bucket."
        )
        self.check_logic = (
            "Check if BlockPublicPolicy is set to true in the account's public access block configuration."
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
        
        # Check if the configuration exists and BlockPublicPolicy is enabled
        if not public_access_config:
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",  # S3 public access block is a global setting
                    account_id=account_id,
                    resource_id=account_id,
                    checked_value="BlockPublicPolicy: true",
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
        
        block_public_policy = public_access_config.get('BlockPublicPolicy', False)
        
        if block_public_policy:
            findings.append(
                self.create_finding(
                    status="PASS",
                    region="global",  # S3 public access block is a global setting
                    account_id=account_id,
                    resource_id=account_id,
                    checked_value="BlockPublicPolicy: true",
                    actual_value="BlockPublicPolicy setting is true",
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
                    checked_value="BlockPublicPolicy: true",
                    actual_value="BlockPublicPolicy setting is false",
                    remediation=(
                        "Enable S3 Block Public Policy at the account level using the AWS CLI command: "
                        f"aws s3control put-public-access-block --account-id {account_id} "
                        "--public-access-block-configuration BlockPublicPolicy=true"
                    )
                )
            )
        
        return findings
