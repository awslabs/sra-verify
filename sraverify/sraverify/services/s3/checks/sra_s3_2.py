"""
SRA-S3-2: S3 block public ACLs is set.
"""
from typing import List, Dict, Any
from sraverify.services.s3.base import S3Check
from sraverify.core.logging import logger


class SRA_S3_2(S3Check):
    """Check if S3 block public ACLs is enabled for the account."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-S3-2"
        self.check_name = "S3 block public ACLs is set"
        self.account_type = "application"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether S3 public block access control lists (ACLs) for buckets and object is enabled. "
            "Setting this fails prevents from setting a public ACL on S3 buckets and Objects. It also prevent creating "
            "a bucket with public ACL and uploading a object with public ACL."
        )
        self.check_logic = (
            "Check if BlockPublicAcls is set to true in the account's public access block configuration."
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
        
        # Check if the configuration exists and BlockPublicAcls is enabled
        if not public_access_config:
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",  # S3 public access block is a global setting
                    account_id=account_id,
                    resource_id=account_id,
                    checked_value="BlockPublicAcls: true",
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
        
        block_public_acls = public_access_config.get('BlockPublicAcls', False)
        
        if block_public_acls:
            findings.append(
                self.create_finding(
                    status="PASS",
                    region="global",  # S3 public access block is a global setting
                    account_id=account_id,
                    resource_id=account_id,
                    checked_value="BlockPublicAcls: true",
                    actual_value="BlockPublicAcls setting is true",
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
                    checked_value="BlockPublicAcls: true",
                    actual_value="BlockPublicAcls setting is false",
                    remediation=(
                        "Enable S3 Block Public Access at the account level using the AWS CLI command: "
                        f"aws s3control put-public-access-block --account-id {account_id} "
                        "--public-access-block-configuration BlockPublicAcls=true"
                    )
                )
            )
        
        return findings
