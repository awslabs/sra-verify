"""
SRA-S3-03: S3 ignore public ACL is enabled.
"""
from typing import List, Dict, Any
from sraverify.services.s3.base import S3Check
from sraverify.core.logging import logger


class SRA_S3_03(S3Check):
    """Check if S3 ignore public ACLs is enabled for the account."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-S3-03"
        self.check_name = "S3 ignore public ACL is enabled"
        self.account_type = "application"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether the IgnorePublicACLs is set to True. Setting this causes Amazon S3 "
            "to ignore all public ACLs on buckets and objects in the bucket."
        )
        self.check_logic = (
            "Check if IgnorePublicAcls is set to true in the account's public access block configuration."
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        
        # Get public access block configuration using the base class method
        # This will use the cache if available or make API calls if needed
        public_access_config = self.get_public_access()
        
        # Check if the configuration exists and IgnorePublicAcls is enabled
        if not public_access_config:
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",  # S3 public access block is a global setting
                    resource_id=self.account_id,
                    checked_value="IgnorePublicAcls: true",
                    actual_value="No public access block configuration found",
                    remediation=(
                        "Enable S3 Block Public Access at the account level using the AWS CLI command: "
                        f"aws s3control put-public-access-block --account-id {self.account_id} "
                        "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
                        "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                    )
                )
            )
            return findings
        
        ignore_public_acls = public_access_config.get('IgnorePublicAcls', False)
        
        if ignore_public_acls:
            findings.append(
                self.create_finding(
                    status="PASS",
                    region="global",  # S3 public access block is a global setting
                    resource_id=self.account_id,
                    checked_value="IgnorePublicAcls: true",
                    actual_value="IgnorePublicAcls setting is true",
                    remediation="No remediation needed"
                )
            )
        else:
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",  # S3 public access block is a global setting
                    resource_id=self.account_id,
                    checked_value="IgnorePublicAcls: true",
                    actual_value="IgnorePublicAcls setting is false",
                    remediation=(
                        "Enable S3 Ignore Public ACLs at the account level using the AWS CLI command: "
                        f"aws s3control put-public-access-block --account-id {self.account_id} "
                        "--public-access-block-configuration IgnorePublicAcls=true"
                    )
                )
            )
        
        return findings
