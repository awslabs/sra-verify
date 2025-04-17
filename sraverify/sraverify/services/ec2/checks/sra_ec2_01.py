"""
SRA-EC2-01: AWS account level EBS encryption by default is enabled.
"""
from typing import List, Dict, Any
from sraverify.services.ec2.base import EC2Check
from sraverify.core.logging import logger


class SRA_EC2_01(EC2Check):
    """Check if AWS account level EBS encryption by default is enabled."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-EC2-01"
        self.check_name = "AWS account level EBS encryption by default is enabled"
        self.description = (
            "This check verifies that the AWS account level configuration to encrypt EBS volumes by default "
            "is enabled in the AWS Region. This enforces, at AWS account level, the encryption of the new EBS "
            "volumes and snapshot copies that you create. You can use AWS managed keys or a customer managed KMS key."
        )
        self.severity = "HIGH"
        self.account_type = "application"
        self.check_logic = "Check Pass if 'EbsEncryptionByDefault' = true."
        self.resource_type = "AWS::EC2::Volume"
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        for region in self.regions:
            # Get EBS encryption by default status using the base class method with caching
            encryption_status = self.get_ebs_encryption_by_default(region)
            
            # Check if the API call was successful
            if not encryption_status:
                findings.append(
                    self.create_finding(
                        status="ERROR",
                        region=region,
                        account_id=account_id,
                        resource_id=f"account/{account_id}/region/{region}",
                        checked_value="EbsEncryptionByDefault: true",
                        actual_value="Failed to retrieve EBS encryption by default status",
                        remediation="Ensure you have the necessary permissions to call the EC2 GetEbsEncryptionByDefault API"
                    )
                )
                continue
            
            # Check if EBS encryption by default is enabled
            is_encryption_enabled = encryption_status.get('EbsEncryptionByDefault', False)
            
            if is_encryption_enabled:
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        account_id=account_id,
                        resource_id=f"account/{account_id}/region/{region}",
                        checked_value="EbsEncryptionByDefault: true",
                        actual_value=f"EBS encryption by default is enabled in region {region}",
                        remediation="No remediation needed"
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"account/{account_id}/region/{region}",
                        checked_value="EbsEncryptionByDefault: true",
                        actual_value=f"EBS encryption by default is not enabled in region {region}",
                        remediation=(
                            f"Enable EBS encryption by default in region {region} using the AWS CLI command: "
                            f"aws ec2 enable-ebs-encryption-by-default --region {region}"
                        )
                    )
                )
        
        return findings
