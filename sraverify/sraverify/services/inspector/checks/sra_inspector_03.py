"""
SRA-INSPECTOR-03: Inspector ECR Image Vulnerability Scanning.
"""
from typing import List, Dict, Any
from sraverify.services.inspector.base import InspectorCheck
from sraverify.core.logging import logger


class SRA_INSPECTOR_03(InspectorCheck):
    """Check if Inspector ECR image vulnerability scanning is enabled for the account."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-INSPECTOR-03"
        self.check_name = "Inspector ECR image vulnerability scanning is enabled"
        self.account_type = "application"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Inspector ECR image vulnerability scanning feature is enabled. "
            "Amazon Inspector scans container images stored in Amazon ECR for software vulnerabilities to generate findings."
        )
        self.check_logic = (
            "Check runs inspector2 batch-get-account-status. Check PASS if ecr status = ENABLED"
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        
        for region in self.regions:
            # Get account status using the base class method with caching
            account_status = self.get_account_status(region)
            
            # Check if ECR scanning is enabled
            ecr_status = account_status.get('ecr', {}).get('status')
            
            if not account_status or ecr_status != 'ENABLED':
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=f"inspector2/{self.account_id}/ecr",
                        checked_value="Inspector ECR scanning: ENABLED",
                        actual_value=f"Inspector ECR scanning: {ecr_status if ecr_status else 'NOT_ENABLED'}",
                        remediation=(
                            "Enable Amazon Inspector ECR scanning for your account using the AWS Console or CLI command: "
                            f"aws inspector2 enable --account-ids {self.account_id} --resource-types ECR --region {region}"
                        )
                    )
                )
            else:
                self.findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=f"inspector2/{self.account_id}/ecr",
                        checked_value="Inspector ECR scanning: ENABLED",
                        actual_value=f"Inspector ECR scanning: {ecr_status}",
                        remediation="No remediation needed"
                    )
                )
        
        return self.findings
