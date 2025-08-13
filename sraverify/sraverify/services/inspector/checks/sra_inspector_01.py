"""
SRA-INSPECTOR-01: Inspector Service Status.
"""
from typing import List, Dict, Any
from sraverify.services.inspector.base import InspectorCheck
from sraverify.core.logging import logger


class SRA_INSPECTOR_01(InspectorCheck):
    """Check if Inspector service is enabled for the account."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-INSPECTOR-01"
        self.check_name = "Inspector service is enabled"
        self.account_type = "application"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Inspector service status for the account is enabled. "
            "Amazon Inspector is a vulnerability management service that continuously scans your AWS "
            "workloads for software vulnerabilities and unintended network exposure."
        )
        self.check_logic = (
            "Check runs inspector2 batch-get-account-status. Check PASS if response state status = Enabled"
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
            
            # Check if state status is enabled
            state_status = account_status.get('state', {}).get('status')
            
            if not account_status or state_status != 'ENABLED':
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=f"inspector2/{self.account_id}",
                        checked_value="Inspector state status: ENABLED",
                        actual_value=f"Inspector state status: {state_status if state_status else 'NOT_ENABLED'}",
                        remediation=(
                            "Enable Amazon Inspector for your account using the AWS Console or CLI command: "
                            f"aws inspector2 enable --account-ids {self.account_id} --resource-types EC2 ECR LAMBDA LAMBDA_CODE --region {region}"
                        )
                    )
                )
            else:
                self.findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=f"inspector2/{self.account_id}",
                        checked_value="Inspector state status: ENABLED",
                        actual_value=f"Inspector state status: {state_status}",
                        remediation="No remediation needed"
                    )
                )
        
        return self.findings
