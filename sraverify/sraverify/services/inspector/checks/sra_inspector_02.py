"""
SRA-INSPECTOR-02: Inspector EC2 Vulnerability Scanning.
"""
from typing import List, Dict, Any
from sraverify.services.inspector.base import InspectorCheck
from sraverify.core.logging import logger


class SRA_INSPECTOR_02(InspectorCheck):
    """Check if Inspector EC2 vulnerability scanning is enabled for the account."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-INSPECTOR-02"
        self.check_name = "Inspector EC2 vulnerability scanning is enabled"
        self.account_type = "application"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Inspector EC2 vulnerability scanning feature is enabled. "
            "Inspector automatically discovers EC2 instances and scans for software vulnerability."
        )
        self.check_logic = (
            "Check runs inspector2 batch-get-account-status. Check PASS if response ec2 status = ENABLED"
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        account_id = self.get_session_accountId(self.session)
        
        for region in self.regions:
            # Get account status using the base class method with caching
            account_status = self.get_account_status(region)
            
            # Check if EC2 scanning is enabled
            ec2_status = account_status.get('ec2', {}).get('status')
            
            if not account_status or ec2_status != 'ENABLED':
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"inspector2/{account_id}/ec2",
                        checked_value="Inspector EC2 scanning: ENABLED",
                        actual_value=f"Inspector EC2 scanning: {ec2_status if ec2_status else 'NOT_ENABLED'}",
                        remediation=(
                            "Enable Amazon Inspector EC2 scanning for your account using the AWS Console or CLI command: "
                            f"aws inspector2 enable --account-ids {account_id} --resource-types EC2 --region {region}"
                        )
                    )
                )
            else:
                self.findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        account_id=account_id,
                        resource_id=f"inspector2/{account_id}/ec2",
                        checked_value="Inspector EC2 scanning: ENABLED",
                        actual_value=f"Inspector EC2 scanning: {ec2_status}",
                        remediation="No remediation needed"
                    )
                )
        
        return self.findings
