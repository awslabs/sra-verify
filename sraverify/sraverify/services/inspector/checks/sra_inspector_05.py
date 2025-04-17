"""
SRA-INSPECTOR-05: Inspector Delegated Admin Account is Configured.
"""
from typing import List, Dict, Any
from sraverify.services.inspector.base import InspectorCheck
from sraverify.core.logging import logger


class SRA_INSPECTOR_05(InspectorCheck):
    """Check if Inspector delegated admin account is configured."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-INSPECTOR-05"
        self.check_name = "Inspector delegated admin account is configured"
        self.account_type = "management"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether a delegated administrator account is configured for Amazon Inspector. "
            "A delegated administrator can manage Inspector findings across all accounts in the organization."
        )
        self.check_logic = (
            "Check runs inspector2 get-delegated-admin-account. Check PASS if response contains delegatedAdmin"
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        account_id = self.get_session_accountId(self.session)
        
        # Check each region separately
        for region in self.regions:
            # Get delegated admin account for this region
            delegated_admin_response = self.get_delegated_admin(region)
            delegated_admin = delegated_admin_response.get('delegatedAdmin', {})
            delegated_admin_id = delegated_admin.get('accountId')
            
            if not delegated_admin_id:
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"inspector2/{region}/delegated-admin",
                        checked_value="Inspector delegated admin account is configured",
                        actual_value="No delegated admin account is configured",
                        remediation=(
                            "Configure a delegated admin account for Inspector using the AWS Console or CLI command: "
                            f"aws organizations register-delegated-administrator --account-id <AUDIT_ACCOUNT_ID> "
                            f"--service-principal inspector2.amazonaws.com --region {region}"
                        )
                    )
                )
            else:
                self.findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        account_id=account_id,
                        resource_id=f"inspector2/{region}/delegated-admin",
                        checked_value="Inspector delegated admin account is configured",
                        actual_value=f"Delegated admin account {delegated_admin_id} is configured",
                        remediation="No remediation needed"
                    )
                )
        
        return self.findings
