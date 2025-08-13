"""
SRA-INSPECTOR-06: Inspector Delegated Admin Account is the Audit Account.
"""
from typing import List, Dict, Any
from sraverify.services.inspector.base import InspectorCheck
from sraverify.core.logging import logger


class SRA_INSPECTOR_06(InspectorCheck):
    """Check if Inspector delegated admin account is the audit account."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-INSPECTOR-06"
        self.check_name = "Inspector delegated admin account is the audit account"
        self.account_type = "management"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Inspector delegated admin account is the audit account of your AWS organization. "
            "Audit account is dedicated to operating security services, monitoring AWS accounts, and automating security "
            "alerting and response. Inspector provides vulnerability management service."
        )
        self.check_logic = (
            "Check runs inspector2 get-delegated-admin-account. PASS if delegated admin is the Audit account "
            "specified by flag --audit-account"
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        
        # Check each region separately
        for region in self.regions:
            # Get delegated admin account for this region
            delegated_admin_response = self.get_delegated_admin(region)
            delegated_admin = delegated_admin_response.get('delegatedAdmin', {})
            delegated_admin_id = delegated_admin.get('accountId')
            
            # If no delegated admin is configured, report a failure
            if not delegated_admin_id:
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=f"inspector2/{region}/delegated-admin",
                        checked_value="Inspector delegated admin account is the audit account",
                        actual_value="No delegated admin account is configured",
                        remediation=(
                            "Configure a delegated admin account for Inspector using the AWS Console or CLI command: "
                            f"aws organizations register-delegated-administrator --account-id <AUDIT_ACCOUNT_ID> "
                            f"--service-principal inspector2.amazonaws.com --region {region}"
                        )
                    )
                )
                continue
            
            # Check if audit_accounts is provided via _audit_accounts (new attribute name)
            audit_accounts = []
            if hasattr(self, '_audit_accounts') and self._audit_accounts:
                audit_accounts = self._audit_accounts
            # For backward compatibility, also check the old attribute name
            elif hasattr(self, 'audit_accounts') and self.audit_accounts:
                audit_accounts = self.audit_accounts
                
            if not audit_accounts:
                self.findings.append(
                    self.create_finding(
                        status="ERROR",
                        region=region,
                        resource_id=f"inspector2/{region}/delegated-admin",
                        checked_value="Inspector delegated admin account is the audit account",
                        actual_value=f"Delegated admin account is {delegated_admin_id}, but no audit account was specified for comparison",
                        remediation="Run the check with the --audit-account parameter to specify the audit account"
                    )
                )
                continue
            
            # Check if the delegated admin is one of the audit accounts
            if delegated_admin_id in audit_accounts:
                self.findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=f"inspector2/{region}/delegated-admin",
                        checked_value="Inspector delegated admin account is the audit account",
                        actual_value=f"Inspector delegated administrator (Account: {delegated_admin_id}) "
                                   f"matches one of the specified Audit accounts {', '.join(audit_accounts)}",
                        remediation="No remediation needed"
                    )
                )
            else:
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=f"inspector2/{region}/delegated-admin",
                        checked_value="Inspector delegated admin account is the audit account",
                        actual_value=f"Inspector delegated administrator (Account: {delegated_admin_id}) "
                                   f"does not match any of the specified Audit accounts ({', '.join(audit_accounts)})",
                        remediation=(
                            "Update the delegated admin account to be the audit account using the AWS Console or CLI commands: "
                            f"1. aws organizations deregister-delegated-administrator --account-id {delegated_admin_id} "
                            f"--service-principal inspector2.amazonaws.com --region {region}\n"
                            f"2. aws organizations register-delegated-administrator --account-id {audit_accounts[0]} "
                            f"--service-principal inspector2.amazonaws.com --region {region}"
                        )
                    )
                )
        
        return self.findings
