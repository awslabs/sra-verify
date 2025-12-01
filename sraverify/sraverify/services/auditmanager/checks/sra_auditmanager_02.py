"""
Check if Audit Manager delegated admin is the audit account.
"""
from typing import Dict, List, Any
from sraverify.services.auditmanager.base import AuditManagerCheck


class SRA_AUDITMANAGER_02(AuditManagerCheck):
    """Check if Audit Manager delegated admin is the audit account."""

    def __init__(self):
        """Initialize Audit Manager delegated admin check."""
        super().__init__()
        self.account_type = "management"
        self.check_id = "SRA-AUDITMANAGER-02"
        self.check_name = "Audit Manager delegated admin is the audit account"
        self.description = "This check verifies that the AWS Audit Manager delegated administrator is configured as the audit account. The delegated administrator should be the security tooling account to centralize audit management."
        self.severity = "HIGH"
        self.check_logic = "Get organization admin account using GetOrganizationAdminAccount API and verify it matches the audit account ID."
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        for region in self.regions:
            admin_response = self.get_organization_admin_account(region)
            
            if "Error" in admin_response:
                error_code = admin_response["Error"].get("Code", "")
                error_message = admin_response["Error"].get("Message", "")
                
                if error_code == "ResourceNotFoundException":
                    self.findings.append(self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=None,
                        actual_value="No delegated administrator configured",
                        remediation=f"Configure a delegated administrator for Audit Manager in {region} using RegisterOrganizationAdminAccount API"
                    ))
                elif "Please complete AWS Audit Manager setup" in error_message:
                    self.findings.append(self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=None,
                        actual_value="Audit Manager setup not completed in this account",
                        remediation=f"Complete AWS Audit Manager setup from the home page in {region} before configuring delegated administrator"
                    ))
                else:
                    self.findings.append(self.create_finding(
                        status="ERROR",
                        region=region,
                        resource_id=None,
                        actual_value=error_message,
                        remediation="Check IAM permissions for Audit Manager API access"
                    ))
            else:
                admin_account_id = admin_response.get("adminAccountId")
                audit_accounts = getattr(self, '_audit_accounts', [])
                
                if admin_account_id in audit_accounts:
                    self.findings.append(self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=f"auditmanager:admin:{admin_account_id}",
                        actual_value=admin_account_id,
                        remediation=""
                    ))
                else:
                    self.findings.append(self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=f"auditmanager:admin:{admin_account_id}",
                        actual_value=admin_account_id,
                        remediation=f"Change delegated administrator to audit account in {region}. Current admin: {admin_account_id}, Expected audit accounts: {audit_accounts}"
                    ))
        
        return self.findings
