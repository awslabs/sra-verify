"""
Check if IAM Access Analyzer delegated admin is the Audit account.
"""
from typing import Dict, List, Any
from sraverify.services.accessanalyzer.base import AccessAnalyzerCheck
from sraverify.core.logging import logger


class SRA_ACCESSANALYZER_03(AccessAnalyzerCheck):
    """Check if IAM Access Analyzer delegated admin is the Audit account."""
    
    def __init__(self):
        """Initialize IAM Access Analyzer check."""
        super().__init__()
        self.check_id = "SRA-ACCESSANALYZER-03"
        self.check_name = "IAM Access Analyzer Delegated Admin is the Audit Account"
        self.description = ("This check verifies whether IAA delegated admin account is the "
                          "audit account of your AWS organization. Audit account is "
                          "dedicated to operating security services, monitoring AWS accounts, and "
                          "automating security alerting and response. IAA helps monitor resources "
                          "shared outside zone of trust.")
        self.severity = "HIGH"
        self.account_type = "management"
        self.check_logic = ("Check if the delegated administrator account matches any of the specified Audit account IDs")

    def execute(self) -> List[Dict[str, Any]]:
        """Execute the check."""
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        # First check if we have a delegated admin in cache
        delegated_admin = self.__class__._delegated_admin_cache.get(account_id, {})
        
        if not delegated_admin:
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    account_id=account_id,
                    resource_id=f"organization/{account_id}",
                    actual_value="No delegated administrator configured for IAM Access Analyzer",
                    remediation="Configure a delegated administrator for IAM Access Analyzer first"
                )
            )
            return findings

        try:
            # Get the delegated admin account ID
            delegated_admin_id = delegated_admin.get('Id')
            
            # Check if audit_accounts is provided via _audit_accounts (new attribute name)
            audit_accounts = []
            if hasattr(self, '_audit_accounts') and self._audit_accounts:
                audit_accounts = self._audit_accounts
            # For backward compatibility, also check the old attribute name
            elif hasattr(self, 'audit_accounts') and self.audit_accounts:
                audit_accounts = self.audit_accounts
                
            if not audit_accounts:
                findings.append(
                    self.create_finding(
                        status="ERROR",
                        region="global",
                        account_id=account_id,
                        resource_id=delegated_admin_id,
                        actual_value="Audit Account ID not provided",
                        remediation="Provide the Audit account IDs using --audit-account flag"
                    )
                )
                return findings
            
            # Check if delegated admin matches any of the specified Audit accounts
            if delegated_admin_id in audit_accounts:
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region="global",
                        account_id=account_id,
                        resource_id=delegated_admin_id,
                        actual_value=f"IAM Access Analyzer delegated administrator (Account: {delegated_admin_id}) "
                                   f"matches one of the specified Audit accounts {', '.join(audit_accounts)}",
                        remediation="No remediation needed"
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region="global",
                        account_id=account_id,
                        resource_id=delegated_admin_id,
                        actual_value=f"IAM Access Analyzer delegated administrator (Account: {delegated_admin_id}) "
                                   f"does not match any of the specified Audit accounts ({', '.join(audit_accounts)})",
                        remediation=f"Update the delegated administrator to be one of the Audit accounts ({', '.join(audit_accounts)})"
                    )
                )
                
        except Exception as e:
            findings.append(
                self.create_finding(
                    status="ERROR",
                    region="global",
                    account_id=account_id,
                    resource_id=delegated_admin_id if 'delegated_admin_id' in locals() else f"organization/{account_id}",
                    actual_value=f"Error checking delegated administrator: {str(e)}",
                    remediation="Ensure proper permissions to check Organizations structure"
                )
            )

        return findings
