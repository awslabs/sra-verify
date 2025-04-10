"""
SRA-SH-7: Security Hub delegated admin account is the Security Tooling (Audit) account.
"""
from typing import List, Dict, Any
from sraverify.services.securityhub.base import SecurityHubCheck
from sraverify.core.logging import logger


class SRA_SH_7(SecurityHubCheck):
    """Check if Security Hub delegated admin account is the Security Tooling (Audit) account."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-SH-7"
        self.check_name = "Security Hub delegated admin account is the Security Tooling (Audit) account"
        self.account_type = "management"  # This check is for the management account
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Security Hub delegated admin account is the audit account of your AWS organization. "
            "Audit account is dedicated to operating security services monitoring AWS accounts and automating security "
            "alerting and response. AWS Security Hub provides a comprehensive view of the security state in AWS and "
            "helps assess AWS environment against security industry standards and best practices."
        )
        self.check_logic = (
            "Check evaluates value from organizations list-delegated-administrators —service-principal "
            "securityhub.amazonaws.com to ensure DelegatedAdministrators ID matches audit account ID passed via flag."
        )
        self.resource_type = "AWS::SecurityHub::Admin"
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        # This check only needs to run in one region since it's an organization-wide setting
        region = self.regions[0] if self.regions else "us-east-1"
        
        # Get delegated administrators
        delegated_admins = self.get_delegated_administrators(region)
        
        # Check if audit_accounts is provided via _audit_accounts attribute
        audit_accounts = []
        if hasattr(self, '_audit_accounts') and self._audit_accounts:
            audit_accounts = self._audit_accounts
        
        if not audit_accounts:
            findings.append(
                self.create_finding(
                    status="ERROR",
                    region="global",
                    account_id=account_id,
                    resource_id=f"delegated-admin/{account_id}",
                    checked_value="Security Hub delegated administrator is an Audit account",
                    actual_value="Audit Account ID not provided",
                    remediation="Provide the Audit account IDs using --audit-account flag"
                )
            )
            return findings
        
        if not delegated_admins:
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    account_id=account_id,
                    resource_id=f"delegated-admin/{account_id}",
                    checked_value=f"Security Hub delegated administrator is an Audit account ({', '.join(audit_accounts)})",
                    actual_value="No Security Hub delegated administrator found",
                    remediation=(
                        "Configure the audit account as the Security Hub delegated administrator. In the management account, "
                        "use the AWS CLI command: "
                        f"aws securityhub enable-organization-admin-account --admin-account-id {audit_accounts[0]} --region {region}"
                    )
                )
            )
            return findings
        
        # Check if any of the delegated administrators is an Audit account
        for admin in delegated_admins:
            admin_id = admin.get('Id', 'Unknown')
            admin_name = admin.get('Name', 'Unknown')
            
            resource_id = f"delegated-admin/{account_id}"
            
            if admin_id in audit_accounts:
                # This delegated admin is in the audit accounts list
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region="global",
                        account_id=account_id,
                        resource_id=resource_id,
                        checked_value=f"Security Hub delegated administrator is an Audit account ({', '.join(audit_accounts)})",
                        actual_value=f"Security Hub delegated administrator {admin_id} ({admin_name}) is an Audit account",
                        remediation="No remediation needed"
                    )
                )
            else:
                # This delegated admin is not in the audit accounts list
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region="global",
                        account_id=account_id,
                        resource_id=resource_id,
                        checked_value=f"Security Hub delegated administrator is an Audit account ({', '.join(audit_accounts)})",
                        actual_value=(
                            f"Security Hub delegated administrator {admin_id} ({admin_name}) "
                            f"is not in the specified Audit accounts ({', '.join(audit_accounts)})"
                        ),
                        remediation=(
                            "Change the Security Hub delegated administrator to the audit account. First, remove the current delegated admin using: "
                            f"aws organizations deregister-delegated-administrator --account-id {admin_id} --service-principal securityhub.amazonaws.com\n"
                            "Then, set the audit account as the delegated admin: "
                            f"aws organizations register-delegated-administrator --account-id {audit_accounts[0]} --service-principal securityhub.amazonaws.com\n"
                            f"aws securityhub enable-organization-admin-account --admin-account-id {audit_accounts[0]} --region {region}"
                        )
                    )
                )
        
        return findings
