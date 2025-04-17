"""
SRA-SECURITYHUB-07: Security Hub check.
"""
from typing import List, Dict, Any
from sraverify.services.securityhub.base import SecurityHubCheck
from sraverify.core.logging import logger


class SRA_SECURITYHUB_07(SecurityHubCheck):
    """Check if Security Hub delegated admin account is the audit account."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-SECURITYHUB-07"
        self.check_name = "Security Hub delegated admin account is the audit account"
        self.account_type = "management"  # This check is for the management account
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Security Hub delegated admin account is the audit account of your AWS organization. "
            "Audit account is dedicated to operating security services, monitoring AWS accounts, and automating security alerting and response. "
            "AWS Security Hub provides a comprehensive view of the security state in AWS and helps assess AWS environment against "
            "security industry standards and best practices."
        )
        self.check_logic = (
            "Check evaluates value from organizations list-delegated-administrators --service-principal securityhub.amazonaws.com "
            "to ensure DelegatedAdministrators ID matches audit account ID passed via flag."
        )
        self._audit_accounts = []  # Will be populated from command line args
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        # Check each region separately
        for region in self.regions:
            # Get delegated administrators for Security Hub
            delegated_admins = self.get_delegated_administrators(region)
            
            resource_id = f"delegated-admin/{account_id}"
            
            # If no audit accounts are provided, we can't perform the check
            if not self._audit_accounts:
                findings.append(
                    self.create_finding(
                        status="ERROR",
                        region=region,
                        account_id=account_id,
                        resource_id=resource_id,
                        checked_value="Delegated administrator is audit account",
                        actual_value="No audit account ID provided for comparison",
                        remediation="Provide an audit account ID using the --audit-account flag"
                    )
                )
                continue
            
            # Use the first audit account in the list
            audit_account_id = self._audit_accounts[0]
            
            # Check if there are any delegated administrators
            if not delegated_admins:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=resource_id,
                        checked_value=f"Delegated administrator is audit account {audit_account_id}",
                        actual_value=f"No Security Hub delegated administrator found in region {region}",
                        remediation=(
                            f"Register the audit account {audit_account_id} as the Security Hub delegated administrator. "
                            f"In the AWS Console, navigate to Security Hub in the management account, go to Settings > General, "
                            f"and set the delegated administrator. Alternatively, use the AWS CLI command: "
                            f"aws organizations register-delegated-administrator --account-id {audit_account_id} "
                            f"--service-principal securityhub.amazonaws.com --region {region}"
                        )
                    )
                )
                continue
            
            # Check if the delegated administrator is the audit account
            delegated_admin_id = None
            for admin in delegated_admins:
                delegated_admin_id = admin.get('Id')
                if delegated_admin_id == audit_account_id:
                    findings.append(
                        self.create_finding(
                            status="PASS",
                            region=region,
                            account_id=account_id,
                            resource_id=resource_id,
                            checked_value=f"Delegated administrator is audit account {audit_account_id}",
                            actual_value=f"Security Hub delegated administrator is the audit account {audit_account_id}",
                            remediation="No remediation needed"
                        )
                    )
                    break
            else:
                # If we didn't break out of the loop, the delegated admin is not the audit account
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=resource_id,
                        checked_value=f"Delegated administrator is audit account {audit_account_id}",
                        actual_value=f"Security Hub delegated administrator {delegated_admin_id} is not the audit account {audit_account_id}",
                        remediation=(
                            f"Update the Security Hub delegated administrator to be the audit account {audit_account_id}. "
                            f"First, deregister the current delegated administrator using: "
                            f"aws organizations deregister-delegated-administrator --account-id {delegated_admin_id} "
                            f"--service-principal securityhub.amazonaws.com --region {region}\n"
                            f"Then, register the audit account as the delegated administrator using: "
                            f"aws organizations register-delegated-administrator --account-id {audit_account_id} "
                            f"--service-principal securityhub.amazonaws.com --region {region}"
                        )
                    )
                )
        
        return findings
