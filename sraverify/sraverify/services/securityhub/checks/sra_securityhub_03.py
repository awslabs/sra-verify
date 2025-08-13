"""
SRA-SECURITYHUB-03: Security Hub check.
"""
from typing import List, Dict, Any
from sraverify.services.securityhub.base import SecurityHubCheck
from sraverify.core.logging import logger


class SRA_SECURITYHUB_03(SecurityHubCheck):
    """Check if Security Hub administration for the account matches delegated administrator."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-SECURITYHUB-03"
        self.check_name = "Security Hub administration for the account matches delegated administrator"
        self.account_type = "management"  # This check is for the management account
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Security Hub service administration for the AWS account is set to "
            "AWS Organization delegated admin account for Security Hub."
        )
        self.check_logic = (
            "Check evaluates securityhub list-organization-admin-accounts and organizations list-delegated-administrators "
            "--service-principal securityhub.amazonaws.com. Check PASS if AccountID and ID returned are the same."
        )
        self._audit_accounts = []  # Will be populated from command line args
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        
        # We only need to check one region for this
        region = self.regions[0]
        
        # Get delegated administrators for Security Hub
        delegated_admins = self.get_delegated_administrators(region)
        
        # Get organization admin accounts
        org_admin_accounts = self.get_organization_admin_accounts(region)
        
        resource_id = f"delegated-admin/{self.account_id}"
        
        # Check if there are any delegated administrators
        if not delegated_admins:
            # Format the actual value properly
            actual_value = 'aws organizations list-delegated-administrators --service-principal securityhub.amazonaws.com - No delegated administrators found'
            
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    resource_id=resource_id,
                    checked_value="Security Hub delegated administrator matches organization admin account",
                    actual_value=actual_value,
                    remediation=(
                        "Register a delegated administrator for Security Hub. In the AWS Console, navigate to "
                        "Organizations, go to Services, find Security Hub, and register a delegated administrator. "
                        "Alternatively, use the AWS CLI command: "
                        "aws organizations register-delegated-administrator --account-id [AUDIT_ACCOUNT_ID] "
                        "--service-principal securityhub.amazonaws.com"
                    )
                )
            )
            return findings
        
        # Check if there are any organization admin accounts
        if not org_admin_accounts:
            # Format the actual value properly
            actual_value = 'aws securityhub list-organization-admin-accounts - No Security Hub admin account found'
            
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    resource_id=resource_id,
                    checked_value="Security Hub delegated administrator matches organization admin account",
                    actual_value=actual_value,
                    remediation=(
                        "Enable a Security Hub administrator account. In the AWS Console, navigate to Security Hub "
                        "in the management account, go to Settings > General, and set the administrator account. "
                        "Alternatively, use the AWS CLI command: "
                        "aws securityhub enable-organization-admin-account --admin-account-id [ADMIN_ID]"
                    )
                )
            )
            return findings
        
        # Get the delegated admin ID and organization admin ID
        delegated_admin_id = delegated_admins[0].get('Id') if delegated_admins else None
        org_admin_id = org_admin_accounts[0].get('AccountId') if org_admin_accounts else None
        
        # Format the actual values properly
        delegated_admin_value = f'aws organizations list-delegated-administrators --service-principal securityhub.amazonaws.com - "DelegatedAdministrators": "Id": "{delegated_admin_id}"'
        org_admin_value = f'aws securityhub list-organization-admin-accounts - "AdminAccounts": "AccountId": "{org_admin_id}"'
        
        # Check if they match
        if delegated_admin_id and org_admin_id and delegated_admin_id == org_admin_id:
            findings.append(
                self.create_finding(
                    status="PASS",
                    region="global",
                    resource_id=resource_id,
                    checked_value="Security Hub delegated administrator matches organization admin account",
                    actual_value=f"{delegated_admin_value} matches {org_admin_value}",
                    remediation="No remediation needed"
                )
            )
        else:
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    resource_id=resource_id,
                    checked_value="Security Hub delegated administrator matches organization admin account",
                    actual_value=f"{delegated_admin_value} does not match {org_admin_value}",
                    remediation=(
                        "Update the Security Hub delegated administrator and organization admin account to match. "
                        "First, deregister the current delegated administrator using: "
                        f"aws organizations deregister-delegated-administrator --account-id {delegated_admin_id} "
                        "--service-principal securityhub.amazonaws.com\n"
                        "Then, register the correct account as the delegated administrator using: "
                        "aws organizations register-delegated-administrator --account-id [CORRECT_ACCOUNT_ID] "
                        "--service-principal securityhub.amazonaws.com\n"
                        "Finally, enable the same account as the Security Hub administrator using: "
                        "aws securityhub enable-organization-admin-account --admin-account-id [CORRECT_ACCOUNT_ID]"
                    )
                )
            )
        
        return findings
