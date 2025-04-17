"""
SRA-SECURITYHUB-06: Security Hub check.
"""
from typing import List, Dict, Any
from sraverify.services.securityhub.base import SecurityHubCheck
from sraverify.core.logging import logger


class SRA_SECURITYHUB_06(SecurityHubCheck):
    """Check if Security Hub administration for the AWS Organization has a delegated administrator."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-SECURITYHUB-06"
        self.check_name = "Security Hub administration for the AWS Organization has a delegated administrator"
        self.account_type = "management"  # This check is for the management account
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Security Hub service administration for the AWS Organization "
            "is set to AWS Organization delegated admin account for Security Hub."
        )
        self.check_logic = (
            "Check evaluates securityhub list-organization-admin-accounts and organizations list-delegated-administrators "
            "--service-principal securityhub.amazonaws.com. Check PASS if AccountID and ID returned are the same."
        )
        self.resource_type = "AWS::Organizations::Account"
    
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
        
        # Get organization admin accounts
        admin_accounts = self.get_organization_admin_accounts(region)
        
        # Get delegated administrators
        delegated_admins = self.get_delegated_administrators(region)
        
        # Check if there's a match between Security Hub admin and Organizations delegated admin
        sh_admin_id = None
        for admin in admin_accounts:
            if admin.get('Status') == 'ENABLED':
                sh_admin_id = admin.get('AccountId')
                break
        
        org_admin_id = None
        for admin in delegated_admins:
            org_admin_id = admin.get('Id')
            break
        
        resource_id = f"delegated-admin/{account_id}"
        
        if not sh_admin_id or not org_admin_id:
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region=region,
                    account_id=account_id,
                    resource_id=resource_id,
                    checked_value=(
                        "aws organizations list-delegated-administrators --service-principal securityhub.amazonaws.com - "
                        "\"DelegatedAdministrators\": \"Id\": \"[ADMIN_ID]\""
                        "aws securityhub list-organization-admin-accounts - \"AdminAccounts\": \"AccountId\": \"[ADMIN_ID]\""
                    ),
                    actual_value=f"No Security Hub admin account or Organizations delegated admin found",
                    remediation=(
                        "Configure a Security Hub delegated administrator account. In the management account, "
                        "use the AWS CLI command: "
                        f"aws securityhub enable-organization-admin-account --admin-account-id [AUDIT_ACCOUNT_ID] --region {region}"
                    )
                )
            )
        elif sh_admin_id != org_admin_id:
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region=region,
                    account_id=account_id,
                    resource_id=resource_id,
                    checked_value=(
                        "aws organizations list-delegated-administrators --service-principal securityhub.amazonaws.com - "
                        "\"DelegatedAdministrators\": \"Id\": \"[ADMIN_ID]\""
                        "aws securityhub list-organization-admin-accounts - \"AdminAccounts\": \"AccountId\": \"[ADMIN_ID]\""
                    ),
                    actual_value=f"Organizations delegated admin for securityhub {org_admin_id} is different than the Security Hub Admin account {sh_admin_id}",
                    remediation=(
                        "Ensure the same account is used as both the Security Hub admin and the Organizations delegated admin. "
                        "First, remove the current delegated admin using: "
                        f"aws organizations deregister-delegated-administrator --account-id {org_admin_id} --service-principal securityhub.amazonaws.com"
                        "Then, set the Security Hub admin account as the delegated admin: "
                        f"aws organizations register-delegated-administrator --account-id {sh_admin_id} --service-principal securityhub.amazonaws.com"
                    )
                )
            )
        else:
            findings.append(
                self.create_finding(
                    status="PASS",
                    region=region,
                    account_id=account_id,
                    resource_id=resource_id,
                    checked_value="Security Hub delegated administrator matches organization admin account",
                    actual_value=f"Delegated admin account {org_admin_id} matches Security Hub admin account {sh_admin_id}",
                    remediation="No remediation needed"
                )
            )
        
        return findings
