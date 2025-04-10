"""
SRA-SH-3: Security Hub administration for the account matches delegated administrator.
"""
from typing import List, Dict, Any
from sraverify.services.securityhub.base import SecurityHubCheck
from sraverify.core.logging import logger


class SRA_SH_3(SecurityHubCheck):
    """Check if Security Hub administration for the account matches delegated administrator."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-SH-3"
        self.check_name = "Security Hub administration for the account matches delegated administrator"
        self.account_type = "management"  # This check is for the management account
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Security Hub service administration for the AWS account is set to "
            "AWS Organization delegated admin account for Security Hub. This check is only applicable if "
            "Security Hub member account has been setup through invitation method only and not through "
            "integration with AWS Organization."
        )
        self.check_logic = (
            "Check evaluates securityhub get-administrator-account to see if Security hub administrator account setup properly."
            "# PASS conditions:"
            "# 1. If 'InvitationId' is NOT present in the response"
            "# 2. AccountId exists and MemberStatus is 'Enabled'"
            ""
            "# FAIL conditions:"
            "# 1. If 'InvitationId' IS present (indicates invitation-based setup)"
            "# 2. If no Administrator account is configured"
            "# 3. If MemberStatus is not 'Enabled'"
        )
    
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
        
        # Check if there's at least one admin account and it's enabled
        has_enabled_admin = False
        admin_account_id = None
        
        for admin in admin_accounts:
            if admin.get('Status') == 'ENABLED':
                has_enabled_admin = True
                admin_account_id = admin.get('AccountId')
                break
        
        resource_id = f"securityhub:admin/{account_id}"
        
        # Get administrator account to check for invitation-based setup
        # The get_administrator_account method might return a list or a dict depending on the API response
        admin_info = self.get_administrator_account(region)
        
        # Initialize has_invitation to False
        has_invitation = False
        
        # Check if admin_info contains invitation information
        if isinstance(admin_info, dict):
            # If it's a dictionary, check for Administrator key
            if 'Administrator' in admin_info:
                admin_details = admin_info['Administrator']
                if isinstance(admin_details, dict):
                    has_invitation = 'InvitationId' in admin_details
        
        if not has_enabled_admin:
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region=region,
                    account_id=account_id,
                    resource_id=resource_id,
                    checked_value="Administrator account is configured and enabled",
                    actual_value="No enabled administrator account found",
                    remediation=(
                        "Configure a Security Hub delegated administrator account. In the management account, "
                        "use the AWS CLI command: "
                        f"aws securityhub enable-organization-admin-account --admin-account-id [AUDIT_ACCOUNT_ID] --region {region}"
                    )
                )
            )
        elif has_invitation:
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region=region,
                    account_id=account_id,
                    resource_id=resource_id,
                    checked_value="If 'InvitationId' is NOT present in the response",
                    actual_value="Security Hub is configured using invitation-based setup instead of organization integration",
                    remediation=(
                        "Reconfigure Security Hub to use AWS Organizations integration instead of invitation-based setup. "
                        "First, disassociate the current member account, then enable Security Hub in the management account "
                        "and delegate administration to the audit account."
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
                    checked_value="If 'InvitationId' is NOT present in the response and AccountId exists and MemberStatus is 'Enabled'",
                    actual_value=f"Admin account {admin_account_id} has been setup properly as the delegated admin",
                    remediation="No remediation needed"
                )
            )
        
        return findings
