"""
SRA-SECURITYHUB-08: Security Hub check.
"""
from typing import List, Dict, Any, Set
from sraverify.services.securityhub.base import SecurityHubCheck
from sraverify.core.logging import logger


class SRA_SECURITYHUB_08(SecurityHubCheck):
    """Check if all active organization accounts are Security Hub members."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-SECURITYHUB-08"
        self.check_name = "All active organization accounts are Security Hub members"
        self.account_type = "audit"  # This check is for the audit account
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether all active members accounts of the AWS Organization are Security Hub members. "
            "Security Hub provides comprehensive security state and should include all AWS accounts."
        )
        self.check_logic = (
            "Compare the outputs of organizations list-accounts and securityhub list-members. "
            "Make sure that the list includes all accounts, excluding the Security Hub admin (audit account) "
            "which is not considered a member."
        )
        self._audit_accounts = []  # Will be populated from command line args
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        
        # Check each region separately
        for region in self.regions:
            # Get all organization accounts
            org_accounts = self.get_organization_accounts(region)
            
            # Get Security Hub members
            securityhub_members = self.get_security_hub_members(region)
            
            resource_id = f"securityhub:members/{self.account_id}/{region}"
            
            # Create sets of account IDs for comparison
            active_org_account_ids = set()
            for account in org_accounts:
                if account.get('Status') == 'ACTIVE':
                    active_org_account_ids.add(account.get('Id'))
            
            securityhub_member_ids = set()
            for member in securityhub_members:
                securityhub_member_ids.add(member.get('AccountId'))
            
            # Determine the audit account ID
            audit_account_id = None
            if self._audit_accounts:
                audit_account_id = self._audit_accounts[0]
            else:
                # If no audit account is provided, assume the current account is the audit account
                audit_account_id = self.account_id
            
            # Remove the audit account from the list of active organization accounts
            # since the audit account is the Security Hub admin and not a member
            if audit_account_id in active_org_account_ids:
                active_org_account_ids.remove(audit_account_id)
            
            # Find accounts that should be Security Hub members but aren't
            missing_accounts = active_org_account_ids - securityhub_member_ids
            
            if missing_accounts:
                missing_accounts_list = ', '.join(missing_accounts)
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_id,
                        checked_value="All active organization accounts are Security Hub members",
                        actual_value=(
                            f"The following active organization accounts are not Security Hub members in region {region}: "
                            f"{missing_accounts_list}. "
                            f"Active organization accounts: {len(active_org_account_ids)}, "
                            f"Security Hub members: {len(securityhub_member_ids)}"
                        ),
                        remediation=(
                            f"Add the missing accounts as Security Hub members in region {region}. "
                            f"In the AWS Console, navigate to Security Hub in the audit account, go to Settings > Accounts, "
                            f"and add the missing accounts. Alternatively, use the AWS CLI command: "
                            f"aws securityhub create-members --account-details 'AccountId={missing_accounts_list.replace(', ', ',AccountId=')}' --region {region}"
                        )
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=resource_id,
                        checked_value="All active organization accounts are Security Hub members",
                        actual_value=(
                            f"All active organization accounts are Security Hub members in region {region}. "
                            f"Active organization accounts (excluding admin): {len(active_org_account_ids)}, "
                            f"Security Hub members: {len(securityhub_member_ids)}"
                        ),
                        remediation="No remediation needed"
                    )
                )
        
        return findings
