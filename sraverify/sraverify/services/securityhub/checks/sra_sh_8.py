"""
SRA-SH-8: All active member accounts are Security Hub members.
"""
from typing import List, Dict, Any
from sraverify.services.securityhub.base import SecurityHubCheck
from sraverify.core.logging import logger


class SRA_SH_8(SecurityHubCheck):
    """Check if all active member accounts are Security Hub members."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-SH-8"
        self.check_name = "All active member accounts are Security Hub members"
        self.account_type = "audit"  # This check is for the audit account
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether all active members accounts of the AWS Organization are Security Hub members. "
            "Security Hub provides comprehensive security state and should include all AWS accounts."
        )
        self.check_logic = (
            "Compare the outputs of organizations list-accounts and securityhub list-members. "
            "Make sure that the list includes all accounts excluding the Security Hub admin (audit account) "
            "which is not considered a member."
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        # This is a global check, so we'll use a single region but report it as global
        region = self.regions[0] if self.regions else "us-east-1"
        
        # Get all organization accounts
        org_accounts = self.get_organization_accounts(region)
        
        # Get all Security Hub members
        sh_members = self.get_security_hub_members(region)
        
        # Filter for active organization accounts
        active_org_accounts = [
            account for account in org_accounts 
            if account.get('Status') == 'ACTIVE' and account.get('Id') != account_id  # Exclude the admin account
        ]
        
        # Get the account IDs for comparison
        active_org_account_ids = {account.get('Id') for account in active_org_accounts}
        sh_member_account_ids = {member.get('AccountId') for member in sh_members}
        
        # Find accounts that are in the organization but not in Security Hub
        missing_accounts = active_org_account_ids - sh_member_account_ids
        
        if missing_accounts:
            missing_accounts_list = ', '.join(missing_accounts)
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",  # Report as global
                    account_id=account_id,
                    resource_id="AWS::SecurityHub::Members",
                    checked_value="All organization accounts and all Security Hub Members",
                    actual_value=f"Count of active organization accounts ({len(active_org_account_ids)}) does not match count of Security Hub Members ({len(sh_member_account_ids)}) + 1 for Security Hub Admin account. Missing accounts: {missing_accounts_list}",
                    remediation=(
                        "Add the missing accounts as Security Hub members. In the Security Hub delegated admin account, "
                        "navigate to Settings > Accounts and add the missing accounts. Alternatively, use the AWS CLI command: "
                        f"aws securityhub create-members --account-details AccountId=[ACCOUNT_ID] --region {region}"
                    )
                )
            )
        else:
            findings.append(
                self.create_finding(
                    status="PASS",
                    region="global",  # Report as global
                    account_id=account_id,
                    resource_id="AWS::SecurityHub::Members",
                    checked_value="All organization accounts and all Security Hub Members",
                    actual_value=f"Count of active organization accounts ({len(active_org_account_ids)}) matches count of Security Hub Members ({len(sh_member_account_ids)}) + 1 for Security Hub Admin account. All organization members are Security Hub members.",
                    remediation="No remediation needed"
                )
            )
        
        return findings
