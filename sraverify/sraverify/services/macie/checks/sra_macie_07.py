"""
SRA-MACIE-07: All active member accounts have relationship with delegated admin account enabled.
"""
from typing import List, Dict, Any, Set
from sraverify.services.macie.base import MacieCheck
from sraverify.core.logging import logger


class SRA_MACIE_07(MacieCheck):
    """Check if all active member accounts have relationship with delegated admin account enabled."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-MACIE-07"
        self.check_name = "All active member accounts have relationship with delegated admin account enabled"
        self.description = (
            "This check verifies whether all active members accounts of the AWS Organization have Macie member relationship "
            "enabled with Macie delegated admin account. Amazon Macie is a data security service that discovers sensitive data "
            "by using machine learning and pattern matching, provides visibility into data security risks, and enables automated "
            "protection against those risks."
        )
        self.severity = "HIGH"
        self.account_type = "audit"
        self.check_logic = "Check runs organizations list-accounts AND macie2 list-members. Check PASS if macie2 list-members includes all members of the AWS organization minus the audit account."
        self.resource_type = "AWS::Macie::Session"
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        # Check if audit accounts are provided
        audit_accounts = []
        if hasattr(self, '_audit_accounts') and self._audit_accounts:
            audit_accounts = self._audit_accounts
        
        for region in self.regions:
            # Get organization members using the base class method with caching
            org_members = self.get_organization_members(region)
            
            # Check if the API call was successful
            if not org_members:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"organization/{account_id}",
                        checked_value="All active member accounts have Macie relationship enabled",
                        actual_value="Failed to retrieve AWS Organization members",
                        remediation="Ensure you have the necessary permissions to call the Organizations ListAccounts API"
                    )
                )
                continue
            
            # Get Macie members using the base class method with caching
            macie_members = self.get_macie_members(region)
            
            # Check if the API call was successful
            if macie_members is None:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"macie2/{account_id}",
                        checked_value="All active member accounts have Macie relationship enabled",
                        actual_value="Failed to retrieve Macie members",
                        remediation="Ensure you have the necessary permissions to call the Macie ListMembers API"
                    )
                )
                continue
            
            # Filter active organization members
            active_org_members = [
                member for member in org_members 
                if member.get('Status') == 'ACTIVE'
            ]
            
            # Create sets of account IDs for comparison
            active_org_account_ids = {member.get('Id') for member in active_org_members}
            macie_member_account_ids = {member.get('accountId') for member in macie_members}
            
            # Remove the current account (delegated admin) from the set of accounts to check
            if account_id in active_org_account_ids:
                active_org_account_ids.remove(account_id)
            
            # Remove audit accounts from the set of accounts to check if provided
            for audit_account in audit_accounts:
                if audit_account in active_org_account_ids:
                    active_org_account_ids.remove(audit_account)
            
            # Find accounts that are not Macie members
            missing_accounts = active_org_account_ids - macie_member_account_ids
            
            # Find accounts that are Macie members but not enabled
            not_enabled_accounts = []
            for member in macie_members:
                if member.get('accountId') in active_org_account_ids and member.get('relationshipStatus') != 'Enabled':
                    not_enabled_accounts.append(member.get('accountId'))
            
            if not missing_accounts and not not_enabled_accounts:
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        account_id=account_id,
                        resource_id=f"macie2/{account_id}/{region}",
                        checked_value="All active member accounts have Macie relationship enabled",
                        actual_value=f"All {len(active_org_account_ids)} active member accounts have Macie relationship enabled in region {region}",
                        remediation="No remediation needed"
                    )
                )
            else:
                missing_accounts_str = ", ".join(missing_accounts) if missing_accounts else "None"
                not_enabled_accounts_str = ", ".join(not_enabled_accounts) if not_enabled_accounts else "None"
                
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"macie2/{account_id}/{region}",
                        checked_value="All active member accounts have Macie relationship enabled",
                        actual_value=(
                            f"Not all active member accounts have Macie relationship enabled in region {region}. "
                            f"Missing accounts: {missing_accounts_str}. "
                            f"Accounts with relationship not enabled: {not_enabled_accounts_str}."
                        ),
                        remediation=(
                            f"Enable Macie for all member accounts in region {region} using the AWS CLI command: "
                            f"aws macie2 create-member --account account_details --region {region}"
                        )
                    )
                )
        
        return findings
