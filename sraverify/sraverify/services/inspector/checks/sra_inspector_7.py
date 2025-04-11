"""
SRA-INSPECTOR-7: All Active Member Accounts Have Inspector Enabled.
"""
from typing import List, Dict, Any, Set
from sraverify.services.inspector.base import InspectorCheck
from sraverify.core.logging import logger


class SRA_INSPECTOR_7(InspectorCheck):
    """Check if all active member accounts have Inspector enabled."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-INSPECTOR-7"
        self.check_name = "All active member accounts have Inspector enabled"
        self.account_type = "audit"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether all active members accounts of the AWS Organization have Inspector enabled. "
            "Inspector is an automated vulnerability management service that continually scans Amazon Elastic Compute Cloud (EC2), "
            "AWS Lambda functions, and container images in Amazon ECR."
        )
        self.check_logic = (
            "Check runs aws organizations list-accounts AND aws inspector2 batch-get-account-status. "
            "PASS if all organization accounts (except audit) have Inspector enabled"
        )
        self._audit_accounts = []  # Will be populated from command line args
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check using BatchGetAccountStatus.
        
        Returns:
            List of findings
        """
        account_id = self.get_session_accountId(self.session)
        
        # Check each region separately
        for region in self.regions:
            # Get organization members
            org_accounts = self.get_organization_members(region)
            
            # Create a set of all active organization account IDs
            org_account_ids = set()
            for account in org_accounts:
                if account.get('Status') == 'ACTIVE':
                    org_account_ids.add(account.get('Id'))
            
            # Get delegated admin account
            delegated_admin_response = self.get_delegated_admin(region)
            delegated_admin = delegated_admin_response.get('delegatedAdmin', {})
            delegated_admin_id = delegated_admin.get('accountId')
            
            # Use the delegated admin ID as the audit account if no audit accounts are provided
            audit_accounts = self._audit_accounts.copy()
            if not audit_accounts and delegated_admin_id:
                audit_accounts = [delegated_admin_id]
            elif not audit_accounts:
                audit_accounts = [account_id]
            
            # Remove audit accounts from the list of accounts to check
            accounts_to_check = org_account_ids - set(audit_accounts)
            
            # Convert to list for the API call
            accounts_list = list(accounts_to_check)
            
            # Use BatchGetAccountStatus to check which accounts have Inspector enabled
            account_statuses = self.batch_get_account_status(region, accounts_list)
            
            # Find accounts that should have Inspector enabled but don't
            missing_accounts = set()
            for acc_id in accounts_to_check:
                # Check if the account is in the results
                if acc_id not in account_statuses:
                    missing_accounts.add(acc_id)
                    continue
                
                # Check if Inspector is enabled for this account
                status = account_statuses[acc_id].get('state', {}).get('status')
                if status != 'ENABLED':
                    missing_accounts.add(acc_id)
            
            if missing_accounts:
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"inspector2/{region}/organization/members",
                        checked_value="All active organization accounts (except audit) have Inspector enabled",
                        actual_value=f"The following accounts do not have Inspector enabled in {region}: {', '.join(missing_accounts)}",
                        remediation=(
                            "Enable Inspector for all member accounts using the AWS Console or CLI command: "
                            f"aws inspector2 enable --account-ids {' '.join(missing_accounts)} --resource-types EC2 ECR LAMBDA LAMBDA_CODE --region {region}"
                        )
                    )
                )
            else:
                self.findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        account_id=account_id,
                        resource_id=f"inspector2/{region}/organization/members",
                        checked_value="All active organization accounts (except audit) have Inspector enabled",
                        actual_value=f"All {len(accounts_to_check)} active organization accounts (except audit) have Inspector enabled in {region}",
                        remediation="No remediation needed"
                    )
                )
        
        return self.findings
