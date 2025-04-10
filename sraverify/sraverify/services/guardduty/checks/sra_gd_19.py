"""
Check if GuardDuty service administration is delegated to a different account.
"""
from typing import Dict, List, Any
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GD_19(GuardDutyCheck):
    """Check if GuardDuty service administration is delegated to a different account."""

    def __init__(self):
        """Initialize GuardDuty service administration delegation check."""
        super().__init__()
        self.check_id = "SRA-GD-19"
        self.check_name = "GuardDuty service administration delegated"
        self.description = ("This check verifies whether GuardDuty service administration for the AWS Organization "
                           "is delegated. Centralized management of GuardDuty across the organization improves "
                           "security visibility and control.")
        self.severity = "HIGH"
        self.check_logic = "Check if GuardDuty is configured with a delegated administrator using GuardDuty list-organization-admin-accounts API."
        self.account_type = "management"
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        # Check all regions
        for region in self.regions:
            detector_id = self.get_detector_id(region)
            
            # Handle regions where we can't access GuardDuty
            if not detector_id:
                findings.append(self.create_finding(
                    status="ERROR", 
                    region=region, 
                    account_id=account_id,
                    resource_id=f"guardduty:{region}", 
                    actual_value="Unable to access GuardDuty in this region", 
                    remediation="Check permissions or if GuardDuty is supported in this region"
                ))
                continue
                
            # List organization admin accounts for GuardDuty
            admin_accounts_response = self.list_organization_admin_accounts(region)
            admin_accounts = admin_accounts_response.get('AdminAccounts', [])
            
            if admin_accounts:
                # GuardDuty has an admin account
                admin_account_id = admin_accounts[0].get('AdminAccountId')
                admin_account_status = admin_accounts[0].get('AdminStatus', 'Unknown')
                
                # Check if the admin account is different from the current account and is enabled
                if admin_account_id != account_id and admin_account_status == 'ENABLED':
                    findings.append(self.create_finding(
                        status="PASS", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value=f"GuardDuty service administration is delegated to account {admin_account_id}", 
                        remediation=""
                    ))
                elif admin_account_id == account_id:
                    findings.append(self.create_finding(
                        status="FAIL", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value="GuardDuty service administration is delegated to the management account itself", 
                        remediation=f"Delegate GuardDuty administration to a security account other than the management account in {region}"
                    ))
                else:
                    findings.append(self.create_finding(
                        status="FAIL", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value=f"GuardDuty service administration is delegated to account {admin_account_id} but status is {admin_account_status}", 
                        remediation=f"Check the status of the delegated administrator account in {region}"
                    ))
            else:
                # No admin account for GuardDuty
                findings.append(self.create_finding(
                    status="FAIL", 
                    region=region, 
                    account_id=account_id,
                    resource_id=f"guardduty:{region}:{detector_id}", 
                    actual_value="GuardDuty service administration is not delegated to any account", 
                    remediation=f"Delegate GuardDuty administration to a security account using the Organizations service in {region}"
                ))
        
        return findings
