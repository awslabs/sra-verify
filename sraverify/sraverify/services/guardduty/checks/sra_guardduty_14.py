"""
Check if GuardDuty delegated admin account is the audit account.
"""
from typing import Dict, List, Any
from sraverify.services.guardduty.base import GuardDutyCheck
from sraverify.core.logging import logger


class SRA_GUARDDUTY_14(GuardDutyCheck):
    """Check if GuardDuty delegated admin account is the audit account."""

    def __init__(self):
        """Initialize GuardDuty delegated admin check."""
        super().__init__()
        self.check_id = "SRA-GUARDDUTY-14"
        self.check_name = "GuardDuty delegated admin is audit account"
        self.description = ("This check verifies whether GuardDuty delegated admin account is the audit account "
                           "of your AWS organization. The audit account is dedicated to operating security services, "
                           "monitoring AWS accounts, and automating security alerting and response. GuardDuty helps "
                           "monitor resources for unusual and suspicious activities.")
        self.severity = "HIGH"
        self.check_logic = "Check if GuardDuty delegated administrator is the audit account using GuardDuty list-organization-admin-accounts API."
        self.account_type = "management"
        self._audit_accounts = []
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        # Get the audit account ID from the _audit_accounts list
        # This is populated by main.py from the CLI arguments
        if not self._audit_accounts:
            logger.warning("Audit account ID not provided. Check cannot be completed.")
            for region in self.regions:
                findings.append(self.create_finding(
                    status="ERROR", 
                    region=region, 
                    account_id=account_id,
                    resource_id=f"guardduty:{region}", 
                    actual_value="Audit account ID not provided", 
                    remediation="Run sraverify with --audit-account parameter"
                ))
            return findings
        
        # Use the first audit account in the list
        audit_account_id = self._audit_accounts[0]
        logger.debug(f"Using audit account ID: {audit_account_id}")
        
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
            
            # Check if there was an error in the response
            if "Error" in admin_accounts_response:
                error_code = admin_accounts_response["Error"].get("Code", "Unknown")
                error_message = admin_accounts_response["Error"].get("Message", "Unknown error")
                
                # Handle BadRequestException specifically for non-management accounts
                if error_code == "BadRequestException" and "not the master account" in error_message:
                    findings.append(self.create_finding(
                        status="ERROR", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value=f"This check must be run from the organization management account", 
                        remediation="Run this check from the AWS Organizations management account"
                    ))
                else:
                    findings.append(self.create_finding(
                        status="ERROR", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value=f"Error accessing GuardDuty organization information: {error_code}", 
                        remediation="Check permissions and AWS Organizations configuration"
                    ))
                continue
            
            admin_accounts = admin_accounts_response.get('AdminAccounts', [])
            
            if admin_accounts:
                # GuardDuty has an admin account
                admin_account_id = admin_accounts[0].get('AdminAccountId')
                admin_account_status = admin_accounts[0].get('AdminStatus', 'Unknown')
                
                # Check if the admin account is the audit account and is enabled
                if admin_account_id == audit_account_id and admin_account_status == 'ENABLED':
                    findings.append(self.create_finding(
                        status="PASS", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value=f"GuardDuty delegated admin account is the audit account ({audit_account_id})", 
                        remediation=""
                    ))
                elif admin_account_id != audit_account_id:
                    findings.append(self.create_finding(
                        status="FAIL", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value=f"GuardDuty delegated admin account ({admin_account_id}) is not the audit account ({audit_account_id})", 
                        remediation=f"Delegate GuardDuty administration to the audit account ({audit_account_id}) in {region}"
                    ))
                else:
                    findings.append(self.create_finding(
                        status="FAIL", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value=f"GuardDuty delegated admin is the audit account but status is {admin_account_status}", 
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
                    remediation=f"Delegate GuardDuty administration to the audit account ({audit_account_id}) using the Organizations service in {region}"
                ))
        
        return findings
