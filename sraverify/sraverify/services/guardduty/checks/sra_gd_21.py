"""
Check if GuardDuty auto-enablement is configured for member accounts.
"""
from typing import Dict, List, Any
from sraverify.services.guardduty.base import GuardDutyCheck
from sraverify.core.logging import logger


class SRA_GD_21(GuardDutyCheck):
    """Check if GuardDuty auto-enablement is configured for member accounts."""

    def __init__(self):
        """Initialize GuardDuty auto-enablement check."""
        super().__init__()
        self.check_id = "SRA-GD-21"
        self.check_name = "GuardDuty auto-enablement configured"
        self.description = ("This check verifies whether auto-enablement configuration for GuardDuty is "
                           " enabled for member accounts of the AWS Organization. This ensures that all  "
                           "existing and new member accounts will have GuardDuty monitoring.")
        self.severity = "HIGH"
        self.check_logic = "Check if GuardDuty AutoEnableOrganizationMembers is set to ALL using describe-organization-configuration API."
        self.account_type = "audit"
    
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
                
            # Get organization configuration for GuardDuty
            org_config = self.get_organization_configuration(region)
            
            # Check if there was an error in the response
            if "Error" in org_config:
                error_code = org_config["Error"].get("Code", "Unknown")
                error_message = org_config["Error"].get("Message", "Unknown error")
                
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
                        actual_value=f"Error accessing GuardDuty organization configuration: {error_code}", 
                        remediation="Check permissions and AWS Organizations configuration"
                    ))
                continue
            
            # Check if AutoEnableOrganizationMembers is set to ALL
            auto_enable_org_members = org_config.get('AutoEnableOrganizationMembers', 'NONE')
            
            if auto_enable_org_members == 'ALL':
                findings.append(self.create_finding(
                    status="PASS", 
                    region=region, 
                    account_id=account_id,
                    resource_id=f"guardduty:{region}:{detector_id}", 
                    actual_value="GuardDuty AutoEnableOrganizationMembers is set to ALL", 
                    remediation=""
                ))
            else:
                findings.append(self.create_finding(
                    status="FAIL", 
                    region=region, 
                    account_id=account_id,
                    resource_id=f"guardduty:{region}:{detector_id}", 
                    actual_value=f"GuardDuty AutoEnableOrganizationMembers is set to {auto_enable_org_members}", 
                    remediation=f"Set AutoEnableOrganizationMembers to ALL in {region} to ensure GuardDuty is enabled for all organization members"
                ))
        
        return findings
