"""
Check if GuardDuty RDS Login Events are configured for auto-enablement.
"""
from typing import Dict, List, Any
from sraverify.services.guardduty.base import GuardDutyCheck
from sraverify.core.logging import logger


class SRA_GUARDDUTY_25(GuardDutyCheck):
    """Check if GuardDuty RDS Login Events are configured for auto-enablement."""

    def __init__(self):
        """Initialize GuardDuty RDS Login Events auto-enablement check."""
        super().__init__()
        self.check_id = "SRA-GUARDDUTY-25"
        self.check_name = "GuardDuty RDS Login Events auto-enablement configured"
        self.description = ("This check verifies whether RDS Login Events are configured for auto-enablement "
                           "in GuardDuty for all member accounts. RDS Login Events monitoring analyzes database "
                           "login activity to detect potentially suspicious login attempts to RDS databases.")
        self.severity = "HIGH"
        self.check_logic = "Check if RDS_LOGIN_EVENTS feature is configured with AutoEnable set to ALL."
        self.account_type = "audit"
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []        
        # Check all regions
        for region in self.regions:
            detector_id = self.get_detector_id(region)
            
            # Handle regions where we can't access GuardDuty
            if not detector_id:
                findings.append(self.create_finding(
                    status="ERROR", 
                    region=region, 
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
                if error_code == "BadRequestException":
                    findings.append(self.create_finding(
                        status="FAIL", 
                        region=region, 
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value=f"{error_code} {error_message}", 
                        remediation="Verify that GuardDuty is the delegated admin in this Region and run the check again."
                    ))
                else:
                    findings.append(self.create_finding(
                        status="ERROR", 
                        region=region, 
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value=f"Error accessing GuardDuty organization configuration: {error_code}", 
                        remediation="Check permissions and AWS Organizations configuration"
                    ))
                continue
            
            # Check if RDS Login Events are configured for auto-enablement
            # Look for RDS_LOGIN_EVENTS in Features
            rds_login_events_found = False
            rds_login_events_auto_enable = "NOT_CONFIGURED"
            features = org_config.get('Features', [])
            
            for feature in features:
                if feature.get('Name') == 'RDS_LOGIN_EVENTS':
                    rds_login_events_found = True
                    rds_login_events_auto_enable = feature.get('AutoEnable', 'NONE')
                    break
            
            if rds_login_events_found and rds_login_events_auto_enable == 'ALL':
                findings.append(self.create_finding(
                    status="PASS", 
                    region=region, 
                    resource_id=f"guardduty:{region}:{detector_id}", 
                    actual_value="GuardDuty RDS Login Events are configured for auto-enablement for all accounts (AutoEnable=ALL)", 
                    remediation=""
                ))
            elif rds_login_events_found:
                findings.append(self.create_finding(
                    status="FAIL", 
                    region=region, 
                    resource_id=f"guardduty:{region}:{detector_id}", 
                    actual_value=f"GuardDuty RDS Login Events are configured with AutoEnable={rds_login_events_auto_enable}, but should be ALL", 
                    remediation=f"Configure RDS Login Events auto-enablement for all accounts in {region} by setting AutoEnable to ALL"
                ))
            else:
                findings.append(self.create_finding(
                    status="FAIL", 
                    region=region, 
                    resource_id=f"guardduty:{region}:{detector_id}", 
                    actual_value=f"GuardDuty RDS Login Events feature is not configured", 
                    remediation=f"Enable RDS Login Events feature and configure auto-enablement for all accounts in {region}"
                ))
        
        return findings
