"""
Check if GuardDuty has RDS protection enabled.
"""
from typing import Dict, List, Any
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_10(GuardDutyCheck):
    """Check if GuardDuty has RDS protection enabled."""

    def __init__(self):
        """Initialize GuardDuty RDS protection check."""
        super().__init__()
        self.check_id = "SRA-GUARDDUTY-10"
        self.check_name = "GuardDuty RDS protection enabled"
        self.description = ("This check verifies that GuardDuty RDS protection is enabled. "
                           "RDS Protection in Amazon GuardDuty analyzes and profiles RDS login activity "
                           "for potential access threats to Amazon Aurora databases and Amazon RDS for PostgreSQL.")
        self.severity = "HIGH"
        self.check_logic = "Get detector details in each Region. Check if RDS protection is enabled in the Features array."
    
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
                
            # Get detector details
            detector_details = self.get_detector_details(region)
            
            if detector_details:
                # Check if RDS protection is enabled in the Features array
                rds_protection_enabled = False
                features = detector_details.get('Features', [])
                
                for feature in features:
                    if feature.get('Name') == 'RDS_LOGIN_EVENTS' and feature.get('Status') == 'ENABLED':
                        rds_protection_enabled = True
                        break
                
                if rds_protection_enabled:
                    findings.append(self.create_finding(
                        status="PASS", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value="RDS protection is enabled", 
                        remediation=""
                    ))
                else:
                    findings.append(self.create_finding(
                        status="FAIL", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value="RDS protection is not enabled", 
                        remediation=f"Enable RDS protection for GuardDuty in {region} to monitor login activity for potential threats to Aurora and RDS for PostgreSQL databases"
                    ))
            else:
                findings.append(self.create_finding(
                    status="FAIL", 
                    region=region, 
                    account_id=account_id,
                    resource_id=f"guardduty:{region}:{detector_id}", 
                    actual_value="Unable to retrieve detector details", 
                    remediation="Check GuardDuty permissions and configuration"
                ))
        
        return findings
