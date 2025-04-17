"""
Check if GuardDuty has S3 protection enabled.
"""
from typing import Dict, List, Any
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_06(GuardDutyCheck):
    """Check if GuardDuty has S3 protection enabled."""

    def __init__(self):
        """Initialize GuardDuty S3 protection check."""
        super().__init__()
        self.check_id = "SRA-GUARDDUTY-06"
        self.check_name = "GuardDuty S3 protection enabled"
        self.description = ("This check verifies that GuardDuty has S3 protection enabled. "
                           "GuardDuty provides enhanced visibility through S3 protection. "
                           "GuardDuty monitors both AWS CloudTrail management events and AWS CloudTrail "
                           "S3 data events to identify potential threats in your Amazon S3 resources.")
        self.severity = "HIGH"
        self.check_logic = "Get detector details in each Region. Check if S3 protection is enabled in the Features array."
    
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
                # Check if S3 protection is enabled in the Features array
                s3_protection_enabled = False
                features = detector_details.get('Features', [])
                
                for feature in features:
                    if feature.get('Name') == 'S3_DATA_EVENTS' and feature.get('Status') == 'ENABLED':
                        s3_protection_enabled = True
                        break
                
                if s3_protection_enabled:
                    findings.append(self.create_finding(
                        status="PASS", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value="S3 protection is enabled", 
                        remediation=""
                    ))
                else:
                    findings.append(self.create_finding(
                        status="FAIL", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value="S3 protection is not enabled", 
                        remediation=f"Enable S3 protection for GuardDuty in {region} to monitor CloudTrail management and S3 data events"
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
