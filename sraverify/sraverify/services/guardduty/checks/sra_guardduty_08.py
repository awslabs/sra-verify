"""
Check if GuardDuty has CloudTrail event and management logs enabled.
"""
from typing import Dict, List, Any
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_08(GuardDutyCheck):
    """Check if GuardDuty has CloudTrail event and management logs enabled."""

    def __init__(self):
        """Initialize GuardDuty CloudTrail logs check."""
        super().__init__()
        self.check_id = "SRA-GUARDDUTY-08"
        self.check_name = "GuardDuty CloudTrail logs enabled"
        self.description = ("This check verifies that GuardDuty has CloudTrail event and management logs as one of the feature, enabled. "
                           "GuardDuty consumes CloudTrail management events directly from CloudTrail through an independent and "
                           "duplicated stream of events and analyzes the CloudTrail event logs.")
        self.severity = "HIGH"
        self.check_logic = "Get detector details in each Region. Check if CloudTrail logs are enabled in the Features array."
    
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
                # Check if CloudTrail logs are enabled in the Features array
                cloudtrail_enabled = False
                features = detector_details.get('Features', [])
                
                for feature in features:
                    if feature.get('Name') == 'CLOUD_TRAIL' and feature.get('Status') == 'ENABLED':
                        cloudtrail_enabled = True
                        break
                
                if cloudtrail_enabled:
                    findings.append(self.create_finding(
                        status="PASS", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value="CloudTrail event and management logs are enabled", 
                        remediation=""
                    ))
                else:
                    findings.append(self.create_finding(
                        status="FAIL", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value="CloudTrail event and management logs are not enabled", 
                        remediation=f"Enable CloudTrail event and management logs for GuardDuty in {region} to monitor for suspicious API activity"
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
