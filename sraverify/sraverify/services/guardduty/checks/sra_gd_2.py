"""
Check if GuardDuty finding frequency is set.
"""
from typing import Dict, List, Any
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GD_2(GuardDutyCheck):
    """Check if GuardDuty finding frequency is set."""

    def __init__(self):
        """Initialize GuardDuty enabled check."""
        super().__init__()
        self.check_id = "SRA-GD-2"
        self.check_name = "GuardDuty finding frequency is set"
        self.description = ("This check verifies that the GuardDuty finding frequency is set "
                           "as per your organization requirement. This determines how often updates to active "
                           "findings are exported to EventBridge, S3 (optional) and Detective (optional). "
                           "By default, updated findings are exported every 6 hours but you can set to "
                           "every 15 minutes or 1 hour.")
        self.severity = "LOW"
        self.check_logic = "Get detector details in each Region. Check value of FindingPublishingFrequency."
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        # Only check regions where GuardDuty is enabled
        enabled_regions = self.get_enabled_regions()
        if not enabled_regions:
            # If GuardDuty is not enabled in any region, return a single finding
            return [self.create_finding(
                status="FAIL", 
                region="global", 
                account_id=account_id,
                resource_id="guardduty:global", 
                actual_value="GuardDuty not enabled in any region", 
                remediation="Enable GuardDuty in at least one region"
            )]
        
        for region in enabled_regions:
            detector_id = self.get_detector_id(region)
            if not detector_id:
                continue
                
            # Use helper method from the base class
            detector_details = self.get_detector_details(region)
            
            if detector_details:
                finding_frequency = detector_details.get('FindingPublishingFrequency', 'Not set')
                
                # Determine if the frequency is set to a valid value
                valid_frequencies = ['FIFTEEN_MINUTES', 'ONE_HOUR', 'SIX_HOURS']
                if finding_frequency in valid_frequencies:
                    findings.append(self.create_finding(
                        status="PASS", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value=f"Finding frequency is set to {finding_frequency}", 
                        remediation="No remediation needed"
                    ))
                else:
                    findings.append(self.create_finding(
                        status="FAIL", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value=f"Finding frequency is not properly set: {finding_frequency}", 
                        remediation="Set GuardDuty finding frequency to FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS"
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
