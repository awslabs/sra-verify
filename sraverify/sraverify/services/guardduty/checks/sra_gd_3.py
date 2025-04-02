"""
Check if GuardDuty detector is enabled.
"""
from typing import Dict, List, Any
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GD_3(GuardDutyCheck):
    """Check if GuardDuty detector is enabled."""

    def __init__(self):
        """Initialize GuardDuty enabled check."""
        super().__init__()
        self.check_id = "SRA-GD-3"
        self.check_name = "GuardDuty detector is enabled"
        self.description = ("This check verifies that the GuardDuty detector in the "
                            "AWS account and AWS region is enabled. Detector represents " 
                            "GuardDuty service in the AWS account and specific region, "
                            "if disabled will not provided threat intelligence service.")
        self.severity = "HIGH"
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
                detector_status = detector_details.get('Status', 'Not set')
                
                if detector_status == 'ENABLED':
                    findings.append(self.create_finding(
                        status="PASS", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value=f"Detector status is {detector_status}", 
                        remediation="No remediation needed"
                    ))
                else:
                    findings.append(self.create_finding(
                        status="FAIL", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value=f"Detector status is {detector_status}", 
                        remediation="Enabled GuardDuty"
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
