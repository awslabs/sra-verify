"""
Check if GuardDuty has DNS logs enabled as a log source.
"""
from typing import Dict, List, Any
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GD_4(GuardDutyCheck):
    """Check if GuardDuty has DNS logs enabled as a log source."""

    def __init__(self):
        """Initialize GuardDuty DNS logs check."""
        super().__init__()
        self.check_id = "SRA-GD-4"
        self.check_name = "GuardDuty DNS logs enabled"
        self.description = ("This check verifies that GuardDuty has DNS logs as one of the log sources, enabled. "
                            "If you use AWS DNS resolvers for your Amazon EC2 instances (the default setting), " 
                            "then GuardDuty can access and process your request and response DNS logs through the " 
                            "internal AWS DNS resolvers.")
        self.severity = "MEDIUM"
        self.check_logic = "Get detector details in each Region. Check if DNS logs are enabled in the Features array."
    
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
                # Check if DNS logs are enabled in the Features array
                dns_logs_enabled = False
                features = detector_details.get('Features', [])
                
                for feature in features:
                    if feature.get('Name') == 'DNS_LOGS' and feature.get('Status') == 'ENABLED':
                        dns_logs_enabled = True
                        break
                
                if dns_logs_enabled:
                    findings.append(self.create_finding(
                        status="PASS", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value="DNS logs are enabled as a data source", 
                        remediation=""
                    ))
                else:
                    findings.append(self.create_finding(
                        status="FAIL", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value="DNS logs are not enabled as a data source", 
                        remediation=f"Enable DNS logs as a data source for GuardDuty in {region}"
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
