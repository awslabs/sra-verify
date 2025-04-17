"""
Check if GuardDuty has malware protection for EBS enabled.
"""
from typing import Dict, List, Any
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_09(GuardDutyCheck):
    """Check if GuardDuty has malware protection for EBS enabled."""

    def __init__(self):
        """Initialize GuardDuty malware protection for EBS check."""
        super().__init__()
        self.check_id = "SRA-GUARDDUTY-09"
        self.check_name = "GuardDuty malware protection for EBS enabled"
        self.description = ("This check verifies that GuardDuty malware protection for EBS is enabled. "
                           "Malware Protection for EC2 helps you detect the potential presence of malware "
                           "by scanning the Amazon EBS volumes that are attached to the Amazon EC2 instances "
                           "and container workloads.")
        self.severity = "HIGH"
        self.check_logic = "Get detector details in each Region. Check if malware protection for EBS is enabled in the Features array."
    
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
                # Check if malware protection for EBS is enabled in the Features array
                ebs_malware_protection_enabled = False
                features = detector_details.get('Features', [])
                
                for feature in features:
                    if feature.get('Name') == 'EBS_MALWARE_PROTECTION' and feature.get('Status') == 'ENABLED':
                        ebs_malware_protection_enabled = True
                        break
                
                if ebs_malware_protection_enabled:
                    findings.append(self.create_finding(
                        status="PASS", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value="Malware protection for EBS is enabled", 
                        remediation=""
                    ))
                else:
                    findings.append(self.create_finding(
                        status="FAIL", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value="Malware protection for EBS is not enabled", 
                        remediation=f"Enable malware protection for EBS in GuardDuty in {region} to scan EC2 instances and container workloads for malware"
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
