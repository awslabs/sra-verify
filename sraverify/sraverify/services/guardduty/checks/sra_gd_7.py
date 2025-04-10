"""
Check if GuardDuty has EKS protection enabled.
"""
from typing import Dict, List, Any
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GD_7(GuardDutyCheck):
    """Check if GuardDuty has EKS protection enabled."""

    def __init__(self):
        """Initialize GuardDuty EKS protection check."""
        super().__init__()
        self.check_id = "SRA-GD-7"
        self.check_name = "GuardDuty EKS protection enabled"
        self.description = ("This check verifies that GuardDuty has EKS protection enabled. "
                           "EKS Audit Log Monitoring helps you detect potentially suspicious activities "
                           "in your EKS clusters within Amazon Elastic Kubernetes Service. It consumes "
                           "Kubernetes audit log events directly from the Amazon EKS control plane logging "
                           "feature through an independent and duplicated stream of audit logs.")
        self.severity = "HIGH"
        self.check_logic = "Get detector details in each Region. Check if EKS protection is enabled in the Features array."
    
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
                # Check if EKS protection is enabled in the Features array
                eks_protection_enabled = False
                features = detector_details.get('Features', [])
                
                for feature in features:
                    if feature.get('Name') == 'EKS_AUDIT_LOGS' and feature.get('Status') == 'ENABLED':
                        eks_protection_enabled = True
                        break
                
                if eks_protection_enabled:
                    findings.append(self.create_finding(
                        status="PASS", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value="EKS protection is enabled", 
                        remediation=""
                    ))
                else:
                    findings.append(self.create_finding(
                        status="FAIL", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value="EKS protection is not enabled", 
                        remediation=f"Enable EKS protection for GuardDuty in {region} to monitor Kubernetes audit logs for suspicious activities"
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
