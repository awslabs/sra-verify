"""
Check if GuardDuty has EKS runtime protection enabled.
"""
from typing import Dict, List, Any
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GD_16(GuardDutyCheck):
    """Check if GuardDuty has EKS runtime protection enabled."""

    def __init__(self):
        """Initialize GuardDuty EKS runtime protection check."""
        super().__init__()
        self.check_id = "SRA-GD-16"
        self.check_name = "GuardDuty EKS runtime protection enabled"
        self.description = ("This check verifies that GuardDuty EKS runtime (original) or runtime protection is enabled. "
                           "Runtime Monitoring observes and analyzes operating system-level, networking, "
                           "and file events to help you detect potential threats in specific AWS workloads")
        self.severity = "HIGH"
        self.check_logic = "Get detector details in each Region. Check if EKS runtime monitoring or runtime monitoring is enabled in the Features array."
    
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
                # Check if EKS runtime protection is enabled in the Features array
                # We need to check both EKS_RUNTIME_MONITORING (original) and RUNTIME_MONITORING features
                eks_runtime_protection_enabled = False
                runtime_monitoring_enabled = False
                features = detector_details.get('Features', [])
                
                for feature in features:
                    if feature.get('Name') == 'EKS_RUNTIME_MONITORING' and feature.get('Status') == 'ENABLED':
                        eks_runtime_protection_enabled = True
                    if feature.get('Name') == 'RUNTIME_MONITORING' and feature.get('Status') == 'ENABLED':
                        runtime_monitoring_enabled = True
                
                # Consider the check passed if either of the runtime monitoring features is enabled
                if eks_runtime_protection_enabled or runtime_monitoring_enabled:
                    enabled_features = []
                    if eks_runtime_protection_enabled:
                        enabled_features.append("EKS_RUNTIME_MONITORING")
                    if runtime_monitoring_enabled:
                        enabled_features.append("RUNTIME_MONITORING")
                    
                    findings.append(self.create_finding(
                        status="PASS", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value=f"Runtime protection is enabled: {', '.join(enabled_features)}", 
                        remediation=""
                    ))
                else:
                    findings.append(self.create_finding(
                        status="FAIL", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value="Runtime protection is not enabled", 
                        remediation=f"Enable Runtime Monitoring for GuardDuty in {region} to monitor operating system-level, networking, and file events in workloads"
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
