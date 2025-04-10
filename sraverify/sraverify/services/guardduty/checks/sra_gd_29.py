"""
Check if GuardDuty has EC2 agent management enabled.
"""
from typing import Dict, List, Any
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GD_29(GuardDutyCheck):
    """Check if GuardDuty has EC2 agent management enabled."""

    def __init__(self):
        """Initialize GuardDuty EC2 agent management check."""
        super().__init__()
        self.check_id = "SRA-GD-29"
        self.check_name = "GuardDuty EC2 agent management enabled"
        self.description = ("This check verifies that GuardDuty has EC2 agent management enabled. "
                           "EC2 agent management allows GuardDuty to automatically deploy and manage "
                           "the security agent on your EC2 instances, simplifying the setup and maintenance "
                           "of runtime monitoring for EC2 workloads.")
        self.severity = "HIGH"
        self.check_logic = "Get detector details in each Region. Check if EC2_AGENT_MANAGEMENT is enabled in the RUNTIME_MONITORING feature's AdditionalConfiguration."
    
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
                # Check if EC2_AGENT_MANAGEMENT is enabled in any RUNTIME_MONITORING feature
                ec2_agent_management_enabled = False
                features = detector_details.get('Features', [])
                
                for feature in features:
                    if feature.get('Name') == 'RUNTIME_MONITORING':
                        # Check AdditionalConfiguration for EC2_AGENT_MANAGEMENT
                        additional_configs = feature.get('AdditionalConfiguration', [])
                        for config in additional_configs:
                            if config.get('Name') == 'EC2_AGENT_MANAGEMENT' and config.get('Status') == 'ENABLED':
                                ec2_agent_management_enabled = True
                                break
                        
                        if ec2_agent_management_enabled:
                            break
                
                if ec2_agent_management_enabled:
                    findings.append(self.create_finding(
                        status="PASS", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value="EC2 agent management is enabled", 
                        remediation=""
                    ))
                else:
                    findings.append(self.create_finding(
                        status="FAIL", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value="EC2 agent management is not enabled", 
                        remediation=f"Enable EC2 agent management in the Runtime Monitoring configuration for GuardDuty in {region}"
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
