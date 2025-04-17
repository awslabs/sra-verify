"""
Check if GuardDuty has Lambda protection enabled.
"""
from typing import Dict, List, Any
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_12(GuardDutyCheck):
    """Check if GuardDuty has Lambda protection enabled."""

    def __init__(self):
        """Initialize GuardDuty Lambda protection check."""
        super().__init__()
        self.check_id = "SRA-GUARDDUTY-12"
        self.check_name = "GuardDuty Lambda protection enabled"
        self.description = ("This check verifies that GuardDuty Lambda protection is enabled. "
                           "Lambda Protection helps identify potential security threats when an AWS Lambda "
                           "function gets invoked in the AWS environment.")
        self.severity = "HIGH"
        self.check_logic = "Get detector details in each Region. Check if Lambda protection is enabled in the Features array."
    
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
                # Check if Lambda protection is enabled in the Features array
                lambda_protection_enabled = False
                features = detector_details.get('Features', [])
                
                for feature in features:
                    if feature.get('Name') == 'LAMBDA_NETWORK_LOGS' and feature.get('Status') == 'ENABLED':
                        lambda_protection_enabled = True
                        break
                
                if lambda_protection_enabled:
                    findings.append(self.create_finding(
                        status="PASS", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value="Lambda protection is enabled", 
                        remediation=""
                    ))
                else:
                    findings.append(self.create_finding(
                        status="FAIL", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value="Lambda protection is not enabled", 
                        remediation=f"Enable Lambda protection for GuardDuty in {region} to identify potential security threats in Lambda function invocations"
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
