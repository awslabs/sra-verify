"""
Check if GuardDuty has VPC flow logs enabled as a log source.
"""
from typing import Dict, List, Any
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_05(GuardDutyCheck):
    """Check if GuardDuty has VPC flow logs enabled as a log source."""

    def __init__(self):
        """Initialize GuardDuty VPC flow logs check."""
        super().__init__()
        self.check_id = "SRA-GUARDDUTY-05"
        self.check_name = "GuardDuty VPC flow logs enabled"
        self.description = ("This check verifies that GuardDuty has VPC flow logs as one of the log sources, "
                            "enabled.GuardDuty analyzes your VPC flow logs from Amazon EC2 instances within your account. "
                            "It consumes VPC flow log events directly from the VPC Flow Logs feature through an independent "
                            "and duplicated stream of flow logs.")
        self.severity = "MEDIUM"
        self.check_logic = "Get detector details in each Region. Check if VPC Flow logs are enabled in the Features array."
    
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
                # Check if VPC flow logs are enabled in the Features array
                vpc_logs_enabled = False
                features = detector_details.get('Features', [])
                
                for feature in features:
                    if feature.get('Name') == 'FLOW_LOGS' and feature.get('Status') == 'ENABLED':
                        vpc_logs_enabled = True
                        break
                
                if vpc_logs_enabled:
                    findings.append(self.create_finding(
                        status="PASS", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value="VPC flow logs are enabled as a data source", 
                        remediation=""
                    ))
                else:
                    findings.append(self.create_finding(
                        status="FAIL", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value="VPC flow logs are not enabled as a data source", 
                        remediation=f"Enable VPC flow logs as a data source for GuardDuty in {region}"
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
