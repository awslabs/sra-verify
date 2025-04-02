"""
Check if GuardDuty detector exists.
"""
from typing import Dict, List, Any
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GD_1(GuardDutyCheck):
    """Check if GuardDuty detector exists."""

    def __init__(self):
        """Initialize GuardDuty enabled check."""
        super().__init__()
        self.check_id = "SRA-GD-1"
        self.check_name = "GuardDuty detector exists"
        self.description = "This check verifies that an GuardDuty detector exists in the AWS Region.\
              A detector is a resource that represents the GuardDuty service and should be present \
                in all AWS member account and AWS Region so that GuardDuty can generate findings \
                    about unauthorized or unusual activity even in those Regions that you may not \
                        be using actively."
        self.severity = "HIGH"
        self.check_logic = "Get detector_id in each Region. Check fails if there is no detector_id"
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        account_id = self.get_session_accountId(self.session)

        for region in self.regions:
            detector_id = self.get_detector_id(region)
            
            if not detector_id:
                self.findings.append(self.create_finding(
                    status="FAIL", 
                    region=region, 
                    account_id=account_id,
                    resource_id=None, 
                    actual_value=None, 
                    remediation=f"Enable GuardDuty in {region}"
                ))
            else:
                self.findings.append(self.create_finding(
                    status="PASS", 
                    region=region, 
                    account_id=account_id,
                    resource_id=f"guardduty:{region}:{detector_id}", 
                    actual_value=None, 
                    remediation=""
                ))
        
        return self.findings
