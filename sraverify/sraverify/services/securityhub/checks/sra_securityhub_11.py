"""
SRA-SECURITYHUB-11: Security Hub check.
"""
from typing import List, Dict, Any
from sraverify.services.securityhub.base import SecurityHubCheck
from sraverify.core.logging import logger


class SRA_SECURITYHUB_11(SecurityHubCheck):
    """Check if Security Hub member account limit has not been reached."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-SECURITYHUB-11"
        self.check_name = "Security Hub member account limit not reached"
        self.account_type = "audit"  # This check is for the audit account
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether the maximum number of allowed member accounts are already associated "
            "with the delegated administrator account for the AWS Organization."
        )
        self.check_logic = (
            "Check evaluates if Security Hub describe-organization-configuration returns \"MemberAccountLimitReached\": false. "
            "PASS if MemberAccountLimitReached is false."
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        
        # Check each region separately
        for region in self.regions:
            # Get organization configuration in this specific region
            org_config = self.get_organization_configuration(region)
            
            resource_id = f"securityhub:member-quota/{self.account_id}"
            
            # Check if MemberAccountLimitReached is false
            limit_reached = org_config.get('MemberAccountLimitReached', True)
            
            if limit_reached:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_id,
                        checked_value="Security Hub has not hit member account limit",
                        actual_value=f"Security Hub has hit member account limit in region {region}",
                        remediation=(
                            f"Contact AWS Support to request an increase in the Security Hub member account limit for region {region}. "
                            f"Alternatively, review your Security Hub member accounts and consider removing inactive or unnecessary accounts."
                        )
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=resource_id,
                        checked_value="Security Hub has not hit member account limit",
                        actual_value=f"Security Hub has not hit member account limit in region {region}",
                        remediation="No remediation needed"
                    )
                )
        
        return findings
