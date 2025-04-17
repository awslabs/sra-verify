"""
SRA-SECURITYHUB-10: Security Hub check.
"""
from typing import List, Dict, Any
from sraverify.services.securityhub.base import SecurityHubCheck
from sraverify.core.logging import logger


class SRA_SECURITYHUB_10(SecurityHubCheck):
    """Check if Security Hub auto-enable is configured for new member accounts."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-SECURITYHUB-10"
        self.check_name = "Security Hub auto-enable is configured"
        self.account_type = "audit"  # This check is for the audit account
        self.severity = "MEDIUM"
        self.description = (
            "This check verifies whether Security Hub is configured to be automatically enabled "
            "for new member accounts when they join the organization."
        )
        self.check_logic = (
            "Check evaluates if Security Hub describe-organization-configuration returns \"AutoEnable\": true. "
            "PASS if AutoEnable is true."
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        # Check each region separately
        for region in self.regions:
            # Get organization configuration in this specific region
            org_config = self.get_organization_configuration(region)
            
            resource_id = f"securityhub:organization-configuration/{account_id}"
            
            # Check if AutoEnable is set to true
            auto_enable = org_config.get('AutoEnable', False)
            
            if not auto_enable:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=resource_id,
                        checked_value="Security Hub is set to auto-enable for new member accounts",
                        actual_value=f"AutoEnable is set to false in region {region}",
                        remediation=(
                            f"Configure Security Hub to automatically enable for new member accounts in region {region}. "
                            f"In the AWS Console, navigate to Security Hub in region {region}, go to Settings > Configuration, "
                            f"and enable 'Auto-enable Security Hub for new accounts'. Alternatively, use the AWS CLI command: "
                            f"aws securityhub update-organization-configuration --auto-enable --region {region}"
                        )
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        account_id=account_id,
                        resource_id=resource_id,
                        checked_value="Security Hub is set to auto-enable for new member accounts",
                        actual_value=f"AutoEnable is set to true in region {region}",
                        remediation="No remediation needed"
                    )
                )
        
        return findings
