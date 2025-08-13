"""
SRA-SECURITYHUB-02: Security Hub check.
"""
from typing import List, Dict, Any
from sraverify.services.securityhub.base import SecurityHubCheck
from sraverify.core.logging import logger


class SRA_SECURITYHUB_02(SecurityHubCheck):
    """Check if Security Hub is configured to auto-enable new security controls."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-SECURITYHUB-02"
        self.check_name = "Security Hub auto-enable new standards is enabled"
        self.account_type = "audit"  # This check is for the audit account
        self.severity = "MEDIUM"
        self.description = (
            "This check verifies whether Security Hub is configured to auto-enable new security standards "
            "as they are added to existing standards. This will ensure that as existing standards are updated "
            "with new controls, the AWS account gets evaluated on those new controls."
        )
        self.check_logic = (
            "Check evaluates if Security Hub describe organization configuration has AutoEnableStandards set to true."
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
            # Get organization configuration for this region
            org_config = self.get_organization_configuration(region)
            
            # Check if auto-enable standards is configured
            # AutoEnableStandards can be "NONE", "DEFAULT", or "NEW_CONTROLS"
            # "NEW_CONTROLS" means new controls are auto-enabled
            auto_enable_standards = org_config.get('AutoEnableStandards', 'NONE')
            auto_enable_new_controls = auto_enable_standards == 'NEW_CONTROLS'
            
            resource_id = f"securityhub:configuration/{self.account_id}"
            
            if not auto_enable_new_controls:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_id,
                        checked_value="AutoEnableStandards: NEW_CONTROLS",
                        actual_value=f"Security hub is not setup to auto enable new standards [AutoEnableStandards: {auto_enable_standards}] in region {region}",
                        remediation=(
                            "Enable auto-enable new controls in Security Hub. In the Security Hub console, "
                            "navigate to Settings > General > Configuration > Auto-enable new controls, and enable this setting. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securityhub update-organization-configuration --auto-enable-standards NEW_CONTROLS --region {region}"
                        )
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=resource_id,
                        checked_value="AutoEnableStandards: NEW_CONTROLS",
                        actual_value=f"Security hub is setup to auto enable new standards [AutoEnableStandards: {auto_enable_standards}] in region {region}",
                        remediation="No remediation needed"
                    )
                )
        
        return findings
