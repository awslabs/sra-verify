"""
SRA-SECURITYHUB-04: Security Hub check.
"""
from typing import List, Dict, Any
from sraverify.services.securityhub.base import SecurityHubCheck
from sraverify.core.logging import logger


class SRA_SECURITYHUB_04(SecurityHubCheck):
    """Check if Security Hub central configuration is enabled."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-SECURITYHUB-04"
        self.check_name = "Security Hub central configuration is enabled"
        self.account_type = "audit"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Security Hub is configured for central configuration. "
            "Central configuration allows the delegated administrator to manage Security Hub, "
            "standards, and controls across all organization accounts from a single location."
        )
        self.check_logic = (
            "Check evaluates if Security Hub organization configuration has ConfigurationType "
            "set to CENTRAL and Status set to ENABLED in the delegated administrator account in all regions."
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        
        for region in self.regions:
            org_config = self.get_organization_configuration(region)
            
            org_configuration = org_config.get('OrganizationConfiguration', {})
            config_type = org_configuration.get('ConfigurationType')
            status = org_configuration.get('Status')
            
            resource_id = f"securityhub:hub/{self.account_id}"
            
            if config_type != 'CENTRAL' or status != 'ENABLED':
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_id,
                        checked_value="OrganizationConfiguration Configuration Type is Central and Status Enabled",
                        actual_value=f"Security Hub delegated admin {self.account_id} is not setup properly to view findings for associated member accounts via ConfigurationType:{config_type} and Status:{status} in region {region}",
                        remediation=(
                            "Configure Security Hub with central configuration. In the Security Hub delegated admin account, "
                            "navigate to Settings > General > Configuration and select 'Centrally manage Security Hub across all accounts in your organization'. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securityhub update-organization-configuration --organization-configuration ConfigurationType=CENTRAL --region {region}"
                        )
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=resource_id,
                        checked_value="OrganizationConfiguration Configuration Type is Central and Status Enabled",
                        actual_value=f"Security Hub delegated admin {self.account_id} is setup properly to view findings for associated member accounts via ConfigurationType:{config_type} and Status:{status} in region {region}",
                        remediation="No remediation needed"
                    )
                )
        
        return findings
