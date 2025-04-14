"""
SRA-SH-4: Security Hub administrator account is enabled.
"""
from typing import List, Dict, Any
from sraverify.services.securityhub.base import SecurityHubCheck
from sraverify.core.logging import logger


class SRA_SH_4(SecurityHubCheck):
    """Check if Security Hub administrator account is enabled."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-SH-4"
        self.check_name = "Security Hub administrator account is enabled"
        self.account_type = "audit"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Security Hub administrator account is enabled. "
            "Administrator account has access to view findings for associated member accounts."
        )
        self.check_logic = (
            "Check looks in audit account "
            "# PASS conditions: "
            "# 1. Administrator account exists and is enabled "
            "# 2. Organization configuration is CENTRAL and ENABLED "
            " "
            "# FAIL conditions: "
            "# 1. No administrator account or not enabled "
            "# 2. Organization configuration not properly set for central management"
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        # This is a global check, so we'll use a single region but report it as global
        region = self.regions[0] if self.regions else "us-east-1"
        
        # Get organization configuration
        org_config = self.get_organization_configuration(region)
        
        # Check if organization configuration is properly set
        org_configuration = org_config.get('OrganizationConfiguration', {})
        config_type = org_configuration.get('ConfigurationType')
        status = org_configuration.get('Status')
        
        resource_id = f"securityhub:hub/{account_id}"
        
        if config_type != 'CENTRAL' or status != 'ENABLED':
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",  # Report as global
                    account_id=account_id,
                    resource_id=resource_id,
                    checked_value="OrganizationConfiguration Configuration Type is Central and Status Enabled",
                    actual_value=f"Security Hub delegated admin {account_id} is not setup properly to view findings for associated member accounts via ConfigurationType:{config_type} and Status:{status}",
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
                    region="global",  # Report as global
                    account_id=account_id,
                    resource_id=resource_id,
                    checked_value="OrganizationConfiguration Configuration Type is Central and Status Enabled",
                    actual_value=f"Security Hub delegated admin {account_id} is setup properly to view findings for associated member accounts via ConfigurationType:{config_type} and Status:{status}",
                    remediation="No remediation needed"
                )
            )
        
        return findings
