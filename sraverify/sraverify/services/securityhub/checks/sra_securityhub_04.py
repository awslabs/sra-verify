"""
SRA-SECURITYHUB-04: Security Hub check.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityhub.base import SecurityHubCheck


class SRA_SECURITYHUB_04(SecurityHubCheck):
    """Check if Security Hub central configuration is enabled."""

    meta = CheckMeta(
        check_id="SRA-SECURITYHUB-04",
        title="Security Hub central configuration is enabled",
        description=(
            "This check verifies whether Security Hub is configured for central configuration. "
            "Central configuration allows the delegated administrator to manage Security Hub, "
            "standards, and controls across all organization accounts from a single location."
        ),
        check_logic=(
            "Check evaluates if Security Hub organization configuration has ConfigurationType "
            "set to CENTRAL and Status set to ENABLED in the delegated administrator account in all regions."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.AUDIT,
        service="SecurityHub",
        resource_type="AWS::SecurityHub::Hub",
        remediation=Remediation(
            text=(
                "Switch the Security Hub organization configuration to central "
                "configuration in the delegated administrator account in every enabled "
                "Region."
            ),
            cli=(
                "aws securityhub update-organization-configuration "
                "--organization-configuration ConfigurationType=CENTRAL --region <region>"
            ),
            console=(
                "Security Hub console in the delegated administrator account, Settings, "
                "General, Configuration, Centrally manage Security Hub across all "
                "accounts in your organization."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Region.
        """
        for region in self.regions:
            org_config = self.get_organization_configuration(region)

            if "Error" in org_config:
                error = org_config['Error']
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"securityhub:hub/{self.account_id}",
                        checked_value="OrganizationConfiguration Configuration Type is Central and Status Enabled",
                        actual_value=f"Security Hub is not enabled in region {region}, so it has no organization configuration",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"securityhub:hub/{self.account_id}",
                        checked_value="OrganizationConfiguration Configuration Type is Central and Status Enabled",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            org_configuration = org_config.get('OrganizationConfiguration', {})
            config_type = org_configuration.get('ConfigurationType')
            status = org_configuration.get('Status')

            resource_id = f"securityhub:hub/{self.account_id}"

            if config_type != 'CENTRAL' or status != 'ENABLED':
                yield self.failed(
                    region=region,
                    resource_id=resource_id,
                    checked_value="OrganizationConfiguration Configuration Type is Central and Status Enabled",
                    actual_value=f"Security Hub delegated admin {self.account_id} is not setup properly to view findings for associated member accounts via ConfigurationType:{config_type} and Status:{status} in region {region}",
                    remediation=(
                        "Configure Security Hub with central configuration. In the Security Hub delegated admin account, "
                        "navigate to Settings > General > Configuration and select 'Centrally manage Security Hub across all accounts in your organization'. "
                        "Alternatively, use the AWS CLI command: "
                        f"aws securityhub update-organization-configuration --organization-configuration ConfigurationType=CENTRAL --region {region}"
                    ),
                )
            else:
                yield self.passed(
                    region=region,
                    resource_id=resource_id,
                    checked_value="OrganizationConfiguration Configuration Type is Central and Status Enabled",
                    actual_value=f"Security Hub delegated admin {self.account_id} is setup properly to view findings for associated member accounts via ConfigurationType:{config_type} and Status:{status} in region {region}",
                )
