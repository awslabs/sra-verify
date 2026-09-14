"""
SRA-SECURITYHUB-10: Security Hub check.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityhub.base import SecurityHubCheck


class SRA_SECURITYHUB_10(SecurityHubCheck):
    """Check if Security Hub auto-enable is configured for new member accounts."""

    meta = CheckMeta(
        check_id="SRA-SECURITYHUB-10",
        title="Security Hub auto-enable is configured",
        description=(
            "This check verifies whether Security Hub is configured to be automatically enabled "
            "for new member accounts when they join the organization."
        ),
        check_logic=(
            "Check evaluates Security Hub organization configuration. For central configuration, "
            "PASS if ConfigurationType is CENTRAL (uses configuration policies). For local configuration, "
            "PASS if AutoEnable is true."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.AUDIT,
        service="SecurityHub",
        resource_type="AWS::SecurityHub::Hub",
        remediation=Remediation(
            text=(
                "Configure Security Hub to enable itself automatically for new member "
                "accounts, either through central configuration policies or by turning on "
                "auto-enable in the local organization configuration in each enabled Region."
            ),
            cli=(
                "aws securityhub update-organization-configuration --auto-enable "
                "--region <region>"
            ),
            console=(
                "Security Hub console in the audit account, Settings, Configuration, "
                "Auto-enable Security Hub for new accounts."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Region.
        """
        # Check each region separately
        for region in self.regions:
            # Get organization configuration in this specific region
            org_config = self.get_organization_configuration(region)

            resource_id = f"securityhub:organization-configuration/{self.account_id}"

            # Check if using central configuration
            org_configuration = org_config.get('OrganizationConfiguration', {})
            config_type = org_configuration.get('ConfigurationType')

            if config_type == 'CENTRAL':
                # In central configuration, AutoEnable is always false and not relevant
                # Configuration policies handle new account enablement
                yield self.passed(
                    region=region,
                    resource_id=resource_id,
                    checked_value="Security Hub auto-enable configured for new accounts",
                    actual_value=f"Central configuration enabled [ConfigurationType: CENTRAL] in region {region} - new accounts managed via configuration policies",
                )
            else:
                # For local configuration, check AutoEnable
                auto_enable = org_config.get('AutoEnable', False)

                if not auto_enable:
                    yield self.failed(
                        region=region,
                        resource_id=resource_id,
                        checked_value="Security Hub is set to auto-enable for new member accounts",
                        actual_value=f"AutoEnable is set to false in region {region}",
                        remediation=(
                            f"Configure Security Hub to automatically enable for new member accounts in region {region}. "
                            f"In the AWS Console, navigate to Security Hub in region {region}, go to Settings > Configuration, "
                            f"and enable 'Auto-enable Security Hub for new accounts'. Alternatively, use the AWS CLI command: "
                            f"aws securityhub update-organization-configuration --auto-enable --region {region}"
                        ),
                    )
                else:
                    yield self.passed(
                        region=region,
                        resource_id=resource_id,
                        checked_value="Security Hub is set to auto-enable for new member accounts",
                        actual_value=f"AutoEnable is set to true in region {region}",
                    )
