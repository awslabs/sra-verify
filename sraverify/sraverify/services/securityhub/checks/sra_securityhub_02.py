"""
SRA-SECURITYHUB-02: Security Hub check.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityhub.base import SecurityHubCheck


class SRA_SECURITYHUB_02(SecurityHubCheck):
    """Check if Security Hub is configured to auto-enable new security controls."""

    meta = CheckMeta(
        check_id="SRA-SECURITYHUB-02",
        title="Security Hub auto-enable new standards is enabled",
        description=(
            "This check verifies whether Security Hub is configured to auto-enable new security standards "
            "as they are added to existing standards. This will ensure that as existing standards are updated "
            "with new controls, the AWS account gets evaluated on those new controls."
        ),
        check_logic=(
            "Check evaluates if Security Hub describe organization configuration has AutoEnableStandards set to true."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.AUDIT,
        service="SecurityHub",
        resource_type="AWS::SecurityHub::Hub",
        remediation=Remediation(
            text=(
                "Turn on auto-enable new controls in the Security Hub organization "
                "configuration in every enabled Region."
            ),
            cli=(
                "aws securityhub update-organization-configuration --auto-enable "
                "--auto-enable-standards DEFAULT --region <region>"
            ),
            console=(
                "Security Hub console in the delegated administrator account, Settings, "
                "General, Configuration, Auto-enable new controls."
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
            # Get organization configuration for this region
            org_config = self.get_organization_configuration(region)

            if "Error" in org_config:
                error = org_config['Error']
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"securityhub:configuration/{self.account_id}",
                        checked_value="Security Hub organization configuration available",
                        actual_value=f"Security Hub is not enabled in region {region}, so it has no organization configuration",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"securityhub:configuration/{self.account_id}",
                        checked_value="Security Hub organization configuration available",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            # Check if using central configuration
            org_configuration = org_config.get('OrganizationConfiguration', {})
            config_type = org_configuration.get('ConfigurationType')

            resource_id = f"securityhub:configuration/{self.account_id}"

            if config_type == 'CENTRAL':
                # In central configuration, AutoEnableStandards is always NONE
                # This is expected behavior, so it should PASS with appropriate messaging
                yield self.passed(
                    region=region,
                    resource_id=resource_id,
                    checked_value="Central configuration enabled for auto-enable standards management",
                    actual_value=(
                        f"Security Hub uses central configuration [ConfigurationType: CENTRAL] in region {region}; "
                        f"central configuration manages standards automatically through configuration policies"
                    ),
                )
            else:
                # For local configuration, check AutoEnable and AutoEnableStandards
                auto_enable = org_config.get('AutoEnable', False)
                auto_enable_standards = org_config.get('AutoEnableStandards', 'NONE')

                # AutoEnableStandards can be "NONE", "DEFAULT", or "NEW_CONTROLS"
                # Both "DEFAULT" and "NEW_CONTROLS" indicate auto-enable is working
                # "DEFAULT" means new controls in existing standards are auto-enabled
                # "NEW_CONTROLS" means new controls are auto-enabled (newer API version)
                auto_enable_new_controls = auto_enable_standards in ['DEFAULT', 'NEW_CONTROLS']

                if not auto_enable or not auto_enable_new_controls:
                    yield self.failed(
                        region=region,
                        resource_id=resource_id,
                        checked_value="AutoEnable: true, AutoEnableStandards: DEFAULT or NEW_CONTROLS",
                        actual_value=f"Security Hub auto-enable configuration [AutoEnable: {auto_enable}, AutoEnableStandards: {auto_enable_standards}] in region {region}",
                        remediation=(
                            "Enable auto-enable new controls in Security Hub. In the Security Hub console, "
                            "navigate to Settings > General > Configuration > Auto-enable new controls, and enable this setting. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securityhub update-organization-configuration --auto-enable --auto-enable-standards DEFAULT --region {region}"
                        ),
                    )
                else:
                    yield self.passed(
                        region=region,
                        resource_id=resource_id,
                        checked_value="AutoEnable: true, AutoEnableStandards: DEFAULT or NEW_CONTROLS",
                        actual_value=f"Security Hub auto-enable is properly configured [AutoEnable: {auto_enable}, AutoEnableStandards: {auto_enable_standards}] in region {region}",
                    )
