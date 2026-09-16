"""Check if Security Lake organization configuration is enabled."""

from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.logging import logger
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securitylake.base import SecurityLakeCheck


class SRA_SECURITYLAKE_04(SecurityLakeCheck):
    """Check if Security Lake organization configuration is enabled."""

    meta = CheckMeta(
        check_id="SRA-SECURITYLAKE-04",
        title="Security Lake organization configuration enabled",
        description=(
            "This check verifies whether Amazon Security Lake has configuration that "
            "will automatically enable new organization accounts as member accounts "
            "from an Amazon Security Lake administrator account."
        ),
        check_logic=(
            "Gets the organization configuration for Security Lake in the region. "
            "The check passes if organization configuration exists, indicating that "
            "Security Lake is configured to automatically enable new organization accounts. "
            "The check fails if no organization configuration is found."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.LOG_ARCHIVE,
        service="SecurityLake",
        resource_type="AWS::SecurityLake::SecurityLake",
        remediation=Remediation(
            text=(
                "Enable the Security Lake organization configuration so new "
                "organization accounts are onboarded automatically."
            ),
            cli="aws securitylake create-data-lake-organization-configuration --region <region>",
            console=(
                "Security Lake console, Settings, Organization configuration, "
                "enable automatic enrollment for new accounts."
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
            logger.debug(f"Checking if Security Lake organization configuration is enabled in {region}")
            resource_id = f"arn:aws:securitylake:{region}:{self.account_id}:organization-configuration/default"

            # Get organization configuration using the base class method
            config = self.get_organization_configuration(region)

            if "Error" in config:
                error = config['Error']
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=resource_id,
                        checked_value="Organization configuration enabled",
                        actual_value=f"No Security Lake data lake exists in {region}, so the control is not configured",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=resource_id,
                        checked_value="Organization configuration enabled",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            if not config:
                yield self.failed(
                    region=region,
                    resource_id=resource_id,
                    checked_value="Organization configuration enabled",
                    actual_value=f"Security Lake organization configuration is not enabled in {region}",
                    remediation=(
                        "Enable Security Lake organization configuration. In the Security Lake console, "
                        "navigate to Settings > Organization Configuration and enable organization configuration. "
                        "Alternatively, use the AWS CLI command: "
                        f"aws securitylake enable-organization-configuration --region {region}"
                    ),
                )
            else:
                yield self.passed(
                    region=region,
                    resource_id=resource_id,
                    checked_value="Organization configuration enabled",
                    actual_value=f"Security Lake organization configuration is enabled in {region}",
                )
