"""Check if Security Lake organization auto-enable configuration matches AWS defaults."""

from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.logging import logger
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securitylake.base import SecurityLakeCheck


class SRA_SECURITYLAKE_05(SecurityLakeCheck):
    """Check if Security Lake organization auto-enable configuration matches AWS defaults."""

    # AWS default/recommended log sources for new accounts
    AWS_DEFAULT_LOG_SOURCES = {
        "CLOUD_TRAIL_MGMT",
        "LAMBDA_EXECUTION",
        "EKS_AUDIT",
        "ROUTE53",
        "SH_FINDINGS",
        "VPC_FLOW"
    }

    meta = CheckMeta(
        check_id="SRA-SECURITYLAKE-05",
        title="Security Lake organization auto-enable matches AWS defaults",
        description=(
            "This check verifies whether Amazon Security Lake organization auto-enable "
            "configuration matches AWS default/recommended log sources for new accounts "
            "(CLOUD_TRAIL_MGMT, LAMBDA_EXECUTION, EKS_AUDIT, ROUTE53, SH_FINDINGS, VPC_FLOW). "
            "S3_DATA and WAF are excluded as they are optional due to high volume."
        ),
        check_logic=(
            "Gets the organization configuration for Security Lake auto-enable settings. "
            "The check passes if all AWS default log sources are configured for auto-enable. "
            "The check fails if any default log sources are missing from auto-enable configuration."
        ),
        severity=Severity.MEDIUM,
        # Organization config managed by delegated admin
        account_type=AccountType.LOG_ARCHIVE,
        service="SecurityLake",
        resource_type="AWS::SecurityLake::SecurityLake",
        remediation=Remediation(
            text=(
                "Configure Security Lake organization auto-enable to include the AWS "
                "default log sources CLOUD_TRAIL_MGMT, LAMBDA_EXECUTION, EKS_AUDIT, "
                "ROUTE53, SH_FINDINGS, and VPC_FLOW."
            ),
            cli=(
                "aws securitylake create-data-lake-organization-configuration "
                "--auto-enable-new-account "
                "'[{\"region\":\"<region>\",\"sources\":["
                "{\"sourceName\":\"CLOUD_TRAIL_MGMT\",\"sourceVersion\":\"2.0\"},"
                "{\"sourceName\":\"LAMBDA_EXECUTION\",\"sourceVersion\":\"2.0\"},"
                "{\"sourceName\":\"EKS_AUDIT\",\"sourceVersion\":\"2.0\"},"
                "{\"sourceName\":\"ROUTE53\",\"sourceVersion\":\"2.0\"},"
                "{\"sourceName\":\"SH_FINDINGS\",\"sourceVersion\":\"2.0\"},"
                "{\"sourceName\":\"VPC_FLOW\",\"sourceVersion\":\"2.0\"}]}]' "
                "--region <region>"
            ),
            console=(
                "Security Lake console, Settings, Organization configuration, "
                "select the default log sources for new accounts."
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
            logger.debug(f"Checking Security Lake organization auto-enable configuration in {region}")
            resource_id = f"arn:aws:securitylake:{region}:{self.account_id}:organization-configuration/auto-enable"

            # Get organization configuration using the base class method
            config = self.get_organization_configuration(region)

            if "Error" in config:
                error = config['Error']
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=resource_id,
                        checked_value=f"Auto-enable configured with AWS defaults: {', '.join(sorted(self.AWS_DEFAULT_LOG_SOURCES))}",
                        actual_value=f"No Security Lake data lake exists in {region}, so the control is not configured",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=resource_id,
                        checked_value=f"Auto-enable configured with AWS defaults: {', '.join(sorted(self.AWS_DEFAULT_LOG_SOURCES))}",
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
                    checked_value=f"Auto-enable configured with AWS defaults: {', '.join(sorted(self.AWS_DEFAULT_LOG_SOURCES))}",
                    actual_value=f"No organization configuration found in {region}",
                    remediation=(
                        "Configure Security Lake organization auto-enable settings. In the Security Lake console, "
                        "navigate to Settings > Organization Configuration and enable auto-enable for new accounts "
                        "with the AWS default log sources."
                    ),
                )
                continue

            # Extract auto-enable sources from configuration
            auto_enable_sources = set()
            auto_enable_config = config.get("autoEnableNewAccount", [])

            # Find the configuration for this region
            for region_config in auto_enable_config:
                if region_config.get("region") == region:
                    sources = region_config.get("sources", [])
                    for source in sources:
                        source_name = source.get("sourceName")
                        if source_name:
                            auto_enable_sources.add(source_name)
                    break

            missing_sources = self.AWS_DEFAULT_LOG_SOURCES - auto_enable_sources

            if missing_sources:
                actual_configured = ', '.join(sorted(auto_enable_sources)) if auto_enable_sources else "None"
                yield self.failed(
                    region=region,
                    resource_id=resource_id,
                    checked_value=f"Auto-enable configured with AWS defaults: {', '.join(sorted(self.AWS_DEFAULT_LOG_SOURCES))}",
                    actual_value=f"Currently configured: {actual_configured}. Missing: {', '.join(sorted(missing_sources))}",
                    remediation=(
                        "Update Security Lake organization auto-enable configuration to include missing sources. "
                        "In the Security Lake console, navigate to Settings > Organization Configuration and "
                        f"add the missing sources: {', '.join(sorted(missing_sources))}."
                    ),
                )
            else:
                yield self.passed(
                    region=region,
                    resource_id=resource_id,
                    checked_value=f"Auto-enable configured with AWS defaults: {', '.join(sorted(self.AWS_DEFAULT_LOG_SOURCES))}",
                    actual_value=f"Currently configured: {', '.join(sorted(auto_enable_sources))}",
                )
