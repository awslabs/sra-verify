"""Check if Security Lake organization auto-enable configuration matches AWS defaults."""

from typing import List, Dict, Any
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.core.logging import logger


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

    def __init__(self):
        """Initialize check."""
        super().__init__()
        self.account_type = "log-archive"  # Organization config managed by delegated admin
        self.check_id = "SRA-SECURITYLAKE-05"
        self.check_name = "Security Lake organization auto-enable matches AWS defaults"
        self.severity = "MEDIUM"
        self.description = (
            "This check verifies whether Amazon Security Lake organization auto-enable "
            "configuration matches AWS default/recommended log sources for new accounts "
            "(CLOUD_TRAIL_MGMT, LAMBDA_EXECUTION, EKS_AUDIT, ROUTE53, SH_FINDINGS, VPC_FLOW). "
            "S3_DATA and WAF are excluded as they are optional due to high volume."
        )
        self.check_logic = (
            "Gets the organization configuration for Security Lake auto-enable settings. "
            "The check passes if all AWS default log sources are configured for auto-enable. "
            "The check fails if any default log sources are missing from auto-enable configuration."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """

        for region in self.regions:
            logger.debug(f"Checking Security Lake organization auto-enable configuration in {region}")
            resource_id = f"arn:aws:securitylake:{region}:{self.account_id}:organization-configuration/auto-enable"

            # Get organization configuration using the base class method
            config = self.get_organization_configuration(region)

            if not config:
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_id,
                        checked_value=f"Auto-enable configured with AWS defaults: {', '.join(sorted(self.AWS_DEFAULT_LOG_SOURCES))}",
                        actual_value=f"No organization configuration found in {region}",
                        remediation=(
                            "Configure Security Lake organization auto-enable settings. In the Security Lake console, "
                            "navigate to Settings > Organization Configuration and enable auto-enable for new accounts "
                            "with the AWS default log sources."
                        )
                    )
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
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_id,
                        checked_value=f"Auto-enable configured with AWS defaults: {', '.join(sorted(self.AWS_DEFAULT_LOG_SOURCES))}",
                        actual_value=f"Currently configured: {actual_configured}. Missing: {', '.join(sorted(missing_sources))}",
                        remediation=(
                            "Update Security Lake organization auto-enable configuration to include missing sources. "
                            "In the Security Lake console, navigate to Settings > Organization Configuration and "
                            f"add the missing sources: {', '.join(sorted(missing_sources))}."
                        )
                    )
                )
            else:
                self.findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=resource_id,
                        checked_value=f"Auto-enable configured with AWS defaults: {', '.join(sorted(self.AWS_DEFAULT_LOG_SOURCES))}",
                        actual_value=f"Currently configured: {', '.join(sorted(auto_enable_sources))}",
                        remediation="No remediation needed"
                    )
                )

        return self.findings
