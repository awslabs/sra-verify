"""Check if Security Lake organization configuration matches expected values."""

from typing import List, Dict, Any
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.core.logging import logger

class SRA_SECURITYLAKE_05(SecurityLakeCheck):
    """Check if Security Lake organization configuration matches expected values."""

    EXPECTED_LOG_SOURCES = {
        "ROUTE53",
        "VPC_FLOW",
        "SH_FINDINGS",
        "CLOUD_TRAIL_MGMT",
        "LAMBDA_EXECUTION",
        "S3_DATA",
        "EKS_AUDIT",
        "WAF"
    }

    def __init__(self):
        """Initialize check."""
        super().__init__()
        self.check_id = "SRA-SECURITYLAKE-05"
        self.check_name = "Security Lake log sources configured"
        self.severity = "MEDIUM"
        self.description = (
            "This check verifies whether Amazon Security Lake organization configuration "
            "matches expected value for log sources (ROUTE53,VPC_FLOW,SH_FINDINGS,"
            "CLOUD_TRAIL_MGMT,LAMBDA_EXECUTION,S3_DATA,EKS_AUDIT,WAF)."
        )
        self.check_logic = (
            "Checks if all expected log sources are enabled in Security Lake. "
            "The check passes if all expected log sources (ROUTE53, VPC_FLOW, SH_FINDINGS, "
            "CLOUD_TRAIL_MGMT, LAMBDA_EXECUTION, S3_DATA, EKS_AUDIT, WAF) are configured. "
            "The check fails if any of the expected log sources are missing."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """

        for region in self.regions:
            logger.debug(f"Checking Security Lake log sources configuration in {region}")
            resource_id = f"arn:aws:securitylake:{region}:{self.account_id}:log-sources/all"

            # Check each expected log source
            configured_sources = set()
            for source in self.EXPECTED_LOG_SOURCES:
                if self.get_log_source_status(region, source):
                    configured_sources.add(source)

            if not configured_sources:
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_id,
                        checked_value=f"Expected log sources: {', '.join(sorted(self.EXPECTED_LOG_SOURCES))}",
                        actual_value=f"No log sources configured in {region}",
                        remediation=(
                            "Configure required log sources in Security Lake. In the Security Lake console, "
                            "navigate to Settings > Log Sources and enable all required log sources. "
                            "Alternatively, use the AWS CLI command for each source: "
                            f"aws securitylake enable-log-source --log-source SOURCE_NAME --region {region}"
                        )
                    )
                )
                continue

            missing_sources = self.EXPECTED_LOG_SOURCES - configured_sources

            if missing_sources:
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_id,
                        checked_value=f"Expected log sources: {', '.join(sorted(self.EXPECTED_LOG_SOURCES))}",
                        actual_value=f"Missing log sources: {', '.join(sorted(missing_sources))}",
                        remediation=(
                            "Enable the missing log sources in Security Lake. In the Security Lake console, "
                            "navigate to Settings > Log Sources and enable the following sources: "
                            f"{', '.join(sorted(missing_sources))}. Alternatively, use the AWS CLI command for each source: "
                            f"aws securitylake enable-log-source --log-source SOURCE_NAME --region {region}"
                        )
                    )
                )
            else:
                self.findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=resource_id,
                        checked_value=f"Expected log sources: {', '.join(sorted(self.EXPECTED_LOG_SOURCES))}",
                        actual_value=f"All expected log sources are configured in {region}",
                        remediation="No remediation needed"
                    )
                )

        return self.findings
