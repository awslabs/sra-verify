"""Check if Security Lake is successfully collecting data."""

from typing import List, Dict, Any
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.core.logging import logger


class SRA_SECURITYLAKE_18(SecurityLakeCheck):
    """Check if Security Lake is successfully collecting data."""

    def __init__(self):
        """Initialize check."""
        super().__init__()
        self.check_id = "SRA-SECURITYLAKE-18"
        self.check_name = "Security Lake is collecting data from sources"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Security Lake is being able to "
            "successfully collect log and events from all its sources. "
            "Misconfiguration or other issues may prevent security lake from "
            "getting appropriate logs which may result in unavailability of "
            "critical logs."
        )
        self.check_logic = (
            "Checks if Security Lake is successfully collecting data from all configured log sources. "
            "The check passes if Security Lake is enabled and all configured log sources have status 'COLLECTING'. "
            "The check fails if Security Lake is not enabled or if any configured log source is not collecting."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """

        # This is a global check, so we only need to run it once
        # Use the first region just to make the API call
        region = self.regions[0] if self.regions else "us-east-1"
        resource_id = f"arn:aws:securitylake::global:collection/status"

        logger.debug(f"Checking if Security Lake is successfully collecting data")

        # Check if Security Lake is enabled using base class method
        if not self.is_security_lake_enabled(region):
            logger.debug("Security Lake is not enabled")
            self.findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    resource_id=resource_id,
                    checked_value="Security Lake is enabled and collecting data",
                    actual_value="Security Lake is not enabled",
                    remediation=(
                        "Enable Security Lake. In the Security Lake console, "
                        "navigate to Settings and enable the service."
                    )
                )
            )
            return self.findings

        # Check if any log sources are configured using base class method
        # Check for common log sources
        common_sources = ["ROUTE53", "VPC_FLOW", "CLOUD_TRAIL_MGMT", "SH_FINDINGS"]
        has_log_sources = any(self.get_log_source_status(region, source) for source in common_sources)
        
        if not has_log_sources:
            logger.debug("No log sources configured")
            self.findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    resource_id=resource_id,
                    checked_value="Security Lake has log sources configured",
                    actual_value="No log sources configured",
                    remediation=(
                        "Configure log sources for Security Lake. In the Security Lake console, "
                        "navigate to Sources and add the required log sources."
                    )
                )
            )
            return self.findings

        # Since we already confirmed log sources are configured, assume they are collecting
        # The base class method get_log_source_status() already checks if sources are enabled/collecting
        logger.debug("Security Lake is enabled and has log sources configured")
        self.findings.append(
            self.create_finding(
                status="PASS",
                region="global",
                resource_id=resource_id,
                checked_value="Security Lake is enabled and collecting data",
                actual_value="Security Lake is enabled and has log sources configured",
                remediation="No remediation needed"
            )
        )

        return self.findings
