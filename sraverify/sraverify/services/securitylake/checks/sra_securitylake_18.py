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
            "getting appropriate logs which may results unavailability of "
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

        # Get Security Lake status using the client from the base class
        client = self.get_client(region)
        response = client.list_data_lakes() if client else []

        if not response:
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

        # Check if any log sources are configured
        log_sources = client.list_log_sources() if client else []
        if not log_sources:
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

        # Check if any log source has failed status
        # Navigate the nested structure: sources[].sources[].awsLogSource.sourceName
        failed_sources = []
        for log_source_entry in log_sources:
            for source in log_source_entry.get("sources", []):
                aws_log_source = source.get("awsLogSource", {})
                source_name = aws_log_source.get("sourceName", "Unknown")

                # Check source status
                source_status = source.get("sourceStatus", [])
                is_collecting = any(status.get("status") == "COLLECTING" for status in source_status)

                if not is_collecting:
                    failed_sources.append(source_name)

        if failed_sources:
            # Use the first failed source for the resource ID
            first_failed_source = failed_sources[0]
            resource_id = f"arn:aws:securitylake::global:log-source/{first_failed_source}"

            logger.debug(f"The following log sources are not collecting data successfully: {', '.join(failed_sources)}")
            self.findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    resource_id=resource_id,
                    checked_value="All log sources are collecting data successfully",
                    actual_value=f"The following log sources are not collecting data successfully: {', '.join(failed_sources)}",
                    remediation=(
                        "Check the configuration of the failed log sources and ensure they have the necessary permissions. "
                        "In the Security Lake console, navigate to Sources, select the failed source, and review its configuration."
                    )
                )
            )
        else:
            logger.debug("All configured log sources are successfully collecting data")
            self.findings.append(
                self.create_finding(
                    status="PASS",
                    region="global",
                    resource_id=resource_id,
                    checked_value="All log sources are collecting data successfully",
                    actual_value="All configured log sources are successfully collecting data",
                    remediation="No remediation needed"
                )
            )

        return self.findings
