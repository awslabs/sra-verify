"""Check if WAF logs are enabled for Security Lake."""


from typing import List, Dict, Any
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.core.logging import logger



class SRA_SECURITYLAKE_12(SecurityLakeCheck):
    """Check if WAF logs are enabled for Security Lake."""

    def __init__(self):
        """Initialize check."""
        super().__init__()
        self.check_id = "SRA-SECURITYLAKE-12"
        self.check_name = "Security Lake WAF logs enabled"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Amazon Security Lake is configured with "
            "WAF log and event source. AWS WAF is a web application firewall that "
            "helps protect your web applications or APIs against common web exploits "
            "and bots that may affect availability, compromise security, or consume "
            "excessive resources. Security Lake collects WAF logs directly from "
            "AWS WAF through an independent and duplicated stream of events."
        )
        self.check_logic = (
            "Checks if the WAF logs source is enabled in Security Lake. "
            "The check passes if the WAF log source is enabled. "
            "The check fails if the WAF log source is not enabled."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """

        for region in self.regions:
            logger.debug(f"Checking if WAF logs are enabled in {region}")
            resource_id = f"arn:aws:securitylake:{region}:{self.account_id}:log-source/WAF"

            # Check if WAF logs are enabled using the base class method
            waf_enabled = self.get_log_source_status(region, "WAF")

            if not waf_enabled:
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_id,
                        checked_value="WAF logs enabled",
                        actual_value=f"WAF logs are not enabled in {region}",
                        remediation=(
                            "Enable WAF logs in Security Lake. In the Security Lake console, "
                            "navigate to Settings > Log Sources and enable WAF logs. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securitylake enable-log-source --log-source WAF --region {region}"
                        )
                    )
                )
            else:
                self.findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=resource_id,
                        checked_value="WAF logs enabled",
                        actual_value=f"WAF logs are enabled in {region}",
                        remediation="No remediation needed"
                    )
                )

        return self.findings
