"""Check if Security Hub findings are enabled for Security Lake."""

from typing import List, Dict, Any
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.core.logging import logger


class SRA_SECURITYLAKE_08(SecurityLakeCheck):
    """Check if Security Hub findings are enabled for Security Lake."""

    def __init__(self):
        """Initialize check."""
        super().__init__()
        self.account_type = "application"  # Log sources configured in application accounts
        self.check_id = "SRA-SECURITYLAKE-08"
        self.check_name = "Security Lake Security Hub findings enabled"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Amazon Security Lake is configured with "
            "SecurityHub findings log and event source. Security Hub findings help "
            "you understand your security posture in AWS and let you check your "
            "environment against security industry standards and best practices. "
            "Security Lake collects findings directly from Security Hub through "
            "an independent and duplicated stream of events."
        )
        self.check_logic = (
            "Checks if the Security Hub findings log source is enabled in Security Lake. "
            "The check passes if the SH_FINDINGS log source is enabled. "
            "The check fails if the SH_FINDINGS log source is not enabled."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """

        for region in self.regions:
            logger.debug(f"Checking if Security Hub findings are enabled in {region}")
            resource_id = f"arn:aws:securitylake:{region}:{self.account_id}:log-source/SH_FINDINGS"

            # Check if Security Hub findings are enabled using the base class method
            securityhub_enabled = self.get_account_log_source_status(region, "SH_FINDINGS")

            if not securityhub_enabled:
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_id,
                        checked_value="Security Hub findings enabled",
                        actual_value=f"Security Hub findings are not enabled in {region}",
                        remediation=(
                            "Enable Security Hub findings in Security Lake. In the Security Lake console, "
                            "navigate to Settings > Log Sources and enable Security Hub findings. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securitylake enable-log-source --log-source SH_FINDINGS --region {region}"
                        )
                    )
                )
            else:
                self.findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=resource_id,
                        checked_value="Security Hub findings enabled",
                        actual_value=f"Security Hub findings are enabled in {region}",
                        remediation="No remediation needed"
                    )
                )

        return self.findings
