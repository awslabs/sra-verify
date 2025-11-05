"""Check if Route 53 log source is enabled for Security Lake."""

from typing import List, Dict, Any
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.core.logging import logger


class SRA_SECURITYLAKE_06(SecurityLakeCheck):
    """Check if Route 53 log source is enabled for Security Lake."""

    def __init__(self):
        """Initialize check."""
        super().__init__()
        self.account_type = "application"  # Log sources configured in application accounts
        self.check_id = "SRA-SECURITYLAKE-06"
        self.check_name = "Security Lake Route 53 log source enabled"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Amazon Security Lake is configured with "
            "Route 53 log and event source. Route 53 resolver query logs track DNS "
            "queries made by resources within Amazon VPC. Security Lake collects "
            "resolver query logs directly from Route 53 through an independent and "
            "duplicated stream of events."
        )
        self.check_logic = (
            "Checks if the Route 53 log source is enabled in Security Lake. "
            "The check passes if the ROUTE53 log source is enabled. "
            "The check fails if the ROUTE53 log source is not enabled."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """

        for region in self.regions:
            logger.debug(f"Checking if Route 53 log source is enabled in {region}")
            resource_id = f"arn:aws:securitylake:{region}:{self.account_id}:log-source/ROUTE53"

            # Check if Route 53 log source is enabled using the base class method
            route53_enabled = self.get_account_log_source_status(region, "ROUTE53")

            if not route53_enabled:
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_id,
                        checked_value="Route 53 log source enabled",
                        actual_value=f"Route 53 log source is not enabled in {region}",
                        remediation=(
                            "Enable Route 53 log source in Security Lake. In the Security Lake console, "
                            "navigate to Settings > Log Sources and enable Route 53 logs. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securitylake enable-log-source --log-source ROUTE53 --region {region}"
                        )
                    )
                )
            else:
                self.findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=resource_id,
                        checked_value="Route 53 log source enabled",
                        actual_value=f"Route 53 log source is enabled in {region}",
                        remediation="No remediation needed"
                    )
                )

        return self.findings
