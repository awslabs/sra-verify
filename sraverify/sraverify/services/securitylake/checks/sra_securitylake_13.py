"""Check if VPC Flow logs are enabled for Security Lake."""

from typing import List, Dict, Any
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.core.logging import logger


class SRA_SECURITYLAKE_13(SecurityLakeCheck):
    """Check if VPC Flow logs are enabled for Security Lake."""

    def __init__(self):
        """Initialize check."""
        super().__init__()
        self.check_id = "SRA-SECURITYLAKE-13"
        self.check_name = "Security Lake VPC flow logs enabled"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Amazon Security Lake is configured with "
            "VPC Flow log and event source. VPC Flow Logs is a feature that enables "
            "you to capture information about the IP traffic going to and from "
            "network interfaces in your VPC. Security Lake collects VPC Flow Logs "
            "directly from Amazon VPC through an independent and duplicated stream "
            "of events."
        )
        self.check_logic = (
            "Checks if the VPC Flow logs source is enabled in Security Lake. "
            "The check passes if the VPC_FLOW log source is enabled. "
            "The check fails if the VPC_FLOW log source is not enabled."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """

        for region in self.regions:
            logger.debug(f"Checking if VPC Flow logs are enabled in {region}")
            resource_id = f"arn:aws:securitylake:{region}:{self.account_id}:log-source/VPC_FLOW"

            # Check if VPC Flow logs are enabled using the base class method
            vpc_flow_enabled = self.get_log_source_status(region, "VPC_FLOW")

            if not vpc_flow_enabled:
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_id,
                        checked_value="VPC Flow logs enabled",
                        actual_value=f"VPC Flow logs are not enabled in {region}",
                        remediation=(
                            "Enable VPC Flow logs in Security Lake. In the Security Lake console, "
                            "navigate to Settings > Log Sources and enable VPC Flow logs. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securitylake enable-log-source --log-source VPC_FLOW --region {region}"
                        )
                    )
                )
            else:
                self.findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=resource_id,
                        checked_value="VPC Flow logs enabled",
                        actual_value=f"VPC Flow logs are enabled in {region}",
                        remediation="No remediation needed"
                    )
                )

        return self.findings
