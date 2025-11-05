"""Check if EKS Audit logs are enabled for Security Lake."""

from typing import List, Dict, Any
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.core.logging import logger


class SRA_SECURITYLAKE_09(SecurityLakeCheck):
    """Check if EKS Audit logs are enabled for Security Lake."""

    def __init__(self):
        """Initialize check."""
        super().__init__()
        self.check_id = "SRA-SECURITYLAKE-09"
        self.check_name = "Security Lake EKS audit logs enabled"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Amazon Security Lake is configured with "
            "EKS Audit log and event source. EKS Audit Logs help you detect "
            "potentially suspicious activities in your EKS clusters within the "
            "Amazon Elastic Kubernetes Service. Security Lake consumes EKS Audit "
            "Log events directly from the Amazon EKS control plane logging feature "
            "through an independent and duplicative stream of audit logs."
        )
        self.check_logic = (
            "Checks if the EKS Audit logs source is enabled in Security Lake. "
            "The check passes if the EKS_AUDIT log source is enabled. "
            "The check fails if the EKS_AUDIT log source is not enabled."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """

        for region in self.regions:
            logger.debug(f"Checking if EKS Audit logs are enabled in {region}")
            resource_id = f"arn:aws:securitylake:{region}:{self.account_id}:log-source/EKS_AUDIT"

            # Check if EKS Audit logs are enabled using the base class method
            eks_enabled = self.get_log_source_status(region, "EKS_AUDIT")

            if not eks_enabled:
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_id,
                        checked_value="EKS Audit logs enabled",
                        actual_value=f"EKS Audit logs are not enabled in {region}",
                        remediation=(
                            "Enable EKS Audit logs in Security Lake. In the Security Lake console, "
                            "navigate to Settings > Log Sources and enable EKS Audit logs. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securitylake enable-log-source --log-source EKS_AUDIT --region {region}"
                        )
                    )
                )
            else:
                self.findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=resource_id,
                        checked_value="EKS Audit logs enabled",
                        actual_value=f"EKS Audit logs are enabled in {region}",
                        remediation="No remediation needed"
                    )
                )

        return self.findings
