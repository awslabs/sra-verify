"""Check if Lambda execution logs are enabled for Security Lake."""


from typing import List, Dict, Any
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.core.logging import logger



class SRA_SECURITYLAKE_10(SecurityLakeCheck):
    """Check if Lambda execution logs are enabled for Security Lake."""

    def __init__(self):
        """Initialize check."""
        super().__init__()
        self.check_id = "SRA-SECURITYLAKE-10"
        self.check_name = "Security Lake Lambda execution logs enabled"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Amazon Security Lake is configured with "
            "Lambda execution log and event source. These operations are often "
            "high-volume activities and should be enabled as per your requirement. "
            "Security Lake pulls data directly from Lambda through an independent "
            "and duplicated stream of events."
        )
        self.check_logic = (
            "Checks if the Lambda execution logs source is enabled in Security Lake. "
            "The check passes if the LAMBDA_EXECUTION log source is enabled. "
            "The check fails if the LAMBDA_EXECUTION log source is not enabled."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """

        for region in self.regions:
            logger.debug(f"Checking if Lambda execution logs are enabled in {region}")
            resource_id = f"arn:aws:securitylake:{region}:{self.account_id}:log-source/LAMBDA_EXECUTION"

            # Check if Lambda execution logs are enabled using the base class method
            lambda_enabled = self.get_log_source_status(region, "LAMBDA_EXECUTION")

            if not lambda_enabled:
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_id,
                        checked_value="Lambda execution logs enabled",
                        actual_value=f"Lambda execution logs are not enabled in {region}",
                        remediation=(
                            "Enable Lambda execution logs in Security Lake. In the Security Lake console, "
                            "navigate to Settings > Log Sources and enable Lambda execution logs. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securitylake enable-log-source --log-source LAMBDA_EXECUTION --region {region}"
                        )
                    )
                )
            else:
                self.findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=resource_id,
                        checked_value="Lambda execution logs enabled",
                        actual_value=f"Lambda execution logs are enabled in {region}",
                        remediation="No remediation needed"
                    )
                )

        return self.findings
