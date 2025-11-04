"""Check if CloudTrail S3 data events are enabled for Security Lake."""

from typing import List, Dict, Any
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.core.logging import logger


class SRA_SECURITYLAKE_07(SecurityLakeCheck):
    """Check if CloudTrail S3 data events are enabled for Security Lake."""

    def __init__(self):
        """Initialize check."""
        super().__init__()
        self.check_id = "SRA-SECURITYLAKE-07"
        self.check_name = "Security Lake CloudTrail S3 data events enabled"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Amazon Security Lake is configured with "
            "CloudTrail data event for S3 log and event source configurations. "
            "CloudTrail data events, also known as data plane operations, show "
            "the resource operations performed on or within resources in your AWS "
            "account. These operations are often high-volume activities and should "
            "be enabled as per your requirement. Security Lake pulls data directly "
            "from S3 through an independent and duplicated stream of events."
        )
        self.check_logic = (
            "Checks if the CloudTrail S3 data events log source is enabled in Security Lake. "
            "The check passes if the S3_DATA log source is enabled. "
            "The check fails if the S3_DATA log source is not enabled."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """

        for region in self.regions:
            logger.debug(f"Checking if CloudTrail S3 data events are enabled in {region}")
            resource_id = f"arn:aws:securitylake:{region}:{self.account_id}:log-source/S3_DATA"

            # Check if S3 data events are enabled using the base class method
            s3_data_enabled = self.get_log_source_status(region, "S3_DATA")

            if not s3_data_enabled:
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_id,
                        checked_value="CloudTrail S3 data events enabled",
                        actual_value=f"CloudTrail S3 data events are not enabled in {region}",
                        remediation=(
                            "Enable CloudTrail S3 data events in Security Lake. In the Security Lake console, "
                            "navigate to Settings > Log Sources and enable CloudTrail S3 data events. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securitylake enable-log-source --log-source S3_DATA --region {region}"
                        )
                    )
                )
            else:
                self.findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=resource_id,
                        checked_value="CloudTrail S3 data events enabled",
                        actual_value=f"CloudTrail S3 data events are enabled in {region}",
                        remediation="No remediation needed"
                    )
                )

        return self.findings
