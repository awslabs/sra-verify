"""Check if CloudTrail management logs are enabled for Security Lake."""

from typing import List, Dict, Any
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.core.logging import logger


class SRA_SECURITYLAKE_11(SecurityLakeCheck):
    """Check if CloudTrail management logs are enabled for Security Lake."""

    def __init__(self):
        """Initialize check."""
        super().__init__()
        self.check_id = "SRA-SECURITYLAKE-11"
        self.check_name = "Security Lake CloudTrail management logs enabled"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Amazon Security Lake is configured with "
            "CloudTrail management log and event source. CloudTrail management events, "
            "also known as control plane events, provide insight into management "
            "operations that are performed on CloudTrail in your AWS account. To "
            "collect CloudTrail management events in Security Lake, there must be at "
            "least one CloudTrail multi-Region organization trail that collects read "
            "and write CloudTrail management events. Logging must be enabled for the trail."
        )
        self.check_logic = (
            "Checks if the CloudTrail management logs source is enabled in Security Lake. "
            "The check passes if the CLOUD_TRAIL_MGMT log source is enabled. "
            "The check fails if the CLOUD_TRAIL_MGMT log source is not enabled."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """

        for region in self.regions:
            logger.debug(f"Checking if CloudTrail management logs are enabled in {region}")
            resource_id = f"arn:aws:securitylake:{region}:{self.account_id}:log-source/CLOUD_TRAIL_MGMT"

            # Check if CloudTrail management logs are enabled using the base class method
            cloudtrail_enabled = self.get_log_source_status(region, "CLOUD_TRAIL_MGMT")

            if not cloudtrail_enabled:
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_id,
                        checked_value="CloudTrail management logs enabled",
                        actual_value=f"CloudTrail management logs are not enabled in {region}",
                        remediation=(
                            "Enable CloudTrail management logs in Security Lake. In the Security Lake console, "
                            "navigate to Settings > Log Sources and enable CloudTrail management logs. "
                            "Ensure you have at least one CloudTrail multi-Region organization trail that collects "
                            "read and write management events. Alternatively, use the AWS CLI command: "
                            f"aws securitylake enable-log-source --log-source CLOUD_TRAIL_MGMT --region {region}"
                        )
                    )
                )
            else:
                self.findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=resource_id,
                        checked_value="CloudTrail management logs enabled",
                        actual_value=f"CloudTrail management logs are enabled in {region}",
                        remediation="No remediation needed"
                    )
                )

        return self.findings
