"""Check if Security Lake organization configuration is enabled."""


from typing import List, Dict, Any
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.core.logging import logger



class SRA_SECURITYLAKE_04(SecurityLakeCheck):
    """Check if Security Lake organization configuration is enabled."""

    def __init__(self):
        """Initialize check."""
        super().__init__()
        self.check_id = "SRA-SECURITYLAKE-04"
        self.check_name = "Security Lake organization configuration enabled"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Amazon Security Lake has configuration that "
            "will be automatically enable new organization accounts as member accounts "
            "from an Amazon Security Lake administrator account."
        )
        self.check_logic = (
            "Gets the organization configuration for Security Lake in the region. "
            "The check passes if organization configuration exists, indicating that "
            "Security Lake is configured to automatically enable new organization accounts. "
            "The check fails if no organization configuration is found."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """

        for region in self.regions:
            logger.debug(f"Checking if Security Lake organization configuration is enabled in {region}")
            resource_id = f"arn:aws:securitylake:{region}:{self.account_id}:organization-configuration/default"

            # Get organization configuration using the base class method
            config = self.get_organization_configuration(region)

            if not config:
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_id,
                        checked_value="Organization configuration enabled",
                        actual_value=f"Security Lake organization configuration is not enabled in {region}",
                        remediation=(
                            "Enable Security Lake organization configuration. In the Security Lake console, "
                            "navigate to Settings > Organization Configuration and enable organization configuration. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securitylake enable-organization-configuration --region {region}"
                        )
                    )
                )
            else:
                self.findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=resource_id,
                        checked_value="Organization configuration enabled",
                        actual_value=f"Security Lake organization configuration is enabled in {region}",
                        remediation="No remediation needed"
                    )
                )

        return self.findings
