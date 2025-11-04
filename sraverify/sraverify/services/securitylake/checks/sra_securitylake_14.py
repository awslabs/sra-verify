"""Check if Security Lake has a delegated administrator."""

from typing import List, Dict, Any
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.core.logging import logger

class SRA_SECURITYLAKE_14(SecurityLakeCheck):
    """Check if Security Lake has a delegated administrator."""

    def __init__(self):
        """Initialize check."""
        super().__init__()
        self.check_id = "SRA-SECURITYLAKE-14"
        self.check_name = "Security Lake has delegated administrator"
        self.severity = "CRITICAL"
        self.description = (
            "This check verifies whether Security Lake service administration for "
            "the AWS Organization is delegated out from AWS Organization management "
            "account to a member account."
        )
        self.check_logic = (
            "Checks if Security Lake has a delegated administrator configured. "
            "The check passes if at least one delegated administrator is found for the Security Lake service. "
            "The check fails if no delegated administrator is configured."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """Run check."""
        findings = []

        # This is a global check, so we only need to run it once
        # Use the first region just to make the API call
        region = self.regions[0] if self.regions else "us-east-1"
        resource_id = f"arn:aws:organizations::global:delegatedadministrator/securitylake"

        # Get delegated administrators using the base class method
        delegated_admin = self.get_delegated_administrators(region)

        if not delegated_admin:
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    resource_id=resource_id,
                    checked_value="Delegated administrator configured",
                    actual_value="No delegated administrator configured for Security Lake",
                    remediation=(
                        "Configure a delegated administrator for Security Lake. In the AWS Organizations console, "
                        "navigate to Services > Security Lake and delegate administration to a member account. "
                        "Alternatively, use the AWS CLI command: "
                        "aws organizations register-delegated-administrator --service-principal securitylake.amazonaws.com "
                        "--account-id ACCOUNT_ID"
                    )
                )
            )
        else:
            admin_info = delegated_admin[0] if delegated_admin else {}  # Get first admin if exists
            admin_id = admin_info.get('Id', 'Unknown')
            findings.append(
                self.create_finding(
                    status="PASS",
                    region="global",
                    resource_id=resource_id,
                    checked_value="Delegated administrator configured",
                    actual_value=f"Delegated administrator {admin_id} is configured for Security Lake",
                    remediation="No remediation needed"
                )
            )

        return findings
