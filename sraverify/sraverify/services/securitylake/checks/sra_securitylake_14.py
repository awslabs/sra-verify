"""Check if Security Lake has a delegated administrator."""

from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securitylake.base import SecurityLakeCheck


class SRA_SECURITYLAKE_14(SecurityLakeCheck):
    """Check if Security Lake has a delegated administrator."""

    meta = CheckMeta(
        check_id="SRA-SECURITYLAKE-14",
        title="Security Lake has delegated administrator",
        description=(
            "This check verifies whether Security Lake service administration for "
            "the AWS Organization is delegated out from AWS Organization management "
            "account to a member account."
        ),
        check_logic=(
            "Checks if Security Lake has a delegated administrator configured. "
            "The check passes if at least one delegated administrator is found for the Security Lake service. "
            "The check fails if no delegated administrator is configured."
        ),
        severity=Severity.CRITICAL,
        # Delegated admin check runs from management account
        account_type=AccountType.MANAGEMENT,
        service="SecurityLake",
        resource_type="AWS::SecurityLake::SecurityLake",
        remediation=Remediation(
            text=(
                "Register a member account as the Security Lake delegated "
                "administrator from the organization management account."
            ),
            cli=(
                "aws organizations register-delegated-administrator "
                "--service-principal securitylake.amazonaws.com "
                "--account-id <log-archive-account-id>"
            ),
            console=(
                "AWS Organizations console, Services, Security Lake, Enable trusted "
                "access, then register the delegated administrator account."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """Run check.

        Yields:
            One global Finding.
        """
        # This is a global check, so we only need to run it once
        # Use the first region just to make the API call
        region = self.regions[0] if self.regions else "us-east-1"
        resource_id = f"arn:aws:organizations::global:delegatedadministrator/securitylake"

        # Get delegated administrators using the base class method
        delegated_admin = self.get_delegated_administrators(region)

        if not delegated_admin:
            yield self.failed(
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
                ),
            )
        else:
            admin_info = delegated_admin[0] if delegated_admin else {}  # Get first admin if exists
            admin_id = admin_info.get('Id', 'Unknown')
            yield self.passed(
                region="global",
                resource_id=resource_id,
                checked_value="Delegated administrator configured",
                actual_value=f"Delegated administrator {admin_id} is configured for Security Lake",
            )
