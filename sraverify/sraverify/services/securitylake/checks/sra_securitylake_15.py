"""Check if Security Lake delegated admin is Log Archive account."""

from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.logging import logger
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securitylake.base import SecurityLakeCheck


class SRA_SECURITYLAKE_15(SecurityLakeCheck):
    """Check if Security Lake delegated admin is Log Archive account."""

    meta = CheckMeta(
        check_id="SRA-SECURITYLAKE-15",
        title="Security Lake delegated admin is log archive account",
        description=(
            "This check verifies whether Security Lake delegated admin account "
            "is the Log Archive account of your AWS organization. The Log Archive "
            "account is dedicated to ingesting and archiving all security-related "
            "logs and backups."
        ),
        check_logic=(
            "Checks if the Security Lake delegated administrator is the Log Archive account. "
            "The check passes if the delegated administrator account ID matches the Log Archive account ID. "
            "The check fails if there is no delegated administrator or if the delegated administrator "
            "is not the Log Archive account."
        ),
        severity=Severity.CRITICAL,
        # Delegated admin check runs from management account
        account_type=AccountType.MANAGEMENT,
        service="SecurityLake",
        resource_type="AWS::SecurityLake::SecurityLake",
        remediation=Remediation(
            text=(
                "Register the Log Archive account as the Security Lake delegated "
                "administrator for the organization."
            ),
            cli=(
                "aws organizations register-delegated-administrator "
                "--service-principal securitylake.amazonaws.com "
                "--account-id <log-archive-account-id>"
            ),
            console=(
                "AWS Organizations console, Services, Security Lake, register the "
                "Log Archive account as the delegated administrator."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One global Finding.
        """

        # This is a global check, so we only need to run it once
        # Use the first region just to make the API call
        region = self.regions[0] if self.regions else "us-east-1"
        resource_id = f"arn:aws:organizations::global:delegatedadministrator/securitylake"

        # Check if Log Archive account ID is provided
        if not self.log_archive_accounts:
            yield self.error(
                region="global",
                resource_id=resource_id,
                checked_value="Delegated administrator is Log Archive account",
                actual_value="Log Archive Account ID not provided",
                remediation="Provide the Log Archive account ID using the --log-archive-account parameter",
            )
            return

        # Use the first log archive account if multiple are provided
        log_archive_account = self.log_archive_accounts[0]
        logger.debug(f"Using Log Archive account: {log_archive_account}")

        # Get delegated administrators using the base class method
        delegated_response = self.get_delegated_administrators(region)

        if "Error" in delegated_response:
            error = delegated_response['Error']
            if self.is_not_configured(error):
                yield self.failed(
                    region="global",
                    resource_id=resource_id,
                    checked_value=f"Delegated administrator is Log Archive account {log_archive_account}",
                    actual_value="No AWS Organization exists, so Security Lake can have no delegated administrator",
                )
            else:
                yield self.error(
                    region="global",
                    resource_id=resource_id,
                    checked_value=f"Delegated administrator is Log Archive account {log_archive_account}",
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
            return

        delegated_admin = delegated_response.get('DelegatedAdministrators', [])

        if not delegated_admin:
            yield self.failed(
                region="global",
                resource_id=resource_id,
                checked_value=f"Delegated administrator is Log Archive account {log_archive_account}",
                actual_value="No delegated administrator configured for Security Lake",
                remediation=(
                    f"Configure a delegated administrator for Security Lake and ensure it is the Log Archive account. "
                    f"In the AWS Organizations console, navigate to Services > Security Lake and delegate "
                    f"administration to the Log Archive account {log_archive_account}."
                ),
            )
            return

        # Get the delegated admin account ID
        admin_info = delegated_admin[0] if delegated_admin else {}
        admin_id = admin_info.get('Id', 'Unknown')

        # Check if the delegated admin is the Log Archive account
        if admin_id == log_archive_account:
            yield self.passed(
                region="global",
                resource_id=resource_id,
                checked_value=f"Delegated administrator is Log Archive account {log_archive_account}",
                actual_value=f"Delegated administrator {admin_id} is the Log Archive account",
            )
        else:
            yield self.failed(
                region="global",
                resource_id=resource_id,
                checked_value=f"Delegated administrator is Log Archive account {log_archive_account}",
                actual_value=f"Delegated administrator {admin_id} is not the Log Archive account {log_archive_account}",
                remediation=(
                    f"Update the delegated administrator for Security Lake to be the Log Archive account. "
                    f"1. Deregister the current delegated administrator: "
                    f"aws organizations deregister-delegated-administrator --service-principal securitylake.amazonaws.com "
                    f"--account-id {admin_id} "
                    f"2. Register the Log Archive account: "
                    f"aws organizations register-delegated-administrator --service-principal securitylake.amazonaws.com "
                    f"--account-id {log_archive_account}"
                ),
            )
