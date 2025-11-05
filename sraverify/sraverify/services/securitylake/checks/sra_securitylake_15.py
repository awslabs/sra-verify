"""Check if Security Lake delegated admin is Log Archive account."""

from typing import List, Dict, Any
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.core.logging import logger


class SRA_SECURITYLAKE_15(SecurityLakeCheck):
    """Check if Security Lake delegated admin is Log Archive account."""

    def __init__(self):
        """Initialize check."""
        super().__init__()
        self.account_type = "management"  # Delegated admin check runs from management account
        self.check_id = "SRA-SECURITYLAKE-15"
        self.check_name = "Security Lake delegated admin is log archive account"
        self.severity = "CRITICAL"
        self.description = (
            "This check verifies whether Security Lake delegated admin account "
            "is the Log Archive account of your AWS organization. The Log Archive "
            "account is dedicated to ingesting and archiving all security-related "
            "logs and backups."
        )
        self.check_logic = (
            "Checks if the Security Lake delegated administrator is the Log Archive account. "
            "The check passes if the delegated administrator account ID matches the Log Archive account ID. "
            "The check fails if there is no delegated administrator or if the delegated administrator "
            "is not the Log Archive account."
        )
        # Initialize log archive account attribute
        self._log_archive_accounts = None

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """

        # This is a global check, so we only need to run it once
        # Use the first region just to make the API call
        region = self.regions[0] if self.regions else "us-east-1"
        resource_id = f"arn:aws:organizations::global:delegatedadministrator/securitylake"

        # Check if Log Archive account ID is provided
        if not hasattr(self, '_log_archive_accounts') or not self._log_archive_accounts:
            self.findings.append(
                self.create_finding(
                    status="ERROR",
                    region="global",
                    resource_id=resource_id,
                    checked_value="Delegated administrator is Log Archive account",
                    actual_value="Log Archive Account ID not provided",
                    remediation="Provide the Log Archive account ID using the --log-archive-account parameter"
                )
            )
            return self.findings

        # Use the first log archive account if multiple are provided
        log_archive_account = self._log_archive_accounts[0]
        logger.debug(f"Using Log Archive account: {log_archive_account}")

        # Get delegated administrators using the base class method
        delegated_admin = self.get_delegated_administrators(region)

        if not delegated_admin:
            self.findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    resource_id=resource_id,
                    checked_value=f"Delegated administrator is Log Archive account {log_archive_account}",
                    actual_value="No delegated administrator configured for Security Lake",
                    remediation=(
                        f"Configure a delegated administrator for Security Lake and ensure it is the Log Archive account. "
                        f"In the AWS Organizations console, navigate to Services > Security Lake and delegate "
                        f"administration to the Log Archive account {log_archive_account}."
                    )
                )
            )
            return self.findings

        # Get the delegated admin account ID
        admin_info = delegated_admin[0] if delegated_admin else {}
        admin_id = admin_info.get('Id', 'Unknown')

        # Check if the delegated admin is the Log Archive account
        if admin_id == log_archive_account:
            self.findings.append(
                self.create_finding(
                    status="PASS",
                    region="global",
                    resource_id=resource_id,
                    checked_value=f"Delegated administrator is Log Archive account {log_archive_account}",
                    actual_value=f"Delegated administrator {admin_id} is the Log Archive account",
                    remediation="No remediation needed"
                )
            )
        else:
            self.findings.append(
                self.create_finding(
                    status="FAIL",
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
                    )
                )
            )

        return self.findings
