"""
Check if log archive account is in Security OU.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.organizations.base import OrganizationsCheck


class SRA_ORGANIZATIONS_09(OrganizationsCheck):
    """Check if log archive account is in Security OU."""

    meta = CheckMeta(
        check_id="SRA-ORGANIZATIONS-09",
        title="Log Archive account is in Security OU",
        description=(
            "This check verifies that the log archive account is located in the Security organizational unit. "
            "According to AWS SRA best practices, the log archive account should be placed in the Security OU "
            "to ensure proper isolation and governance of centralized logging infrastructure."
        ),
        check_logic=(
            "Get the Security OU under the organization root, then list all accounts in the Security OU. "
            "Check passes if the log archive account (provided via --log-archive-account CLI parameter) "
            "is found in the Security OU."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="Organizations",
        resource_type="AWS::Organizations::Account",
        remediation=Remediation(
            text=(
                "Move the log archive account into the Security organizational "
                "unit, creating the Security OU under the organization root first "
                "if it does not exist."
            ),
            cli=(
                "aws organizations move-account "
                "--account-id <log-archive-account-id> "
                "--source-parent-id <current-parent-id> "
                "--destination-parent-id <security-ou-id>"
            ),
            console=(
                "AWS Organizations console, AWS accounts, select the log archive "
                "account, Actions, Move, choose the Security OU."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per log archive account, or one Finding describing why
            the log archive account placement could not be determined.
        """
        # Organizations is a global service, use "global" as region
        region = "global"

        # Check if log archive account is provided
        if not self.log_archive_accounts:
            yield self.error(
                region=region,
                resource_id=None,
                actual_value="Log archive account ID not provided",
                remediation="Run check with --log-archive-account parameter to specify the log archive account ID",
                checked_value="Log Archive account in Security OU",
            )
            return

        # Get organization roots
        roots_response = self.get_roots()
        if "Error" in roots_response:
            error_message = roots_response["Error"].get("Message", "Unknown error")
            yield self.error(
                region=region,
                resource_id=None,
                actual_value=f"Error: {error_message}",
                remediation="Check IAM permissions for Organizations API access",
                checked_value="Log Archive account in Security OU",
            )
            return

        roots = roots_response.get("Roots", [])
        if not roots:
            yield self.error(
                region=region,
                resource_id=None,
                actual_value="No organization root found",
                remediation="Ensure AWS Organizations is enabled and properly configured",
                checked_value="Log Archive account in Security OU",
            )
            return

        root = roots[0]
        root_id = root.get("Id", "")

        # Get OUs under the root to find Security OU
        ous_response = self.get_ous_for_parent(root_id)
        if "Error" in ous_response:
            error_message = ous_response["Error"].get("Message", "Unknown error")
            yield self.error(
                region=region,
                resource_id=root_id,
                actual_value=f"Error: {error_message}",
                remediation="Check IAM permissions for Organizations API access",
                checked_value="Log Archive account in Security OU",
            )
            return

        ous = ous_response.get("OrganizationalUnits", [])

        # Find Security OU
        security_ou = None
        for ou in ous:
            if ou.get("Name") == "Security":
                security_ou = ou
                break

        if not security_ou:
            yield self.failed(
                region=region,
                resource_id=root_id,
                actual_value="Security OU not found under organization root",
                remediation=(
                    "Create a Security organizational unit under the organization root and move the "
                    "log archive account into it. Navigate to AWS Organizations in the console, create the "
                    "Security OU, then move the log archive account to the Security OU."
                ),
                checked_value="Log Archive account in Security OU",
            )
            return

        security_ou_id = security_ou.get("Id", "")

        # Get accounts in Security OU
        accounts_response = self.get_accounts_for_parent(security_ou_id)
        if "Error" in accounts_response:
            error_message = accounts_response["Error"].get("Message", "Unknown error")
            yield self.error(
                region=region,
                resource_id=security_ou_id,
                actual_value=f"Error: {error_message}",
                remediation="Check IAM permissions for Organizations API access",
                checked_value="Log Archive account in Security OU",
            )
            return

        accounts = accounts_response.get("Accounts", [])
        account_ids_in_security_ou = [acc.get("Id") for acc in accounts]

        # Check if log archive account(s) are in Security OU
        for log_archive_account_id in self.log_archive_accounts:
            if log_archive_account_id in account_ids_in_security_ou:
                # Find account name for better reporting
                account_name = next(
                    (acc.get("Name", "Unknown") for acc in accounts if acc.get("Id") == log_archive_account_id),
                    "Unknown"
                )
                yield self.passed(
                    region=region,
                    resource_id=log_archive_account_id,
                    actual_value=f"Log archive account {log_archive_account_id} ({account_name}) is in Security OU",
                    checked_value="Log Archive account in Security OU",
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=log_archive_account_id,
                    actual_value=f"Log archive account {log_archive_account_id} is not in Security OU",
                    remediation=(
                        f"Move the log archive account {log_archive_account_id} to the Security OU. "
                        "Navigate to AWS Organizations in the console, select the log archive account, "
                        "and move it to the Security OU."
                    ),
                    checked_value="Log Archive account in Security OU",
                )
