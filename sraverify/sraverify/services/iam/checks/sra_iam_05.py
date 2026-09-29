"""
Check that the member account root user has no credentials (SRA-IAM-05).
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import GLOBAL_REGION, Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.iam.base import IAMCheck

#: GetAccountSummary keys describing root user credentials, in report order,
#: with the wording each gets in a FAIL row.
_ROOT_CREDENTIAL_KEYS: tuple[tuple[str, str], ...] = (
    ("AccountPasswordPresent", "password"),
    ("AccountAccessKeysPresent", "access keys"),
    ("AccountSigningCertificatesPresent", "signing certificates"),
    ("AccountMFAEnabled", "MFA device"),
)


class SRA_IAM_05(IAMCheck):
    """Member account root user has no credentials."""

    meta = CheckMeta(
        check_id="SRA-IAM-05",
        title="Member account root user has no credentials",
        description=(
            "This check verifies that the root user of a member account has no "
            "password, no access keys, no signing certificates, and no MFA device. "
            "With centralized root access, root credentials can be deleted from member "
            "accounts so that the root user cannot sign in or recover its password, "
            "and any task that needs root is performed through a task-scoped privileged "
            "session from the management account or the IAM delegated administrator. "
            "AWS SRA recommends removing all member account root credentials. The "
            "management account is out of scope and produces no row."
        ),
        check_logic=(
            "Call IAM GetAccountSummary in the account. PASS if AccountPasswordPresent, "
            "AccountAccessKeysPresent, AccountSigningCertificatesPresent and "
            "AccountMFAEnabled are all 0. FAIL naming each credential present. No row "
            "for the management account. ERROR if the call fails. One global row."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="IAM",
        resource_type="AWS::Organizations::Account",
        remediation=Remediation(
            text=(
                "From the management account or the IAM delegated administrator, delete "
                "the member account root user credentials with a privileged root "
                "session scoped to IAMDeleteRootUserCredentials."
            ),
            cli=(
                "aws sts assume-root --region <region> --target-principal <member-account-id> "
                "--task-policy-arn arn=arn:aws:iam::aws:policy/root-task/IAMDeleteRootUserCredentials\n"
                "# with the returned credentials:\n"
                "aws iam delete-login-profile\n"
                "aws iam list-access-keys; aws iam delete-access-key --access-key-id <id>\n"
                "aws iam list-signing-certificates; aws iam delete-signing-certificate --certificate-id <id>\n"
                "aws iam list-mfa-devices; aws iam deactivate-mfa-device --serial-number <arn>"
            ),
            console=(
                "IAM console in the management or delegated administrator account, Root "
                "access management, select the member account, Take privileged action, "
                "Delete root user credentials."
            ),
        ),
        sra_sections=("Management account", "AWS Identity and Access Management"),
        additional_urls=(
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-enable-root-access.html",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user-privileged-task.html",
            "https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One global Finding for a member account; nothing for the management
            account.
        """
        organization = self.get_organization()
        if "Error" in organization:
            error = organization["Error"]
            yield self.error(
                region=GLOBAL_REGION,
                resource_id=self.account_id,
                actual_value=(
                    f"{error['Operation']} failed: {error['Code']}: "
                    f"{error['Message']}"
                ),
                remediation=self._remediation_for(error),
            )
            return

        management_id = organization.get("Organization", {}).get("MasterAccountId")
        if management_id == self.account_id:
            # Centralized root access cannot remove the management account's root
            # credentials, and that root user should keep a password with MFA.
            return

        summary = self.get_account_summary()
        if "Error" in summary:
            error = summary["Error"]
            yield self.error(
                region=GLOBAL_REGION,
                resource_id=self.account_id,
                actual_value=(
                    f"{error['Operation']} failed: {error['Code']}: "
                    f"{error['Message']}"
                ),
                remediation=self._remediation_for(error),
            )
            return

        summary_map = summary.get("SummaryMap", {})
        missing = [key for key, _ in _ROOT_CREDENTIAL_KEYS if key not in summary_map]
        if missing:
            # A key AWS did not return is not evidence the credential is absent.
            yield self.error(
                region=GLOBAL_REGION,
                resource_id=self.account_id,
                actual_value=(
                    "GetAccountSummary returned no value for "
                    f"{', '.join(missing)}"
                ),
                remediation=(
                    "Re-run the scan; if the keys stay absent, confirm the IAM "
                    "GetAccountSummary response in this partition reports root user "
                    "credentials"
                ),
            )
            return

        present = [label for key, label in _ROOT_CREDENTIAL_KEYS if summary_map[key]]
        if present:
            yield self.failed(
                region=GLOBAL_REGION,
                resource_id=self.account_id,
                actual_value=f"Root user has: {', '.join(present)}",
            )
        else:
            yield self.passed(
                region=GLOBAL_REGION,
                resource_id=self.account_id,
                actual_value=(
                    "Root user has no password, access keys, signing certificates or "
                    "MFA device"
                ),
            )
