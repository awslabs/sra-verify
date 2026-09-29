"""
Check that the IAM delegated administrator is the audit account (SRA-IAM-04).
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import GLOBAL_REGION, Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.iam.base import IAMCheck


class SRA_IAM_04(IAMCheck):
    """Centralized root access management is delegated to the audit account."""

    meta = CheckMeta(
        check_id="SRA-IAM-04",
        title="Centralized root access management is delegated to the audit account",
        description=(
            "This check verifies that the delegated administrator for IAM "
            "(service principal iam.amazonaws.com) is the audit (Security Tooling) "
            "account. The IAM delegated administrator can delete member account root "
            "credentials and start privileged root sessions, so AWS SRA recommends "
            "delegating that capability to the Security Tooling account rather than "
            "exercising it from the management account."
        ),
        check_logic=(
            "Call Organizations ListDelegatedAdministrators for iam.amazonaws.com from "
            "the management account. PASS if a delegated administrator is in "
            "--audit-account. FAIL if there is none or it is another account. ERROR if "
            "--audit-account is not supplied or the call fails. One global row."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="IAM",
        resource_type="AWS::Organizations::DelegatedAdministrator",
        remediation=Remediation(
            text=(
                "Register the audit account as the delegated administrator for IAM, "
                "deregistering any other IAM delegated administrator first."
            ),
            cli=(
                "aws organizations register-delegated-administrator "
                "--service-principal iam.amazonaws.com --account-id <audit-account-id>"
            ),
            console=(
                "IAM console in the management account, Root access management, "
                "Delegated administrator, Register, enter the audit account ID."
            ),
        ),
        sra_sections=("Security Tooling account", "AWS Identity and Access Management"),
        additional_urls=(
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-enable-root-access.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One global Finding for the IAM delegated administrator.
        """
        audit_accounts = self.audit_accounts
        # Decided before any call: a missing flag cannot be changed by AWS.
        if not audit_accounts:
            yield self.error(
                region=GLOBAL_REGION,
                resource_id=None,
                actual_value="Audit account ID not provided",
                remediation=(
                    "Re-run the check with the --audit-account parameter so the IAM "
                    "delegated administrator can be compared against the audit account"
                ),
            )
            return

        response = self.get_iam_delegated_administrators()

        if "Error" in response:
            error = response["Error"]
            if self.is_not_configured(error):
                yield self.failed(
                    region=GLOBAL_REGION,
                    resource_id=self.account_id,
                    actual_value=(
                        "No AWS Organization exists, so IAM can have no delegated "
                        "administrator"
                    ),
                )
            else:
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

        # Sorted so the cell is identical across runs.
        admin_ids = sorted(
            admin["Id"]
            for admin in response.get("DelegatedAdministrators", [])
            if admin.get("Id")
        )
        expected = ", ".join(audit_accounts)

        if not admin_ids:
            yield self.failed(
                region=GLOBAL_REGION,
                resource_id=self.account_id,
                actual_value="No delegated administrator is registered for iam.amazonaws.com",
            )
            return

        matching = [admin_id for admin_id in admin_ids if admin_id in audit_accounts]
        if matching:
            yield self.passed(
                region=GLOBAL_REGION,
                resource_id=matching[0],
                actual_value=(
                    f"IAM delegated administrator {matching[0]} is one of the audit "
                    f"accounts ({expected})"
                ),
            )
        else:
            yield self.failed(
                region=GLOBAL_REGION,
                resource_id=admin_ids[0],
                actual_value=(
                    f"IAM delegated administrator {', '.join(admin_ids)} is not one of "
                    f"the audit accounts ({expected})"
                ),
                remediation=(
                    f"Deregister {', '.join(admin_ids)} and register one of the audit "
                    f"accounts ({expected}) as the delegated administrator for "
                    "iam.amazonaws.com"
                ),
            )
