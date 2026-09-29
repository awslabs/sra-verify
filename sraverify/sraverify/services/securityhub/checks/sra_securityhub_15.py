"""
SRA-SECURITYHUB-15: Security Hub V2 delegated administrator is the audit account.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityhub.base import SecurityHubCheck


class SRA_SECURITYHUB_15(SecurityHubCheck):
    """Check if the Security Hub V2 delegated administrator is the audit account."""

    meta = CheckMeta(
        check_id="SRA-SECURITYHUB-15",
        title="Security Hub V2 delegated administrator is the audit account",
        description=(
            "This check verifies that the delegated administrator for Security Hub, the "
            "unified service rather than Security Hub CSPM, is the audit (Security Tooling) "
            "account. The two services record their delegated administrator separately: a "
            "CSPM administrator that is not the management account is inherited by Security "
            "Hub, but a CSPM administrator set to the management account is not, because the "
            "management account cannot administer Security Hub. SRA-SECURITYHUB-07 reads only "
            "the CSPM designation."
        ),
        check_logic=(
            "Call securityhub:ListOrganizationAdminAccounts with Feature SecurityHubV2 from the "
            "management account. The answer is organization-wide, so one global row is "
            "produced. Passes if an AdminAccounts entry matches an --audit-account value. "
            "Fails if the list is empty or names another account. ERROR if --audit-account "
            "was not supplied."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="SecurityHub",
        resource_type="AWS::SecurityHub::HubV2",
        remediation=Remediation(
            text=(
                "From the management account, designate the audit account as the Security Hub "
                "delegated administrator."
            ),
            cli=(
                "aws securityhub enable-organization-admin-account "
                "--admin-account-id <audit-account-id> --feature SecurityHubV2 --region <region>"
            ),
            console=(
                "Security Hub console (securityhub/v2) in the management account, Get started, "
                "Delegated administrator, choose the audit account, select Trusted access, "
                "Configure."
            ),
        ),
        sra_sections=("Security Tooling account", "AWS Security Hub"),
        additional_urls=(
            "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-set-da.html",
            "https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_ListOrganizationAdminAccounts.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One global Finding.
        """
        checked_value = "Security Hub V2 delegated administrator is the audit account"
        resource_id = f"securityhub:hubv2-admin/{self.account_id}"

        # A missing flag cannot be changed by an AWS call, so it is decided first.
        if not self.audit_accounts:
            yield self.error(
                region="global",
                resource_id=resource_id,
                checked_value=checked_value,
                actual_value="Audit account ID not provided",
                remediation=(
                    "Re-run the check with the --audit-account parameter so the Security "
                    "Hub V2 delegated administrator can be compared against the audit account"
                ),
            )
            return

        # The V2 designation is organization-wide -- observed 2026-09-25 as the
        # same answer from us-east-1, us-west-2 and eu-central-1, including a
        # Region with no CSPM administrator -- so any scanned Region's endpoint
        # answers for the whole organization and the row is labelled global.
        response = self.get_organization_admin_accounts_v2(self.regions[0])

        if "Error" in response:
            error = response["Error"]
            if self.is_not_configured(error):
                # The service-wide 'not subscribed to AWS Security Hub' needle:
                # AWS answered that Security Hub is not enabled here, so no
                # delegated administrator can have been designated.
                yield self.failed(
                    region="global",
                    resource_id=resource_id,
                    checked_value=checked_value,
                    actual_value=(
                        "Security Hub is not enabled in the management account, so no "
                        "Security Hub V2 delegated administrator is designated"
                    ),
                )
            else:
                yield self.error(
                    region="global",
                    resource_id=resource_id,
                    checked_value=checked_value,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: {error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
            return

        # V2 entries carry no Status field (observed); honour one if AWS adds it.
        admin_ids = sorted(
            admin["AccountId"]
            for admin in response.get("AdminAccounts", [])
            if admin.get("AccountId")
            and admin.get("Status", "ENABLED") == "ENABLED"
        )
        expected = ", ".join(self.audit_accounts)

        if not admin_ids:
            yield self.failed(
                region="global",
                resource_id=resource_id,
                checked_value=checked_value,
                actual_value="No Security Hub V2 delegated administrator is designated",
                remediation=(
                    f"Designate the audit account ({self.audit_accounts[0]}) as the "
                    f"Security Hub delegated administrator: aws securityhub "
                    f"enable-organization-admin-account --admin-account-id "
                    f"{self.audit_accounts[0]} --feature SecurityHubV2"
                ),
            )
            return

        matching = [admin for admin in admin_ids if admin in self.audit_accounts]
        if matching:
            yield self.passed(
                region="global",
                resource_id=f"securityhub:hubv2-admin/{matching[0]}",
                checked_value=checked_value,
                actual_value=(
                    f"Security Hub V2 delegated administrator {matching[0]} is an audit "
                    f"account"
                ),
            )
        else:
            yield self.failed(
                region="global",
                resource_id=f"securityhub:hubv2-admin/{admin_ids[0]}",
                checked_value=checked_value,
                actual_value=(
                    f"Security Hub V2 delegated administrator is {', '.join(admin_ids)}, "
                    f"not the audit account ({expected})"
                ),
                remediation=(
                    f"Remove {admin_ids[0]} as the Security Hub delegated administrator and "
                    f"designate the audit account ({self.audit_accounts[0]})"
                ),
            )
