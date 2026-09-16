"""
SRA-MACIE-06: Macie delegated admin account is the Security Tooling (Audit) account.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.macie.base import MacieCheck


class SRA_MACIE_06(MacieCheck):
    """Check if Macie delegated admin account is the Security Tooling (Audit) account."""

    meta = CheckMeta(
        check_id="SRA-MACIE-06",
        title="Macie delegated admin account is the Security Tooling (Audit) account",
        description=(
            "This check verifies whether Macie delegated admin account is the audit account of your AWS organization. "
            "audit account is dedicated to operating security services, monitoring AWS accounts, and automating security "
            "alerting and response. Macie provides sensitive data discovery service."
        ),
        check_logic=(
            "Check validates that the administrator account for Macie is the --audit-account. "
            "Check PASS if macie2 get-administrator-account account ID == audit account passed via —audit-account flag"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="Macie",
        resource_type="AWS::Macie::Session",
        remediation=Remediation(
            text=(
                "Register the Security Tooling (Audit) account as the Macie delegated "
                "administrator in every enabled Region, replacing any other delegate."
            ),
            cli=(
                "aws macie2 enable-organization-admin-account "
                "--admin-account-id <audit-account-id> --region <region>"
            ),
            console=(
                "Macie console in the management account, Settings, Delegated "
                "administrator, enter the Audit account ID, Delegate. Repeat per Region."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Region, or one Finding describing why the Macie
            administrator account could not be determined.
        """
        # Check if audit accounts are provided.
        audit_accounts = self.audit_accounts

        if not audit_accounts:
            # Missing required input is not a regional condition, report once.
            yield self.error(
                region="global",
                resource_id=f"macie2/{self.account_id}",
                checked_value="Administrator account is Audit account",
                actual_value="Audit Account ID not provided",
                remediation="Provide the Audit account IDs using --audit-account flag"
            )
            return

        for region in self.regions:
            # Get Macie administrator account using the base class method with caching
            admin_account = self.get_macie_administrator_account(region)

            if "Error" in admin_account:
                error = admin_account['Error']
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"macie2/{self.account_id}/{region}",
                        checked_value="Administrator account is Audit account",
                        actual_value=f"Macie is not enabled in {region}, so it has no administrator account to compare against the Audit account",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"macie2/{self.account_id}/{region}",
                        checked_value="Administrator account is Audit account",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            # A successful response with no 'administrator' member is a real
            # answer: AWS was asked, and there is no administrator.
            if 'administrator' not in admin_account:
                yield self.failed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="Administrator account is Audit account",
                    actual_value=f"No administrator account found for Macie in region {region}",
                    remediation=(
                        f"Enable Macie and register the Audit account ({', '.join(audit_accounts)}) as a delegated administrator for Macie in region {region} using the AWS CLI command: "
                        f"aws macie2 enable-organization-admin-account --admin-account-id {audit_accounts[0]} --region {region}"
                    )
                )
                continue

            # Check if administrator account exists and is enabled
            admin_account_id = admin_account.get('administrator', {}).get('accountId')
            relation_status = admin_account.get('administrator', {}).get('relationshipStatus')

            if not admin_account_id or relation_status != 'Enabled':
                yield self.failed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="Administrator account is Audit account",
                    actual_value=f"Administrator account found for Macie in region {region} but status is not Enabled: {relation_status}",
                    remediation=(
                        f"Enable Macie and register the Audit account ({', '.join(audit_accounts)}) as a delegated administrator for Macie in region {region} using the AWS CLI command: "
                        f"aws macie2 enable-organization-admin-account --admin-account-id {audit_accounts[0]} --region {region}"
                    )
                )
                continue

            # Check if administrator account is the Audit account
            if admin_account_id in audit_accounts:
                yield self.passed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/administrator/{admin_account_id}/{region}",
                    checked_value="Administrator account is Audit account",
                    actual_value=f"Macie administrator account {admin_account_id} is one of the specified Audit accounts in region {region}"
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/administrator/{admin_account_id}/{region}",
                    checked_value="Administrator account is Audit account",
                    actual_value=f"Macie administrator account {admin_account_id} is not one of the specified Audit accounts ({', '.join(audit_accounts)}) in region {region}",
                    remediation=(
                        f"Disable the current administrator and enable the Audit account ({', '.join(audit_accounts)}) as a delegated administrator for Macie in region {region} using the AWS CLI commands: "
                        f"aws macie2 disable-organization-admin-account --admin-account-id {admin_account_id} --region {region} && "
                        f"aws macie2 enable-organization-admin-account --admin-account-id {audit_accounts[0]} --region {region}"
                    )
                )
