"""
SRA-MACIE-05: Macie administration for the AWS Organization has a delegated administrator.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.macie.base import MacieCheck


class SRA_MACIE_05(MacieCheck):
    """Check if Macie administration for the AWS Organization has a delegated administrator."""

    meta = CheckMeta(
        check_id="SRA-MACIE-05",
        title="Macie administration for the AWS Organization has a delegated administrator",
        description=(
            "This check verifies whether Macie service administration for the AWS Organization is delegated out to AWS Organization management account."
        ),
        check_logic=(
            "Check validates that a delegated administrator exists for Macie. "
            "PASS if macie2 get-administrator-account returns a valid administrator account"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="Macie",
        resource_type="AWS::Macie::Session",
        remediation=Remediation(
            text=(
                "Register a delegated administrator for Macie from the AWS Organizations "
                "management account, in every enabled Region."
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
            One Finding per Region.
        """
        for region in self.regions:
            # Get Macie administrator account using the base class method with caching
            admin_account = self.get_macie_administrator_account(region)

            if "Error" in admin_account:
                error = admin_account['Error']
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"macie2/{self.account_id}/{region}",
                        checked_value="Administrator account for Macie",
                        actual_value=f"Macie is not enabled in {region}, so it has no administrator account",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"macie2/{self.account_id}/{region}",
                        checked_value="Administrator account for Macie",
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
                    checked_value="Administrator account for Macie",
                    actual_value=f"No administrator account found for Macie in region {region}",
                    remediation=(
                        f"Enable Macie and register a delegated administrator for Macie in region {region} using the AWS CLI command: "
                        f"aws macie2 enable-organization-admin-account --admin-account-id your-audit-account-id --region {region}"
                    )
                )
                continue

            # Check if administrator account exists and is enabled
            admin_account_id = admin_account.get('administrator', {}).get('accountId')
            relation_status = admin_account.get('administrator', {}).get('relationshipStatus')

            if admin_account_id and relation_status == 'Enabled':
                yield self.passed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/administrator/{admin_account_id}/{region}",
                    checked_value="Administrator account for Macie",
                    actual_value=f"Macie has an administrator account: {admin_account_id} with status: {relation_status} in region {region}"
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="Administrator account for Macie",
                    actual_value=f"Administrator account found for Macie in region {region} but status is not Enabled: {relation_status}",
                    remediation=(
                        f"Enable Macie and register a delegated administrator for Macie in region {region} using the AWS CLI command: "
                        f"aws macie2 enable-organization-admin-account --admin-account-id your-audit-account-id --region {region}"
                    )
                )
