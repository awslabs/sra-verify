"""
SRA-MACIE-10: Macie member account limit not reached.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.macie.base import MacieCheck


class SRA_MACIE_10(MacieCheck):
    """Check if Macie member account limit not reached."""

    meta = CheckMeta(
        check_id="SRA-MACIE-10",
        title="Macie member account limit not reached",
        description=(
            "This check verifies whether the maximum number of allowed member accounts are already associated with the "
            "delegated administrator account for the AWS Organization."
        ),
        check_logic=(
            "Check runs macie2 describe-organization-configuration. PASS if maxaccountlimitreached = False"
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.AUDIT,
        service="Macie",
        resource_type="AWS::Macie::Session",
        remediation=Remediation(
            text=(
                "Open an AWS Support case requesting an increase to the Macie member "
                "account quota for the delegated administrator account."
            ),
            cli=(
                "aws support create-case --subject 'Increase Macie member account limit' "
                "--service-code amazon-macie --category-code other "
                "--severity-code low --communication-body '<details>'"
            ),
            console=(
                "AWS Support Center, Create case, Service limit increase, "
                "select Macie, request a higher member account limit."
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
            # Establish enablement through GetAdministratorAccount first; see the
            # same guard in sra_macie_08.py for why DescribeOrganizationConfiguration
            # cannot establish it. In short: when Macie is off it answers
            # "you must be the Macie administrator for an organization", which is
            # also what an enabled-but-delegated-elsewhere organization answers,
            # so that sentence is not declared semantic and this check would
            # report ERROR where its eight siblings report FAIL.
            admin_account = self.get_macie_administrator_account(region)
            if "Error" in admin_account and self.is_not_configured(
                admin_account["Error"]
            ):
                yield self.failed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="maxAccountLimitReached: false",
                    actual_value=f"Macie is not enabled in {region}, so no member account limit applies",
                )
                continue

            # Get organization configuration using the base class method with caching
            org_config = self.get_organization_configuration(region)

            if "Error" in org_config:
                error = org_config['Error']
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"macie2/{self.account_id}/{region}",
                        checked_value="maxAccountLimitReached: false",
                        actual_value=f"Macie is not enabled in {region}, so no member account limit applies",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"macie2/{self.account_id}/{region}",
                        checked_value="maxAccountLimitReached: false",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            # Check if max account limit is reached
            max_account_limit_reached = org_config.get('maxAccountLimitReached', False)

            if not max_account_limit_reached:
                yield self.passed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="maxAccountLimitReached: false",
                    actual_value=f"Macie member account limit not reached in region {region}"
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="maxAccountLimitReached: false",
                    actual_value=f"Macie member account limit reached in region {region}",
                    remediation=(
                        "Contact AWS Support to request an increase in the Macie member account limit"
                    )
                )
