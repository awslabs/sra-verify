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
            # Get organization configuration using the base class method with caching
            org_config = self.get_organization_configuration(region)

            # Check if the API call was successful
            if not org_config:
                yield self.failed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="maxAccountLimitReached: false",
                    actual_value="Failed to retrieve Macie organization configuration",
                    remediation="Ensure Macie is enabled and you have the necessary permissions to call the Macie DescribeOrganizationConfiguration API"
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
