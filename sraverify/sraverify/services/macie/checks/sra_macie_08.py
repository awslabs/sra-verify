"""
SRA-MACIE-08: Macie AutoEnable configuration is enabled for new member accounts.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.macie.base import MacieCheck


class SRA_MACIE_08(MacieCheck):
    """Check if Macie AutoEnable configuration is enabled for new member accounts."""

    meta = CheckMeta(
        check_id="SRA-MACIE-08",
        title="Macie AutoEnable configuration is enabled for new member accounts",
        description=(
            "This check verifies whether auto-enablement configuration for Macie is enabled for member accounts of the AWS Organization. "
            "This ensures that all existing and new member accounts will have Macie monitoring."
        ),
        check_logic=(
            "Check runs macie2 describe-organization-configuration. PASS if autoenable = True"
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.AUDIT,
        service="Macie",
        resource_type="AWS::Macie::Session",
        remediation=Remediation(
            text=(
                "Turn on automatic enablement in the Macie organization configuration "
                "so accounts joining the organization get Macie without manual action."
            ),
            cli=(
                "aws macie2 update-organization-configuration --auto-enable "
                "--region <region>"
            ),
            console=(
                "Macie console in the delegated administrator account, Accounts, "
                "Automatically enable Macie for new accounts. Repeat per Region."
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
                    checked_value="autoEnable: true",
                    actual_value="Failed to retrieve Macie organization configuration",
                    remediation="Ensure Macie is enabled and you have the necessary permissions to call the Macie DescribeOrganizationConfiguration API"
                )
                continue

            # Check if auto-enable is enabled
            auto_enable = org_config.get('autoEnable', False)

            if auto_enable:
                yield self.passed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="autoEnable: true",
                    actual_value=f"Macie AutoEnable configuration is enabled for new member accounts in region {region}"
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="autoEnable: true",
                    actual_value=f"Macie AutoEnable configuration is not enabled for new member accounts in region {region}",
                    remediation=(
                        f"Enable Macie AutoEnable configuration for new member accounts in region {region} using the AWS CLI command: "
                        f"aws macie2 update-organization-configuration --auto-enable --region {region}"
                    )
                )
