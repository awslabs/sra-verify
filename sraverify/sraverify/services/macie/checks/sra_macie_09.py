"""
SRA-MACIE-09: All active member accounts have Macie enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.macie.base import MacieCheck


class SRA_MACIE_09(MacieCheck):
    """Check if all active member accounts have Macie enabled."""

    meta = CheckMeta(
        check_id="SRA-MACIE-09",
        title="All active member accounts have Macie enabled",
        description=(
            "This check verifies whether all active members accounts of the AWS Organization have Macie enabled. "
            "Amazon Macie is a data security service that discovers sensitive data by using machine learning and pattern matching, "
            "provides visibility into data security risks, and enables automated protection against those risks."
        ),
        check_logic=(
            "Check runs macie2 list-members, PASS if 'relationshipStatus': 'Enabled' for all members"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.AUDIT,
        service="Macie",
        resource_type="AWS::Macie::Session",
        remediation=Remediation(
            text=(
                "From the Macie delegated administrator account, enable Macie for every "
                "member account so each membership reports the Enabled relationship status."
            ),
            cli="aws macie2 enable-macie --region <region>",
            console=(
                "Macie console in the delegated administrator account, Accounts, "
                "select the member accounts, Enable Macie. Repeat per Region."
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
            # Get Macie members using the base class method with caching
            macie_members = self.get_macie_members(region)

            # Check if the API call was successful
            if macie_members is None:
                yield self.failed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="All member accounts have Macie enabled",
                    actual_value="Failed to retrieve Macie members",
                    remediation="Ensure you have the necessary permissions to call the Macie ListMembers API"
                )
                continue

            # Check if there are any members
            if not macie_members:
                yield self.failed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="All member accounts have Macie enabled",
                    actual_value="No Macie members found",
                    remediation=f"Enable Macie for member accounts in region {region} using the AWS CLI command: aws macie2 create-member --account account_details --region {region}"
                )
                continue

            # Check if all members have Macie enabled
            disabled_members = [
                member for member in macie_members
                if member.get('relationshipStatus') != 'Enabled'
            ]

            if not disabled_members:
                yield self.passed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="All member accounts have Macie enabled",
                    actual_value=f"All {len(macie_members)} member accounts have Macie enabled in region {region}"
                )
            else:
                disabled_account_ids = [member.get('accountId', 'Unknown') for member in disabled_members]
                disabled_accounts_str = ", ".join(disabled_account_ids)

                yield self.failed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="All member accounts have Macie enabled",
                    actual_value=f"{len(disabled_members)} out of {len(macie_members)} member accounts do not have Macie enabled in region {region}: {disabled_accounts_str}",
                    remediation=(
                        f"Enable Macie for all member accounts in region {region} using the AWS CLI command: "
                        f"aws macie2 enable-macie --region {region}"
                    )
                )
