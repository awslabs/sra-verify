"""
SRA-MACIE-07: All active member accounts have relationship with delegated admin account enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.macie.base import MacieCheck


class SRA_MACIE_07(MacieCheck):
    """Check if all active member accounts have relationship with delegated admin account enabled."""

    meta = CheckMeta(
        check_id="SRA-MACIE-07",
        title="All active member accounts have relationship with delegated admin account enabled",
        description=(
            "This check verifies whether all active members accounts of the AWS Organization have Macie member relationship "
            "enabled with Macie delegated admin account. Amazon Macie is a data security service that discovers sensitive data "
            "by using machine learning and pattern matching, provides visibility into data security risks, and enables automated "
            "protection against those risks."
        ),
        check_logic=(
            "Check runs organizations list-accounts AND macie2 list-members. "
            "Check PASS if macie2 list-members includes all members of the AWS organization minus the audit account."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.AUDIT,
        service="Macie",
        resource_type="AWS::Macie::Session",
        remediation=Remediation(
            text=(
                "From the Macie delegated administrator account, add every active "
                "organization member as a Macie member and confirm each relationship "
                "reaches the Enabled state."
            ),
            cli=(
                "aws macie2 create-member "
                "--account accountId=<account-id>,email=<email> --region <region>"
            ),
            console=(
                "Macie console in the delegated administrator account, Accounts, "
                "select the accounts that are not enabled, Enable Macie. "
                "Repeat per Region."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Region.
        """
        audit_accounts = self.audit_accounts

        for region in self.regions:
            # Get organization members using the base class method with caching
            org_members = self.get_organization_members(region)

            # Check if the API call was successful
            if not org_members:
                yield self.failed(
                    region=region,
                    resource_id=f"organization/{self.account_id}",
                    checked_value="All active member accounts have Macie relationship enabled",
                    actual_value="Failed to retrieve AWS Organization members",
                    remediation="Ensure you have the necessary permissions to call the Organizations ListAccounts API"
                )
                continue

            # Get Macie members using the base class method with caching
            macie_members = self.get_macie_members(region)

            # Check if the API call was successful
            if macie_members is None:
                yield self.failed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}",
                    checked_value="All active member accounts have Macie relationship enabled",
                    actual_value="Failed to retrieve Macie members",
                    remediation="Ensure you have the necessary permissions to call the Macie ListMembers API"
                )
                continue

            # Filter active organization members
            active_org_members = [
                member for member in org_members
                if member.get('Status') == 'ACTIVE'
            ]

            # Create sets of account IDs for comparison
            active_org_account_ids = {member.get('Id') for member in active_org_members}
            macie_member_account_ids = {member.get('accountId') for member in macie_members}

            # Remove the current account (delegated admin) from the set of accounts to check
            if self.account_id in active_org_account_ids:
                active_org_account_ids.remove(self.account_id)

            # Remove audit accounts from the set of accounts to check if provided
            for audit_account in audit_accounts:
                if audit_account in active_org_account_ids:
                    active_org_account_ids.remove(audit_account)

            # Find accounts that are not Macie members
            missing_accounts = active_org_account_ids - macie_member_account_ids

            # Find accounts that are Macie members but not enabled
            not_enabled_accounts = []
            for member in macie_members:
                if member.get('accountId') in active_org_account_ids and member.get('relationshipStatus') != 'Enabled':
                    not_enabled_accounts.append(member.get('accountId'))

            if not missing_accounts and not not_enabled_accounts:
                yield self.passed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="All active member accounts have Macie relationship enabled",
                    actual_value=f"All {len(active_org_account_ids)} active member accounts have Macie relationship enabled in region {region}"
                )
            else:
                missing_accounts_str = ", ".join(missing_accounts) if missing_accounts else "None"
                not_enabled_accounts_str = ", ".join(not_enabled_accounts) if not_enabled_accounts else "None"

                yield self.failed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="All active member accounts have Macie relationship enabled",
                    actual_value=(
                        f"Not all active member accounts have Macie relationship enabled in region {region}. "
                        f"Missing accounts: {missing_accounts_str}. "
                        f"Accounts with relationship not enabled: {not_enabled_accounts_str}."
                    ),
                    remediation=(
                        f"Enable Macie for all member accounts in region {region} using the AWS CLI command: "
                        f"aws macie2 create-member --account account_details --region {region}"
                    )
                )
