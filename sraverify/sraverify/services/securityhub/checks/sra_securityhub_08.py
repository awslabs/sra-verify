"""
SRA-SECURITYHUB-08: Security Hub check.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityhub.base import SecurityHubCheck


class SRA_SECURITYHUB_08(SecurityHubCheck):
    """Check if all active organization accounts are Security Hub members."""

    meta = CheckMeta(
        check_id="SRA-SECURITYHUB-08",
        title="All active organization accounts are Security Hub members",
        description=(
            "This check verifies whether all active members accounts of the AWS Organization are Security Hub members. "
            "Security Hub provides comprehensive security state and should include all AWS accounts."
        ),
        check_logic=(
            "Compare the outputs of organizations list-accounts and securityhub list-members. "
            "Make sure that the list includes all accounts, excluding the Security Hub admin (audit account) "
            "which is not considered a member."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.AUDIT,
        service="SecurityHub",
        resource_type="AWS::SecurityHub::Hub",
        remediation=Remediation(
            text=(
                "Add every active organization account as a Security Hub member in the "
                "delegated administrator account in each enabled Region."
            ),
            cli=(
                "aws securityhub create-members --account-details "
                "'AccountId=<account-id>' --region <region>"
            ),
            console=(
                "Security Hub console in the audit account, Settings, Accounts, select "
                "the accounts, Enable."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Region.
        """
        # Check each region separately
        for region in self.regions:
            # Get all organization accounts
            accounts_response = self.get_organization_accounts(region)

            # Get Security Hub members
            members_response = self.get_security_hub_members(region)

            resource_id = f"securityhub:members/{self.account_id}/{region}"

            if "Error" in accounts_response:
                error = accounts_response['Error']
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=resource_id,
                        checked_value="All active organization accounts are Security Hub members",
                        actual_value="No AWS Organization exists, so it has no accounts to enrol in Security Hub",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=resource_id,
                        checked_value="All active organization accounts are Security Hub members",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            if "Error" in members_response:
                error = members_response['Error']
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=resource_id,
                        checked_value="All active organization accounts are Security Hub members",
                        actual_value=f"Security Hub is not enabled in region {region}, so it has no member accounts",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=resource_id,
                        checked_value="All active organization accounts are Security Hub members",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            org_accounts = accounts_response.get('Accounts', [])
            securityhub_members = members_response.get('Members', [])

            # Create sets of account IDs for comparison
            active_org_account_ids = set()
            for account in org_accounts:
                if account.get('Status') == 'ACTIVE':
                    active_org_account_ids.add(account.get('Id'))

            securityhub_member_ids = set()
            for member in securityhub_members:
                securityhub_member_ids.add(member.get('AccountId'))

            # Determine the audit account ID. If no audit account is provided,
            # assume the current account is the audit account.
            audit_account_id = self.audit_accounts[0] if self.audit_accounts else self.account_id

            # Remove the audit account from the list of active organization accounts
            # since the audit account is the Security Hub admin and not a member
            if audit_account_id in active_org_account_ids:
                active_org_account_ids.remove(audit_account_id)

            # Find accounts that should be Security Hub members but aren't
            missing_accounts = active_org_account_ids - securityhub_member_ids

            if missing_accounts:
                missing_accounts_list = ', '.join(missing_accounts)
                yield self.failed(
                    region=region,
                    resource_id=resource_id,
                    checked_value="All active organization accounts are Security Hub members",
                    actual_value=(
                        f"The following active organization accounts are not Security Hub members in region {region}: "
                        f"{missing_accounts_list}. "
                        f"Active organization accounts: {len(active_org_account_ids)}, "
                        f"Security Hub members: {len(securityhub_member_ids)}"
                    ),
                    remediation=(
                        f"Add the missing accounts as Security Hub members in region {region}. "
                        f"In the AWS Console, navigate to Security Hub in the audit account, go to Settings > Accounts, "
                        f"and add the missing accounts. Alternatively, use the AWS CLI command: "
                        f"aws securityhub create-members --account-details 'AccountId={missing_accounts_list.replace(', ', ',AccountId=')}' --region {region}"
                    ),
                )
            else:
                yield self.passed(
                    region=region,
                    resource_id=resource_id,
                    checked_value="All active organization accounts are Security Hub members",
                    actual_value=(
                        f"All active organization accounts are Security Hub members in region {region}. "
                        f"Active organization accounts (excluding admin): {len(active_org_account_ids)}, "
                        f"Security Hub members: {len(securityhub_member_ids)}"
                    ),
                )
