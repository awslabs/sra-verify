"""
Check if GuardDuty service administration is delegated to a different account.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_13(GuardDutyCheck):
    """Check if GuardDuty service administration is delegated to a different account."""

    meta = CheckMeta(
        check_id="SRA-GUARDDUTY-13",
        title="GuardDuty service administration delegated",
        description=(
            "This check verifies whether GuardDuty service administration for the AWS Organization "
            "is delegated. Centralized management of GuardDuty across the organization improves "
            "security visibility and control."
        ),
        check_logic=(
            "Check if GuardDuty is configured with a delegated administrator using "
            "GuardDuty list-organization-admin-accounts API."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="GuardDuty",
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(
            text=(
                "Delegate GuardDuty administration to a security account other than the "
                "organization management account in every enabled Region."
            ),
            cli=(
                "aws guardduty enable-organization-admin-account "
                "--admin-account-id <security-account-id> --region <region>"
            ),
            console=(
                "GuardDuty console in the management account, Settings, Accounts, "
                "Delegated administrator, enter the security account ID, Delegate."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Region.
        """
        # Check all regions
        for region in self.regions:
            detector_id = self.get_detector_id(region)

            # Handle regions where we can't access GuardDuty
            if not detector_id:
                yield self.error(
                    region=region,
                    resource_id=f"guardduty:{region}",
                    actual_value="Unable to access GuardDuty in this region",
                    remediation="Check permissions or if GuardDuty is supported in this region",
                )
                continue

            # List organization admin accounts for GuardDuty
            admin_accounts_response = self.list_organization_admin_accounts(region)
            admin_accounts = admin_accounts_response.get('AdminAccounts', [])

            if admin_accounts:
                # GuardDuty has an admin account
                admin_account_id = admin_accounts[0].get('AdminAccountId')
                admin_account_status = admin_accounts[0].get('AdminStatus', 'Unknown')

                # Check if the admin account is different from the current account and is enabled
                if admin_account_id != self.account_id and admin_account_status == 'ENABLED':
                    yield self.passed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value=f"GuardDuty service administration is delegated to account {admin_account_id}",
                    )
                elif admin_account_id == self.account_id:
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value="GuardDuty service administration is delegated to the management account itself",
                        remediation=f"Delegate GuardDuty administration to a security account other than the management account in {region}",
                    )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value=f"GuardDuty service administration is delegated to account {admin_account_id} but status is {admin_account_status}",
                        remediation=f"Check the status of the delegated administrator account in {region}",
                    )
            else:
                # No admin account for GuardDuty
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value="GuardDuty service administration is not delegated to any account",
                    remediation=f"Delegate GuardDuty administration to a security account using the Organizations service in {region}",
                )
