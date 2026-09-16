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
            detectors = self.get_detector_id(region)

            # Test for the error result before reading any success-path key: this
            # is where "GuardDuty is not enabled here" and "the call failed" part
            # company.
            if "Error" in detectors:
                error = detectors["Error"]
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}",
                        actual_value=(
                            f"GuardDuty is not configured in this Region "
                            f"({error['Code']})"
                        ),
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"guardduty:{region}",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            detector_id = self.detector_id_of(detectors)

            if not detector_id:
                # Reached only after the error test above passed, so ListDetectors
                # succeeded and named no detector: GuardDuty is not enabled in this
                # Region. AWS answered, and the answer is that the control is absent,
                # which is a FAIL. Reporting it as ERROR asserted an inability to
                # determine something we had in fact determined.
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}",
                    actual_value="No GuardDuty detector in this Region",
                    remediation=f"Enable GuardDuty in {region}",
                )
                continue

            # List organization admin accounts for GuardDuty
            admin_accounts_response = self.list_organization_admin_accounts(region)

            if "Error" in admin_accounts_response:
                error = admin_accounts_response["Error"]
                yield self.error(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
                continue
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
