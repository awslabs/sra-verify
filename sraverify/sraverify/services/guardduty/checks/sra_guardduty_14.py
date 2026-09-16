"""
Check if GuardDuty delegated admin account is the audit account.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.logging import logger
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_14(GuardDutyCheck):
    """Check if GuardDuty delegated admin account is the audit account."""

    meta = CheckMeta(
        check_id="SRA-GUARDDUTY-14",
        title="GuardDuty delegated admin is audit account",
        description=(
            "This check verifies whether GuardDuty delegated admin account is the audit account "
            "of your AWS organization. The audit account is dedicated to operating security services, "
            "monitoring AWS accounts, and automating security alerting and response. GuardDuty helps "
            "monitor resources for unusual and suspicious activities."
        ),
        check_logic=(
            "Check if GuardDuty delegated administrator is the audit account using "
            "GuardDuty list-organization-admin-accounts API."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="GuardDuty",
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(
            text=(
                "Delegate GuardDuty administration to the audit account in every "
                "enabled Region."
            ),
            cli=(
                "aws guardduty enable-organization-admin-account "
                "--admin-account-id <audit-account-id> --region <region>"
            ),
            console=(
                "GuardDuty console in the management account, Settings, Accounts, "
                "Delegated administrator, enter the audit account ID, Delegate."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Region, or one Finding describing why the GuardDuty
            delegated administrator could not be evaluated.
        """
        if not self.audit_accounts:
            logger.warning("Audit account ID not provided. Check cannot be completed.")
            # Missing required input is not a regional condition, report once.
            yield self.error(
                region="global",
                resource_id=f"guardduty:{self.account_id}",
                actual_value="Audit account ID not provided",
                remediation="Run sraverify with --audit-account parameter",
            )
            return

        # Use the first audit account in the list
        audit_account_id = self.audit_accounts[0]
        logger.debug(f"Using audit account ID: {audit_account_id}")

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
                yield self.error(
                    region=region,
                    resource_id=f"guardduty:{region}",
                    actual_value="Unable to access GuardDuty in this region",
                    remediation="Check permissions or if GuardDuty is supported in this region",
                )
                continue

            # List organization admin accounts for GuardDuty
            admin_accounts_response = self.list_organization_admin_accounts(region)

            # Check if there was an error in the response
            if "Error" in admin_accounts_response:
                error = admin_accounts_response["Error"]
                # BadRequestException from ListOrganizationAdminAccounts
                # means "not the master account" -- run the scan somewhere
                # else. That is an ERROR, and it is exactly why the
                # discriminator table does not declare this code for this
                # operation even though it declares it for
                # DescribeOrganizationConfiguration.
                if (
                    error["Code"] == "BadRequestException"
                    and "not the master account" in error["Message"]
                ):
                    yield self.error(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value="This check must be run from the organization management account",
                        remediation="Run this check from the AWS Organizations management account",
                    )
                else:
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

                # Check if the admin account is the audit account and is enabled
                if admin_account_id == audit_account_id and admin_account_status == 'ENABLED':
                    yield self.passed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value=f"GuardDuty delegated admin account is the audit account ({audit_account_id})",
                    )
                elif admin_account_id != audit_account_id:
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value=f"GuardDuty delegated admin account ({admin_account_id}) is not the audit account ({audit_account_id})",
                        remediation=f"Delegate GuardDuty administration to the audit account ({audit_account_id}) in {region}",
                    )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value=f"GuardDuty delegated admin is the audit account but status is {admin_account_status}",
                        remediation=f"Check the status of the delegated administrator account in {region}",
                    )
            else:
                # No admin account for GuardDuty
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value="GuardDuty service administration is not delegated to any account",
                    remediation=f"Delegate GuardDuty administration to the audit account ({audit_account_id}) using the Organizations service in {region}",
                )
