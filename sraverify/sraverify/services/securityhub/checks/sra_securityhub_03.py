"""
SRA-SECURITYHUB-03: Security Hub check.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityhub.base import SecurityHubCheck


class SRA_SECURITYHUB_03(SecurityHubCheck):
    """Check if Security Hub administration for the account matches delegated administrator."""

    meta = CheckMeta(
        check_id="SRA-SECURITYHUB-03",
        title="Security Hub administration for the account matches delegated administrator",
        description=(
            "This check verifies whether Security Hub service administration for the AWS account is set to "
            "AWS Organization delegated admin account for Security Hub."
        ),
        check_logic=(
            "Check evaluates securityhub list-organization-admin-accounts and organizations list-delegated-administrators "
            "--service-principal securityhub.amazonaws.com. Check PASS if AccountID and ID returned are the same."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="SecurityHub",
        resource_type="AWS::SecurityHub::Hub",
        remediation=Remediation(
            text=(
                "Register one account as both the Organizations delegated administrator "
                "for securityhub.amazonaws.com and the Security Hub organization admin "
                "account."
            ),
            cli=(
                "aws organizations register-delegated-administrator "
                "--account-id <audit-account-id> "
                "--service-principal securityhub.amazonaws.com\n"
                "aws securityhub enable-organization-admin-account "
                "--admin-account-id <audit-account-id>"
            ),
            console=(
                "Organizations console, Services, Security Hub, Register delegated "
                "administrator; then Security Hub console in the management account, "
                "Settings, General, set the administrator account."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding for the organization.
        """
        # We only need to check one region for this
        region = self.regions[0]

        # Get delegated administrators for Security Hub
        delegated_response = self.get_delegated_administrators(region)

        # Get organization admin accounts
        admin_response = self.get_organization_admin_accounts(region)

        resource_id = f"delegated-admin/{self.account_id}"

        if "Error" in delegated_response:
            error = delegated_response['Error']
            if self.is_not_configured(error):
                yield self.failed(
                    region="global",
                    resource_id=resource_id,
                    checked_value="Security Hub delegated administrator matches organization admin account",
                    actual_value="No AWS Organization exists, so Security Hub can have no delegated administrator",
                )
            else:
                yield self.error(
                    region="global",
                    resource_id=resource_id,
                    checked_value="Security Hub delegated administrator matches organization admin account",
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
            return

        if "Error" in admin_response:
            error = admin_response['Error']
            if self.is_not_configured(error):
                yield self.failed(
                    region="global",
                    resource_id=resource_id,
                    checked_value="Security Hub delegated administrator matches organization admin account",
                    actual_value=f"Security Hub is not enabled in region {region}, so it has no administrator account",
                )
            else:
                yield self.error(
                    region="global",
                    resource_id=resource_id,
                    checked_value="Security Hub delegated administrator matches organization admin account",
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
            return

        delegated_admins = delegated_response.get('DelegatedAdministrators', [])
        org_admin_accounts = admin_response.get('AdminAccounts', [])

        # Check if there are any delegated administrators
        if not delegated_admins:
            # Format the actual value properly
            actual_value = 'aws organizations list-delegated-administrators --service-principal securityhub.amazonaws.com - No delegated administrators found'

            yield self.failed(
                region="global",
                resource_id=resource_id,
                checked_value="Security Hub delegated administrator matches organization admin account",
                actual_value=actual_value,
                remediation=(
                    "Register a delegated administrator for Security Hub. In the AWS Console, navigate to "
                    "Organizations, go to Services, find Security Hub, and register a delegated administrator. "
                    "Alternatively, use the AWS CLI command: "
                    "aws organizations register-delegated-administrator --account-id [AUDIT_ACCOUNT_ID] "
                    "--service-principal securityhub.amazonaws.com"
                ),
            )
            return

        # Check if there are any organization admin accounts
        if not org_admin_accounts:
            # Format the actual value properly
            actual_value = 'aws securityhub list-organization-admin-accounts - No Security Hub admin account found'

            yield self.failed(
                region="global",
                resource_id=resource_id,
                checked_value="Security Hub delegated administrator matches organization admin account",
                actual_value=actual_value,
                remediation=(
                    "Enable a Security Hub administrator account. In the AWS Console, navigate to Security Hub "
                    "in the management account, go to Settings > General, and set the administrator account. "
                    "Alternatively, use the AWS CLI command: "
                    "aws securityhub enable-organization-admin-account --admin-account-id [ADMIN_ID]"
                ),
            )
            return

        # Get the delegated admin ID and organization admin ID
        delegated_admin_id = delegated_admins[0].get('Id') if delegated_admins else None
        org_admin_id = org_admin_accounts[0].get('AccountId') if org_admin_accounts else None

        # Format the actual values properly
        delegated_admin_value = f'aws organizations list-delegated-administrators --service-principal securityhub.amazonaws.com - "DelegatedAdministrators": "Id": "{delegated_admin_id}"'
        org_admin_value = f'aws securityhub list-organization-admin-accounts - "AdminAccounts": "AccountId": "{org_admin_id}"'

        # Check if they match
        if delegated_admin_id and org_admin_id and delegated_admin_id == org_admin_id:
            yield self.passed(
                region="global",
                resource_id=resource_id,
                checked_value="Security Hub delegated administrator matches organization admin account",
                actual_value=f"{delegated_admin_value} matches {org_admin_value}",
            )
        else:
            yield self.failed(
                region="global",
                resource_id=resource_id,
                checked_value="Security Hub delegated administrator matches organization admin account",
                actual_value=f"{delegated_admin_value} does not match {org_admin_value}",
                remediation=(
                    "Update the Security Hub delegated administrator and organization admin account to match. "
                    "First, deregister the current delegated administrator using: "
                    f"aws organizations deregister-delegated-administrator --account-id {delegated_admin_id} "
                    "--service-principal securityhub.amazonaws.com\n"
                    "Then, register the correct account as the delegated administrator using: "
                    "aws organizations register-delegated-administrator --account-id [CORRECT_ACCOUNT_ID] "
                    "--service-principal securityhub.amazonaws.com\n"
                    "Finally, enable the same account as the Security Hub administrator using: "
                    "aws securityhub enable-organization-admin-account --admin-account-id [CORRECT_ACCOUNT_ID]"
                ),
            )
