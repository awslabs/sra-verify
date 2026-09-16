"""
SRA-SECURITYHUB-06: Security Hub check.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityhub.base import SecurityHubCheck


class SRA_SECURITYHUB_06(SecurityHubCheck):
    """Check if Security Hub administration for the AWS Organization has a delegated administrator."""

    meta = CheckMeta(
        check_id="SRA-SECURITYHUB-06",
        title="Security Hub administration for the AWS Organization has a delegated administrator",
        description=(
            "This check verifies whether Security Hub service administration for the AWS Organization "
            "is set to AWS Organization delegated admin account for Security Hub."
        ),
        check_logic=(
            "Check evaluates securityhub list-organization-admin-accounts and organizations list-delegated-administrators "
            "--service-principal securityhub.amazonaws.com. Check PASS if AccountID and ID returned are the same."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="SecurityHub",
        resource_type="AWS::Organizations::Account",
        remediation=Remediation(
            text=(
                "Delegate Security Hub administration for the organization to the audit "
                "account, and register that same account as the Organizations delegated "
                "administrator for securityhub.amazonaws.com."
            ),
            cli=(
                "aws securityhub enable-organization-admin-account "
                "--admin-account-id <audit-account-id> --region <region>\n"
                "aws organizations register-delegated-administrator "
                "--account-id <audit-account-id> "
                "--service-principal securityhub.amazonaws.com"
            ),
            console=(
                "Security Hub console in the management account, Settings, General, "
                "Delegated administrator, enter the audit account ID, Delegate."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding for the organization.
        """
        # This check only needs to run in one region since it's an organization-wide setting
        region = self.regions[0] if self.regions else "us-east-1"

        # Get organization admin accounts
        admin_response = self.get_organization_admin_accounts(region)

        # Get delegated administrators
        delegated_response = self.get_delegated_administrators(region)

        resource_id = f"delegated-admin/{self.account_id}"

        if "Error" in admin_response:
            error = admin_response['Error']
            if self.is_not_configured(error):
                yield self.failed(
                    region=region,
                    resource_id=resource_id,
                    checked_value="Security Hub admin account matches Organizations delegated admin",
                    actual_value=f"Security Hub is not enabled in region {region}, so it has no administrator account",
                )
            else:
                yield self.error(
                    region=region,
                    resource_id=resource_id,
                    checked_value="Security Hub admin account matches Organizations delegated admin",
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
            return

        if "Error" in delegated_response:
            error = delegated_response['Error']
            if self.is_not_configured(error):
                yield self.failed(
                    region=region,
                    resource_id=resource_id,
                    checked_value="Security Hub admin account matches Organizations delegated admin",
                    actual_value="No AWS Organization exists, so Security Hub can have no delegated administrator",
                )
            else:
                yield self.error(
                    region=region,
                    resource_id=resource_id,
                    checked_value="Security Hub admin account matches Organizations delegated admin",
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
            return

        admin_accounts = admin_response.get('AdminAccounts', [])
        delegated_admins = delegated_response.get('DelegatedAdministrators', [])

        # Check if there's a match between Security Hub admin and Organizations delegated admin
        sh_admin_id = None
        for admin in admin_accounts:
            if admin.get('Status') == 'ENABLED':
                sh_admin_id = admin.get('AccountId')
                break

        org_admin_id = None
        for admin in delegated_admins:
            org_admin_id = admin.get('Id')
            break

        if not sh_admin_id or not org_admin_id:
            yield self.failed(
                region=region,
                resource_id=resource_id,
                checked_value=(
                    "aws organizations list-delegated-administrators --service-principal securityhub.amazonaws.com - "
                    "\"DelegatedAdministrators\": \"Id\": \"[ADMIN_ID]\""
                    "aws securityhub list-organization-admin-accounts - \"AdminAccounts\": \"AccountId\": \"[ADMIN_ID]\""
                ),
                actual_value=f"No Security Hub admin account or Organizations delegated admin found",
                remediation=(
                    "Configure a Security Hub delegated administrator account. In the management account, "
                    "use the AWS CLI command: "
                    f"aws securityhub enable-organization-admin-account --admin-account-id [AUDIT_ACCOUNT_ID] --region {region}"
                ),
            )
        elif sh_admin_id != org_admin_id:
            yield self.failed(
                region=region,
                resource_id=resource_id,
                checked_value=(
                    "aws organizations list-delegated-administrators --service-principal securityhub.amazonaws.com - "
                    "\"DelegatedAdministrators\": \"Id\": \"[ADMIN_ID]\""
                    "aws securityhub list-organization-admin-accounts - \"AdminAccounts\": \"AccountId\": \"[ADMIN_ID]\""
                ),
                actual_value=f"Organizations delegated admin for securityhub {org_admin_id} is different than the Security Hub Admin account {sh_admin_id}",
                remediation=(
                    "Ensure the same account is used as both the Security Hub admin and the Organizations delegated admin. "
                    "First, remove the current delegated admin using: "
                    f"aws organizations deregister-delegated-administrator --account-id {org_admin_id} --service-principal securityhub.amazonaws.com"
                    "Then, set the Security Hub admin account as the delegated admin: "
                    f"aws organizations register-delegated-administrator --account-id {sh_admin_id} --service-principal securityhub.amazonaws.com"
                ),
            )
        else:
            yield self.passed(
                region=region,
                resource_id=resource_id,
                checked_value="Security Hub delegated administrator matches organization admin account",
                actual_value=f"Delegated admin account {org_admin_id} matches Security Hub admin account {sh_admin_id}",
            )
