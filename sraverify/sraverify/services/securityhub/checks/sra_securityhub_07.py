"""
SRA-SECURITYHUB-07: Security Hub check.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityhub.base import SecurityHubCheck


class SRA_SECURITYHUB_07(SecurityHubCheck):
    """Check if Security Hub delegated admin account is the audit account."""

    meta = CheckMeta(
        check_id="SRA-SECURITYHUB-07",
        title="Security Hub delegated admin account is the audit account",
        description=(
            "This check verifies whether Security Hub delegated admin account is the audit account of your AWS organization. "
            "Audit account is dedicated to operating security services, monitoring AWS accounts, and automating security alerting and response. "
            "AWS Security Hub provides a comprehensive view of the security state in AWS and helps assess AWS environment against "
            "security industry standards and best practices."
        ),
        check_logic=(
            "Check evaluates value from organizations list-delegated-administrators --service-principal securityhub.amazonaws.com "
            "to ensure DelegatedAdministrators ID matches audit account ID passed via flag."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="SecurityHub",
        resource_type="AWS::SecurityHub::Hub",
        remediation=Remediation(
            text=(
                "Register the audit account as the Organizations delegated administrator "
                "for securityhub.amazonaws.com."
            ),
            cli=(
                "aws organizations register-delegated-administrator "
                "--account-id <audit-account-id> "
                "--service-principal securityhub.amazonaws.com --region <region>"
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
            One Finding per Region.
        """
        # Check each region separately
        for region in self.regions:
            # Get delegated administrators for Security Hub
            delegated_response = self.get_delegated_administrators(region)

            resource_id = f"delegated-admin/{self.account_id}"

            # If no audit accounts are provided, we can't perform the check
            if not self.audit_accounts:
                yield self.error(
                    region=region,
                    resource_id=resource_id,
                    checked_value="Delegated administrator is audit account",
                    actual_value="No audit account ID provided for comparison",
                    remediation="Provide an audit account ID using the --audit-account flag",
                )
                continue

            # Use the first audit account in the list
            audit_account_id = self.audit_accounts[0]

            if "Error" in delegated_response:
                error = delegated_response['Error']
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=resource_id,
                        checked_value=f"Delegated administrator is audit account {audit_account_id}",
                        actual_value="No AWS Organization exists, so Security Hub can have no delegated administrator",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=resource_id,
                        checked_value=f"Delegated administrator is audit account {audit_account_id}",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            delegated_admins = delegated_response.get('DelegatedAdministrators', [])

            # Check if there are any delegated administrators
            if not delegated_admins:
                yield self.failed(
                    region=region,
                    resource_id=resource_id,
                    checked_value=f"Delegated administrator is audit account {audit_account_id}",
                    actual_value=f"No Security Hub delegated administrator found in region {region}",
                    remediation=(
                        f"Register the audit account {audit_account_id} as the Security Hub delegated administrator. "
                        f"In the AWS Console, navigate to Security Hub in the management account, go to Settings > General, "
                        f"and set the delegated administrator. Alternatively, use the AWS CLI command: "
                        f"aws organizations register-delegated-administrator --account-id {audit_account_id} "
                        f"--service-principal securityhub.amazonaws.com --region {region}"
                    ),
                )
                continue

            # Check if the delegated administrator is the audit account
            delegated_admin_id = None
            for admin in delegated_admins:
                delegated_admin_id = admin.get('Id')
                if delegated_admin_id == audit_account_id:
                    yield self.passed(
                        region=region,
                        resource_id=resource_id,
                        checked_value=f"Delegated administrator is audit account {audit_account_id}",
                        actual_value=f"Security Hub delegated administrator is the audit account {audit_account_id}",
                    )
                    break
            else:
                # If we didn't break out of the loop, the delegated admin is not the audit account
                yield self.failed(
                    region=region,
                    resource_id=resource_id,
                    checked_value=f"Delegated administrator is audit account {audit_account_id}",
                    actual_value=f"Security Hub delegated administrator {delegated_admin_id} is not the audit account {audit_account_id}",
                    remediation=(
                        f"Update the Security Hub delegated administrator to be the audit account {audit_account_id}. "
                        f"First, deregister the current delegated administrator using: "
                        f"aws organizations deregister-delegated-administrator --account-id {delegated_admin_id} "
                        f"--service-principal securityhub.amazonaws.com --region {region}\n"
                        f"Then, register the audit account as the delegated administrator using: "
                        f"aws organizations register-delegated-administrator --account-id {audit_account_id} "
                        f"--service-principal securityhub.amazonaws.com --region {region}"
                    ),
                )
