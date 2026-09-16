"""
Check if IAM Access Analyzer delegated admin is the Audit account.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.accessanalyzer.base import AccessAnalyzerCheck


class SRA_ACCESSANALYZER_03(AccessAnalyzerCheck):
    """Check if IAM Access Analyzer delegated admin is the Audit account."""

    meta = CheckMeta(
        check_id="SRA-ACCESSANALYZER-03",
        title="IAM Access Analyzer Delegated Admin is the Audit Account",
        description=(
            "This check verifies whether IAA delegated admin account is the "
            "audit account of your AWS organization. Audit account is "
            "dedicated to operating security services, monitoring AWS accounts, and "
            "automating security alerting and response. IAA helps monitor resources "
            "shared outside zone of trust."
        ),
        check_logic=(
            "Check if the delegated administrator account matches any of the specified "
            "Audit account IDs"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="IAM Access Analyzer",
        resource_type="AWS::AccessAnalyzer::Analyzer",
        remediation=Remediation(
            text=(
                "Register the audit account as the IAM Access Analyzer delegated "
                "administrator, deregistering any other delegated administrator first."
            ),
            cli=(
                "aws organizations register-delegated-administrator "
                "--account-id <audit-account-id> "
                "--service-principal access-analyzer.amazonaws.com"
            ),
            console=(
                "IAM console in the management account, Access Analyzer, Settings, "
                "Delegated administrator, enter the audit account ID, Save changes."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """Execute the check.

        Yields:
            One global Finding for the delegated administrator.
        """

        delegated_response = self.get_delegated_admin()

        if "Error" in delegated_response:
            error = delegated_response['Error']
            if self.is_not_configured(error):
                yield self.failed(
                    region="global",
                    resource_id=f"organization/{self.account_id}",
                    actual_value="No AWS Organization exists, so IAM Access Analyzer can have no delegated administrator",
                )
            else:
                yield self.error(
                    region="global",
                    resource_id=f"organization/{self.account_id}",
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
            return

        delegated_admins = delegated_response.get('DelegatedAdministrators', [])
        delegated_admin = delegated_admins[0] if delegated_admins else {}

        if not delegated_admin:
            yield self.failed(
                region="global",
                resource_id=f"organization/{self.account_id}",
                actual_value="No delegated administrator configured for IAM Access Analyzer",
                remediation="Configure a delegated administrator for IAM Access Analyzer first",
            )
            return

        # Get the delegated admin account ID
        delegated_admin_id = delegated_admin.get('Id')

        # Audit accounts reach the check through the ScanContext-delegating
        # property, which returns [] when --audit-account was not supplied.
        audit_accounts = self.audit_accounts

        if not audit_accounts:
            yield self.error(
                region="global",
                resource_id=delegated_admin_id,
                actual_value="Audit Account ID not provided",
                remediation="Provide the Audit account IDs using --audit-account flag",
            )
            return

        # Check if delegated admin matches any of the specified Audit accounts
        if delegated_admin_id in audit_accounts:
            yield self.passed(
                region="global",
                resource_id=delegated_admin_id,
                actual_value=f"IAM Access Analyzer delegated administrator (Account: {delegated_admin_id}) "
                           f"matches one of the specified Audit accounts {', '.join(audit_accounts)}",
            )
        else:
            yield self.failed(
                region="global",
                resource_id=delegated_admin_id,
                actual_value=f"IAM Access Analyzer delegated administrator (Account: {delegated_admin_id}) "
                           f"does not match any of the specified Audit accounts ({', '.join(audit_accounts)})",
                remediation=f"Update the delegated administrator to be one of the Audit accounts ({', '.join(audit_accounts)})",
            )
