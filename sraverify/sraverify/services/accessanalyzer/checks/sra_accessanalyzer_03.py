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

        delegated_admin = self.get_delegated_admin()

        if not delegated_admin:
            yield self.failed(
                region="global",
                resource_id=f"organization/{self.account_id}",
                actual_value="No delegated administrator configured for IAM Access Analyzer",
                remediation="Configure a delegated administrator for IAM Access Analyzer first",
            )
            return

        try:
            # Get the delegated admin account ID
            delegated_admin_id = delegated_admin.get('Id')

            # Audit accounts reach the check through the ScanContext-delegating
            # property. This used to be a two-branch hasattr probe whose first
            # branch tested an underscore-prefixed attribute that lives on
            # ScanContext and never on a check, so it was always False; the
            # elif fallback already resolved through this property. Collapsing
            # the two is behavior-preserving.
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

        except Exception as e:
            yield self.error(
                region="global",
                resource_id=delegated_admin_id if 'delegated_admin_id' in locals() else f"organization/{self.account_id}",
                actual_value=f"Error checking delegated administrator: {str(e)}",
                remediation="Ensure proper permissions to check Organizations structure",
            )
