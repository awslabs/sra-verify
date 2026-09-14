"""
SRA-INSPECTOR-06: Inspector Delegated Admin Account is the Audit Account.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.inspector.base import InspectorCheck


class SRA_INSPECTOR_06(InspectorCheck):
    """Check if Inspector delegated admin account is the audit account."""

    meta = CheckMeta(
        check_id="SRA-INSPECTOR-06",
        title="Inspector delegated admin account is the audit account",
        description=(
            "This check verifies whether Inspector delegated admin account is the audit account of your AWS organization. "
            "Audit account is dedicated to operating security services, monitoring AWS accounts, and automating security "
            "alerting and response. Inspector provides vulnerability management service."
        ),
        check_logic=(
            "Check runs inspector2 get-delegated-admin-account. PASS if delegated admin is the Audit account "
            "specified by flag --audit-account"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="Inspector",
        resource_type="AWS::Inspector::Assessment",
        remediation=Remediation(
            text=(
                "Delegate Amazon Inspector administration to the audit account in "
                "every enabled Region, deregistering any other delegated "
                "administrator first."
            ),
            cli=(
                "aws organizations register-delegated-administrator "
                "--account-id <audit-account-id> "
                "--service-principal inspector2.amazonaws.com"
            ),
            console=(
                "Inspector console in the management account, Settings, Account "
                "management, Delegated administrator, enter the audit account ID, "
                "Delegate."
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
            # Get delegated admin account for this region
            delegated_admin_response = self.get_delegated_admin(region)
            delegated_admin = delegated_admin_response.get('delegatedAdmin', {})
            delegated_admin_id = delegated_admin.get('accountId')

            # If no delegated admin is configured, report a failure
            if not delegated_admin_id:
                yield self.failed(
                    region=region,
                    resource_id=f"inspector2/{region}/delegated-admin",
                    checked_value="Inspector delegated admin account is the audit account",
                    actual_value="No delegated admin account is configured",
                    remediation=(
                        "Configure a delegated admin account for Inspector using the AWS Console or CLI command: "
                        f"aws organizations register-delegated-administrator --account-id <AUDIT_ACCOUNT_ID> "
                        f"--service-principal inspector2.amazonaws.com --region {region}"
                    ),
                )
                continue

            # Audit accounts reach the check through the ScanContext-delegating
            # property. This used to be a two-branch hasattr probe whose first
            # branch tested an underscore-prefixed attribute that lives on
            # ScanContext and never on a check, so it was always False; the
            # elif fallback already resolved through this property. Collapsing
            # the two is behavior-preserving.
            audit_accounts = self.audit_accounts

            if not audit_accounts:
                yield self.error(
                    region=region,
                    resource_id=f"inspector2/{region}/delegated-admin",
                    checked_value="Inspector delegated admin account is the audit account",
                    actual_value=f"Delegated admin account is {delegated_admin_id}, but no audit account was specified for comparison",
                    remediation="Run the check with the --audit-account parameter to specify the audit account",
                )
                continue

            # Check if the delegated admin is one of the audit accounts
            if delegated_admin_id in audit_accounts:
                yield self.passed(
                    region=region,
                    resource_id=f"inspector2/{region}/delegated-admin",
                    checked_value="Inspector delegated admin account is the audit account",
                    actual_value=f"Inspector delegated administrator (Account: {delegated_admin_id}) "
                                 f"matches one of the specified Audit accounts {', '.join(audit_accounts)}",
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"inspector2/{region}/delegated-admin",
                    checked_value="Inspector delegated admin account is the audit account",
                    actual_value=f"Inspector delegated administrator (Account: {delegated_admin_id}) "
                                 f"does not match any of the specified Audit accounts ({', '.join(audit_accounts)})",
                    remediation=(
                        "Update the delegated admin account to be the audit account using the AWS Console or CLI commands: "
                        f"1. aws organizations deregister-delegated-administrator --account-id {delegated_admin_id} "
                        f"--service-principal inspector2.amazonaws.com --region {region}\n"
                        f"2. aws organizations register-delegated-administrator --account-id {audit_accounts[0]} "
                        f"--service-principal inspector2.amazonaws.com --region {region}"
                    ),
                )
