"""
SRA-INSPECTOR-05: Inspector Delegated Admin Account is Configured.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.inspector.base import InspectorCheck


class SRA_INSPECTOR_05(InspectorCheck):
    """Check if Inspector delegated admin account is configured."""

    meta = CheckMeta(
        check_id="SRA-INSPECTOR-05",
        title="Inspector delegated admin account is configured",
        description=(
            "This check verifies whether a delegated administrator account is configured for Amazon Inspector. "
            "A delegated administrator can manage Inspector findings across all accounts in the organization."
        ),
        check_logic=(
            "Check runs inspector2 get-delegated-admin-account. Check PASS if response contains delegatedAdmin"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="Inspector",
        resource_type="AWS::Inspector::Assessment",
        remediation=Remediation(
            text=(
                "Register the audit account as the Amazon Inspector delegated "
                "administrator in every enabled Region."
            ),
            cli=(
                "aws organizations register-delegated-administrator "
                "--account-id <audit-account-id> "
                "--service-principal inspector2.amazonaws.com"
            ),
            console=(
                "Inspector console in the management account, Settings, Account "
                "management, Delegated administrator, enter the audit account ID, "
                "Delegate. Repeat per Region."
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

            if not delegated_admin_id:
                yield self.failed(
                    region=region,
                    resource_id=f"inspector2/{region}/delegated-admin",
                    checked_value="Inspector delegated admin account is configured",
                    actual_value="No delegated admin account is configured",
                    remediation=(
                        "Configure a delegated admin account for Inspector using the AWS Console or CLI command: "
                        f"aws organizations register-delegated-administrator --account-id <AUDIT_ACCOUNT_ID> "
                        f"--service-principal inspector2.amazonaws.com --region {region}"
                    ),
                )
            else:
                yield self.passed(
                    region=region,
                    resource_id=f"inspector2/{region}/delegated-admin",
                    checked_value="Inspector delegated admin account is configured",
                    actual_value=f"Delegated admin account {delegated_admin_id} is configured",
                )
