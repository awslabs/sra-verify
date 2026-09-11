"""
Check if Firewall Manager delegated administrator is the audit account.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.firewallmanager.base import FirewallManagerCheck


class SRA_FIREWALLMANAGER_01(FirewallManagerCheck):
    """Check if Firewall Manager delegated administrator is the audit account."""

    meta = CheckMeta(
        check_id="SRA-FIREWALLMANAGER-01",
        title="Firewall Manager delegated administrator is the audit account",
        description=(
            "Verifies that AWS Firewall Manager delegated administrator is configured "
            "and set to the audit account"
        ),
        check_logic=(
            "Calls get_admin_account() to retrieve the Firewall Manager administrator "
            "account and verifies it matches the audit account ID"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="FirewallManager",
        resource_type="AWS::FMS::AdminAccount",
        remediation=Remediation(
            text=(
                "Designate the audit account as the AWS Firewall Manager delegated "
                "administrator from the organization management account, and wait for "
                "its role status to reach READY."
            ),
            cli="aws fms put-admin-account --admin-account <audit-account-id> --region us-east-1",
            console=(
                "AWS Firewall Manager console in the management account, Settings, "
                "Firewall Manager administrator, enter the audit account ID, Submit."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding for the Firewall Manager administrator account.
        """
        region = "us-east-1"

        admin_response = self.get_admin_account()

        if "Error" in admin_response:
            yield self.error(
                region=region,
                resource_id=None,
                actual_value=admin_response["Error"].get("Message", "Unknown error"),
                remediation="Configure Firewall Manager delegated administrator: https://docs.aws.amazon.com/waf/latest/developerguide/fms-prereq.html"
            )
            return

        admin_account = admin_response.get("AdminAccount")
        role_status = admin_response.get("RoleStatus")

        if not admin_account:
            yield self.failed(
                region=region,
                resource_id=None,
                actual_value="No Firewall Manager administrator configured",
                remediation="Set up Firewall Manager administrator account: https://docs.aws.amazon.com/waf/latest/developerguide/fms-prereq.html"
            )
        elif not self.audit_accounts:
            yield self.error(
                region=region,
                resource_id=admin_account,
                actual_value=f"Firewall Manager administrator is {admin_account}, but audit account not specified",
                remediation="Run check with --audit-account parameter to verify delegated administrator"
            )
        elif admin_account not in self.audit_accounts:
            yield self.failed(
                region=region,
                resource_id=admin_account,
                actual_value=f"Firewall Manager administrator is {admin_account}, expected one of {self.audit_accounts}",
                remediation=f"Change Firewall Manager administrator to audit account using PutAdminAccount API"
            )
        elif role_status != "READY":
            yield self.failed(
                region=region,
                resource_id=admin_account,
                actual_value=f"Firewall Manager administrator status is {role_status}",
                remediation="Wait for administrator account to reach READY status or reconfigure if in error state"
            )
        else:
            yield self.passed(
                region=region,
                resource_id=admin_account,
                actual_value=f"Firewall Manager administrator is audit account {admin_account} with status {role_status}"
            )
