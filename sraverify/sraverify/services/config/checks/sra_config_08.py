"""
SRA-CONFIG-08: AWS Config Aggregator Authorization.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.config.base import ConfigCheck


class SRA_CONFIG_08(ConfigCheck):
    """Check if Config delegated admin account is the Security Tooling (Audit) account."""

    meta = CheckMeta(
        check_id="SRA-CONFIG-08",
        title="Config delegated admin account is the Security Tooling (Audit) account",
        description=(
            "This check verifies whether Config delegated admin account is the audit account of your "
            "AWS organization. The audit account is dedicated to operating security services, monitoring "
            "AWS accounts, and automating security alerting and response."
        ),
        check_logic=(
            "Compares the delegated admin account ID with the provided audit account ID."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.MANAGEMENT,
        service="Config",
        resource_type="AWS::Organizations::Account",
        remediation=Remediation(
            text=(
                "Register the audit account as the AWS Config delegated administrator for "
                "both the config.amazonaws.com and config-multiaccountsetup.amazonaws.com "
                "service principals, deregistering any other account first."
            ),
            cli=(
                "aws organizations register-delegated-administrator "
                "--service-principal config.amazonaws.com --account-id <AUDIT_ACCOUNT_ID>\n"
                "aws organizations register-delegated-administrator "
                "--service-principal config-multiaccountsetup.amazonaws.com "
                "--account-id <AUDIT_ACCOUNT_ID>"
            ),
            console=(
                "Config console in the management account, Settings, Delegated administrator, "
                "enter the audit account ID and delegate."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One global Finding per delegated administrator account, or one
            global Finding when the audit account is not the delegated
            administrator.
        """
        # Check if Audit account ID is provided
        if not self.audit_accounts:
            yield self.error(
                region="global",
                resource_id="delegated-admin/none",
                checked_value="Delegated administrator is audit account",
                actual_value="No audit account ID provided",
                remediation="Provide the audit account ID using the --audit-account parameter",
            )
            return

        # Get delegated administrators for both Config service principals
        delegated_admins = self.get_delegated_administrators()

        if not delegated_admins:
            # No delegated administrator found for either service principal
            yield self.failed(
                region="global",
                resource_id=f"delegated-admin/none",
                checked_value=f"Delegated administrator is audit account {', '.join(self.audit_accounts)}",
                actual_value=f"No delegated administrator found for Config service",
                remediation=(
                    f"Register the audit account as a delegated administrator for Config using both service principals:\n"
                    f"1. aws organizations register-delegated-administrator "
                    f"--service-principal config.amazonaws.com "
                    f"--account-id {self.audit_accounts[0]}\n"
                    f"2. aws organizations register-delegated-administrator "
                    f"--service-principal config-multiaccountsetup.amazonaws.com "
                    f"--account-id {self.audit_accounts[0]}"
                ),
            )
            return

        # Group delegated admins by account ID to check if the same account is used for both service principals
        admin_accounts = {}
        for admin in delegated_admins:
            admin_id = admin.get('Id', 'Unknown')
            admin_name = admin.get('Name', 'Unknown')

            if admin_id not in admin_accounts:
                admin_accounts[admin_id] = {
                    'name': admin_name,
                    'count': 1
                }
            else:
                admin_accounts[admin_id]['count'] += 1

        # Check if any of the audit accounts is a delegated administrator
        audit_account_found = False
        for audit_account_id in self.audit_accounts:
            if audit_account_id in admin_accounts:
                admin_info = admin_accounts[audit_account_id]
                admin_name = admin_info['name']
                service_count = admin_info['count']

                # Check if the audit account is delegated for both service principals
                if service_count == 2:
                    audit_account_found = True
                    yield self.passed(
                        region="global",
                        resource_id=f"delegated-admin/{audit_account_id}",
                        checked_value=f"Delegated administrator is audit account {audit_account_id}",
                        actual_value=f"Config delegated administrator is the audit account {audit_account_id} ({admin_name}) for both service principals",
                    )
                else:
                    audit_account_found = True
                    # Pre-migration this site emitted status="WARN", which is not
                    # a legal Status member. A partially configured control is a
                    # FAIL per the product principle, and the substantive
                    # remediation below is preserved verbatim.
                    yield self.failed(
                        region="global",
                        resource_id=f"delegated-admin/{audit_account_id}",
                        checked_value=f"Delegated administrator is audit account {audit_account_id} for both service principals",
                        actual_value=f"Config delegated administrator is the audit account {audit_account_id} ({admin_name}) but not for all required service principals",
                        remediation=(
                            f"Ensure the audit account is registered as a delegated administrator for both Config service principals:\n"
                            f"1. aws organizations register-delegated-administrator "
                            f"--service-principal config.amazonaws.com "
                            f"--account-id {audit_account_id}\n"
                            f"2. aws organizations register-delegated-administrator "
                            f"--service-principal config-multiaccountsetup.amazonaws.com "
                            f"--account-id {audit_account_id}"
                        ),
                    )

        # If no audit account is a delegated administrator
        if not audit_account_found:
            # List all accounts that are delegated administrators
            other_admins = []
            for admin_id, info in admin_accounts.items():
                other_admins.append(f"{admin_id} ({info['name']})")

            yield self.failed(
                region="global",
                resource_id=f"delegated-admin/none",
                checked_value=f"Delegated administrator is audit account {', '.join(self.audit_accounts)}",
                actual_value=f"Config delegated administrator(s) {', '.join(other_admins)} are not the audit account {', '.join(self.audit_accounts)}",
                remediation=(
                    f"1. Deregister the current delegated administrator(s).\n"
                    f"2. Register the audit account as a delegated administrator for both Config service principals:\n"
                    f"   aws organizations register-delegated-administrator "
                    f"--service-principal config.amazonaws.com "
                    f"--account-id {self.audit_accounts[0]}\n"
                    f"   aws organizations register-delegated-administrator "
                    f"--service-principal config-multiaccountsetup.amazonaws.com "
                    f"--account-id {self.audit_accounts[0]}"
                ),
            )
