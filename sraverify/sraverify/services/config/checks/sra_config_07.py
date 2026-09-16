"""
SRA-CONFIG-07: AWS Config Aggregator.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.config.base import ConfigCheck


class SRA_CONFIG_07(ConfigCheck):
    """Check if Config administration for the AWS Organization has a delegated administrator."""

    meta = CheckMeta(
        check_id="SRA-CONFIG-07",
        title="Config administration for the AWS Organization has a delegated administrator",
        description=(
            "This check verifies whether Config service administration for your AWS Organization "
            "is delegated out of the AWS Organization management account."
        ),
        check_logic=(
            "Checks if a delegated administrator exists for the Config service using the "
            "list-delegated-administrators API with service principals config.amazonaws.com "
            "and config-multiaccountsetup.amazonaws.com."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.MANAGEMENT,
        service="Config",
        resource_type="AWS::Organizations::Account",
        remediation=Remediation(
            text=(
                "Register a delegated administrator for AWS Config out of the management "
                "account, for both the config.amazonaws.com and "
                "config-multiaccountsetup.amazonaws.com service principals."
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
            global Finding when none is registered.
        """
        # Get delegated administrators for both Config service principals
        delegated_response = self.get_delegated_administrators()

        if "Error" in delegated_response:
            error = delegated_response['Error']
            if self.is_not_configured(error):
                yield self.failed(
                    region="global",
                    resource_id=f"organization/{self.account_id}",
                    actual_value="No AWS Organization exists, so AWS Config can have no delegated administrator",
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

        if not delegated_admins:
            # No delegated administrator found for either service principal
            yield self.failed(
                region="global",
                resource_id="delegated-admin/none",
                checked_value="Delegated administrator exists for Config service",
                actual_value="No delegated administrator found for Config service",
                remediation=(
                    "Register a delegated administrator for Config using both service principals:\n"
                    "1. aws organizations register-delegated-administrator "
                    "--service-principal config.amazonaws.com "
                    "--account-id <AUDIT_ACCOUNT_ID>\n"
                    "2. aws organizations register-delegated-administrator "
                    "--service-principal config-multiaccountsetup.amazonaws.com "
                    "--account-id <AUDIT_ACCOUNT_ID>"
                ),
            )
            return

        # Group delegated admins by service principal to check coverage
        service_principals_covered = set()
        admin_accounts = {}

        for admin in delegated_admins:
            admin_id = admin.get('Id', 'Unknown')
            admin_name = admin.get('Name', 'Unknown')

            # In a real implementation, we would know which service principal this admin is for
            # For now, we'll just track unique admin accounts
            if admin_id not in admin_accounts:
                admin_accounts[admin_id] = {
                    'name': admin_name,
                    'count': 1
                }
            else:
                admin_accounts[admin_id]['count'] += 1

        # Check if we have full coverage of service principals
        if len(delegated_admins) >= 2:
            # We have at least one delegated admin for each service principal
            for admin_id, info in admin_accounts.items():
                admin_name = info['name']
                service_count = info['count']

                if service_count == 2:
                    # This account is delegated for both service principals
                    yield self.passed(
                        region="global",
                        resource_id=f"delegated-admin/{admin_id}",
                        checked_value="Delegated administrator exists for Config service",
                        actual_value=f"Config service has delegated administrator set to account {admin_id} ({admin_name}) for both service principals",
                    )
                else:
                    # This account is delegated for only one service principal.
                    # Pre-migration this site emitted status="WARN", which is not
                    # a legal Status member. A partially configured control is a
                    # FAIL per the product principle, and the substantive
                    # remediation below is preserved verbatim.
                    yield self.failed(
                        region="global",
                        resource_id=f"delegated-admin/{admin_id}",
                        checked_value="Delegated administrator exists for all Config service principals",
                        actual_value=f"Config service has delegated administrator set to account {admin_id} ({admin_name}) but not for all required service principals",
                        remediation=(
                            f"Ensure the same account is registered as a delegated administrator for both Config service principals:\n"
                            f"1. aws organizations register-delegated-administrator "
                            f"--service-principal config.amazonaws.com "
                            f"--account-id {admin_id}\n"
                            f"2. aws organizations register-delegated-administrator "
                            f"--service-principal config-multiaccountsetup.amazonaws.com "
                            f"--account-id {admin_id}"
                        ),
                    )
        else:
            # We don't have full coverage of service principals
            admin_list = []
            for admin_id, info in admin_accounts.items():
                admin_list.append(f"{admin_id} ({info['name']})")

            # Pre-migration this site emitted status="WARN", which is not a legal
            # Status member. A partially configured control is a FAIL per the
            # product principle, and the substantive remediation below is
            # preserved verbatim.
            yield self.failed(
                region="global",
                resource_id=f"delegated-admin/{','.join(admin_accounts.keys())}",
                checked_value="Delegated administrator exists for all Config service principals",
                actual_value=f"Config service has delegated administrators ({', '.join(admin_list)}) but not for all required service principals",
                remediation=(
                    "Ensure a delegated administrator is registered for both Config service principals:\n"
                    "1. aws organizations register-delegated-administrator "
                    "--service-principal config.amazonaws.com "
                    "--account-id <AUDIT_ACCOUNT_ID>\n"
                    "2. aws organizations register-delegated-administrator "
                    "--service-principal config-multiaccountsetup.amazonaws.com "
                    "--account-id <AUDIT_ACCOUNT_ID>"
                ),
            )
