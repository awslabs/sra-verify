"""
Check if the Security Incident Response delegated administrator is the audit account.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityincidentresponse.base import SecurityIncidentResponseCheck


class SRA_SECURITYINCIDENTRESPONSE_01(SecurityIncidentResponseCheck):
    """Check if the Security Incident Response delegated administrator is the audit account."""

    meta = CheckMeta(
        check_id="SRA-SECURITYINCIDENTRESPONSE-01",
        title="Security Incident Response delegated admin is audit account",
        description=(
            "Verifies that the Security Incident Response delegated administrator is "
            "configured and is the audit account"
        ),
        check_logic=(
            "Lists delegated administrators for security-ir.amazonaws.com and verifies "
            "the audit account is designated"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="SecurityIncidentResponse",
        resource_type="AWS::Organizations::DelegatedAdministrator",
        remediation=Remediation(
            text=(
                "Register the audit account as the delegated administrator for AWS "
                "Security Incident Response in AWS Organizations."
            ),
            cli=(
                "aws organizations register-delegated-administrator "
                "--account-id <audit-account-id> "
                "--service-principal security-ir.amazonaws.com"
            ),
            console=(
                "AWS Organizations console, Services, AWS Security Incident Response, "
                "enable trusted access, then register the audit account as the "
                "delegated administrator."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding describing the delegated-administrator configuration.
        """
        region = self.regions[0] if self.regions else "us-east-1"

        # Check if audit accounts are provided
        audit_accounts = self.audit_accounts
        if not audit_accounts:
            # Missing required input is not a regional condition, report once.
            yield self.error(
                region="global",
                resource_id=None,
                actual_value="No audit accounts specified",
                remediation="Run with --audit-account parameter to specify audit account IDs"
            )
            return

        response = self.get_delegated_administrators()

        if "Error" in response:
            error = response["Error"]
            if self.is_not_configured(error):
                # AWS reported the registration absent, which is the same finding
                # as an empty delegated-administrator list below.
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value="No delegated administrator is configured for Security Incident Response",
                )
            else:
                yield self.error(
                    region=region,
                    resource_id=None,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation="Check IAM permissions for Organizations API access"
                )
            return

        delegated_admins = response.get("DelegatedAdministrators", [])

        if not delegated_admins:
            yield self.failed(
                region=region,
                resource_id=None,
                actual_value="No delegated administrator configured for Security Incident Response",
                remediation="Configure a delegated administrator for Security Incident Response using: aws organizations register-delegated-administrator --account-id <audit-account-id> --service-principal security-ir.amazonaws.com"
            )
        else:
            # Check if any of the delegated admins is the audit account
            audit_admin_found = False

            for admin in delegated_admins:
                admin_id = admin.get("Id")
                if admin_id in audit_accounts:
                    audit_admin_found = True
                    yield self.passed(
                        region=region,
                        resource_id=admin_id,
                        actual_value=f"Audit account {admin_id} is configured as delegated administrator"
                    )
                    break

            if not audit_admin_found:
                admin_ids = [admin.get("Id") for admin in delegated_admins]
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value=f"Delegated administrators found: {admin_ids}, but none are audit accounts: {audit_accounts}",
                    remediation="Register the audit account as delegated administrator: aws organizations register-delegated-administrator --account-id <audit-account-id> --service-principal security-ir.amazonaws.com"
                )
