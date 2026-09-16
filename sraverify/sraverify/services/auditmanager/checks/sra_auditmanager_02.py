"""
Check if Audit Manager delegated admin is the audit account.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.auditmanager.base import AuditManagerCheck


class SRA_AUDITMANAGER_02(AuditManagerCheck):
    """Check if Audit Manager delegated admin is the audit account."""

    meta = CheckMeta(
        check_id="SRA-AUDITMANAGER-02",
        title="Audit Manager delegated admin is the audit account",
        description=(
            "This check verifies that the AWS Audit Manager delegated administrator "
            "is configured as the audit account. The delegated administrator should "
            "be the security tooling account to centralize audit management."
        ),
        check_logic=(
            "Get organization admin account using GetOrganizationAdminAccount API "
            "and verify it matches the audit account ID."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="AuditManager",
        resource_type="AWS::AuditManager::Account",
        remediation=Remediation(
            text=(
                "Register the audit (security tooling) account as the AWS Audit "
                "Manager delegated administrator in every enabled Region, so "
                "assessments and evidence collection are managed centrally rather "
                "than from the organization management account."
            ),
            cli=(
                "aws auditmanager register-organization-admin-account "
                "--admin-account-id <audit-account-id> --region <region>"
            ),
            console=(
                "AWS Console, Audit Manager, Settings, Delegated administrator, Edit."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per region, or one Finding describing why the
            delegated administrator could not be evaluated.
        """
        # The audit account IDs are required input: without them there is
        # nothing to compare the delegated administrator against, so the
        # control cannot be evaluated and the row is an ERROR rather than a
        # FAIL. The guard sits ahead of the region loop because
        # get_organization_admin_account is an AWS call whose result cannot
        # change this outcome. A missing --audit-account is also not a
        # regional condition, so it is reported once with region="global"
        # rather than fanned out across the Regions being scanned.
        if not self.audit_accounts:
            yield self.error(
                region="global",
                resource_id=None,
                actual_value="Audit account ID not provided",
                remediation="Re-run the check with the --audit-account parameter so the delegated administrator can be compared against the audit account"
            )
            return

        for region in self.regions:
            admin_response = self.get_organization_admin_account(region)

            if "Error" in admin_response:
                error = admin_response["Error"]

                if self.is_not_configured(error):
                    # The one declared pair for this operation is the
                    # setup-not-completed condition, so that is what this branch
                    # reports. A denied call with any other message is undeclared
                    # and reaches the ERROR branch below.
                    yield self.failed(
                        region=region,
                        resource_id=None,
                        actual_value="Audit Manager is not set up in this account, so no delegated administrator is configured",
                        remediation=f"Complete Audit Manager setup from the Audit Manager console in {region}, then register the audit account as delegated administrator using RegisterOrganizationAdminAccount"
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=None,
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
            else:
                admin_account_id = admin_response.get("adminAccountId")
                audit_accounts = self.audit_accounts

                if admin_account_id in audit_accounts:
                    yield self.passed(
                        region=region,
                        resource_id=f"auditmanager:admin:{admin_account_id}",
                        actual_value=admin_account_id
                    )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=f"auditmanager:admin:{admin_account_id}",
                        actual_value=admin_account_id or "No delegated administrator account ID returned",
                        remediation=f"Change delegated administrator to audit account in {region}. Current admin: {admin_account_id}, Expected audit accounts: {audit_accounts}"
                    )
