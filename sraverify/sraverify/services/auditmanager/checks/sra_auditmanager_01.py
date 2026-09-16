"""
Check if AWS Audit Manager is enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.auditmanager.base import AuditManagerCheck


class SRA_AUDITMANAGER_01(AuditManagerCheck):
    """Check if AWS Audit Manager is enabled."""

    meta = CheckMeta(
        check_id="SRA-AUDITMANAGER-01",
        title="AWS Audit Manager is enabled",
        description=(
            "This check verifies that AWS Audit Manager is enabled in the AWS "
            "account. Audit Manager helps you continuously audit your AWS usage to "
            "simplify how you assess risk and compliance with regulations and "
            "industry standards."
        ),
        check_logic=(
            "Check account registration status using GetAccountStatus API. Check "
            "passes if status is ACTIVE."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service="AuditManager",
        resource_type="AWS::AuditManager::Account",
        remediation=Remediation(
            text=(
                "Register the account with AWS Audit Manager in every enabled Region "
                "so continuous evidence collection begins, using the Audit Manager "
                "console setup page or the RegisterAccount API."
            ),
            cli="aws auditmanager register-account --region <region>",
            console=(
                "AWS Console, Audit Manager, Get started, Complete AWS Audit Manager "
                "setup."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per region.
        """
        for region in self.regions:
            status_response = self.get_account_status(region)

            if "Error" in status_response:
                error = status_response["Error"]
                yield self.error(
                    region=region,
                    resource_id=None,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation="Check IAM permissions for Audit Manager API access"
                )
            else:
                account_status = status_response.get("status", "UNKNOWN")

                if account_status == "ACTIVE":
                    yield self.passed(
                        region=region,
                        resource_id=f"auditmanager:{self.account_id}",
                        actual_value=account_status
                    )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=None,
                        actual_value=account_status,
                        remediation=f"Enable AWS Audit Manager in {region} by registering the account using the RegisterAccount API or AWS console"
                    )
