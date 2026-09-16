"""
Check if IAM Access Analyzer has a delegated administrator for the organization.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.logging import logger
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.accessanalyzer.base import AccessAnalyzerCheck


class SRA_ACCESSANALYZER_02(AccessAnalyzerCheck):
    """Check if IAM Access Analyzer has a delegated administrator for the organization."""

    meta = CheckMeta(
        check_id="SRA-ACCESSANALYZER-02",
        title="IAM Access Analyzer Organization Delegated Administrator",
        description=(
            "This check verifies whether IAA service administration for your AWS "
            "Organization is delegated out of your AWS Organization management account. "
            "The delegated administrator has permissions to create and manage analyzers "
            "with the AWS organization as the zone of trust."
        ),
        check_logic=(
            "Check if a delegated administrator is configured for IAM Access Analyzer "
            "in the organization"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="IAM Access Analyzer",
        resource_type="AWS::AccessAnalyzer::Analyzer",
        remediation=Remediation(
            text=(
                "Register a delegated administrator for IAM Access Analyzer from the "
                "organization management account, so analyzer administration does not "
                "run out of the management account."
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
            One global Finding for the organization.
        """
        logger.debug(f"Executing {self.check_id} check for account {self.account_id}")

        # Reaches the shared accessor rather than session.client('organizations')
        # directly. Before this the whole body sat in `except Exception:` whose
        # handler yielded a **FAIL** naming the exception -- so a denied
        # ListDelegatedAdministrators, an Organizations outage, and a genuinely
        # absent delegated administrator all produced the same finding.
        delegated_response = self.get_delegated_admin()

        if "Error" in delegated_response:
            error = delegated_response['Error']
            if self.is_not_configured(error):
                yield self.failed(
                    region="global",
                    resource_id=f"organization/{self.account_id}",
                    actual_value=(
                        "No AWS Organization exists, so IAM Access Analyzer can "
                        "have no delegated administrator"
                    ),
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

        if delegated_admins:
            delegated_admin = delegated_admins[0]
            yield self.passed(
                region="global",
                resource_id=delegated_admin['Id'],
                actual_value=(
                    f"IAM Access Analyzer delegated administrator configured: "
                    f"Account {delegated_admin['Id']}"
                ),
            )
        else:
            yield self.failed(
                region="global",
                resource_id=f"organization/{self.account_id}",
                actual_value="No delegated administrator configured for IAM Access Analyzer",
                remediation=(
                    "Configure a delegated administrator for IAM Access Analyzer "
                    "using AWS Organizations"
                ),
            )
