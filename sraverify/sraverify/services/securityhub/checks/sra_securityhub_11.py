"""
SRA-SECURITYHUB-11: Security Hub check.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityhub.base import SecurityHubCheck


class SRA_SECURITYHUB_11(SecurityHubCheck):
    """Check if Security Hub member account limit has not been reached."""

    meta = CheckMeta(
        check_id="SRA-SECURITYHUB-11",
        title="Security Hub member account limit not reached",
        description=(
            "This check verifies whether the maximum number of allowed member accounts are already associated "
            "with the delegated administrator account for the AWS Organization."
        ),
        check_logic=(
            "Check evaluates if Security Hub describe-organization-configuration returns \"MemberAccountLimitReached\": false. "
            "PASS if MemberAccountLimitReached is false."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.AUDIT,
        service="SecurityHub",
        resource_type="AWS::SecurityHub::Hub",
        remediation=Remediation(
            text=(
                "Request a Security Hub member account limit increase from AWS Support, or "
                "remove inactive member accounts from the delegated administrator account."
            ),
            cli=(
                "aws securityhub describe-organization-configuration --region <region>\n"
                "aws securityhub disassociate-members --account-ids <account-id> "
                "--region <region>"
            ),
            console=(
                "Service Quotas console, AWS Security Hub, request a quota increase; or "
                "Security Hub console, Settings, Accounts, remove inactive accounts."
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
            # Get organization configuration in this specific region
            org_config = self.get_organization_configuration(region)

            resource_id = f"securityhub:member-quota/{self.account_id}"

            if "Error" in org_config:
                error = org_config['Error']
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=resource_id,
                        checked_value="Security Hub has not hit member account limit",
                        actual_value=f"Security Hub is not enabled in region {region}, so no member account limit applies",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=resource_id,
                        checked_value="Security Hub has not hit member account limit",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            # Check if MemberAccountLimitReached is false
            limit_reached = org_config.get('MemberAccountLimitReached', True)

            if limit_reached:
                yield self.failed(
                    region=region,
                    resource_id=resource_id,
                    checked_value="Security Hub has not hit member account limit",
                    actual_value=f"Security Hub has hit member account limit in region {region}",
                    remediation=(
                        f"Contact AWS Support to request an increase in the Security Hub member account limit for region {region}. "
                        f"Alternatively, review your Security Hub member accounts and consider removing inactive or unnecessary accounts."
                    ),
                )
            else:
                yield self.passed(
                    region=region,
                    resource_id=resource_id,
                    checked_value="Security Hub has not hit member account limit",
                    actual_value=f"Security Hub has not hit member account limit in region {region}",
                )
