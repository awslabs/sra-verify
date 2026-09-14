"""
SRA-SECURITYHUB-09: Security Hub check.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityhub.base import SecurityHubCheck


class SRA_SECURITYHUB_09(SecurityHubCheck):
    """Check if all Security Hub member accounts have Enabled status."""

    meta = CheckMeta(
        check_id="SRA-SECURITYHUB-09",
        title="All Security Hub member accounts have Enabled status",
        description=(
            "This check verifies whether each Security Hub member account has member status Enabled. "
            "Enabled status indicates that the member account is currently active. For manually invited "
            "member accounts, it indicates that the member account accepted the invitation."
        ),
        check_logic=(
            "Check runs aws securityhub list-members in each region and verifies that all members have "
            "MemberStatus: Enabled. PASS if all members have Enabled status."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.AUDIT,
        service="SecurityHub",
        resource_type="AWS::SecurityHub::Hub",
        remediation=Remediation(
            text=(
                "Bring every Security Hub member account to Enabled status: have "
                "manually invited accounts accept their invitation, and re-enable any "
                "organization member whose status has lapsed."
            ),
            cli=(
                "aws securityhub list-members --region <region>\n"
                "aws securityhub create-members --account-details "
                "'AccountId=<account-id>' --region <region>"
            ),
            console=(
                "Security Hub console in the audit account, Settings, Accounts, review "
                "the status column and re-enable the affected accounts."
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
            # Get Security Hub members
            securityhub_members = self.get_security_hub_members(region)

            resource_id = f"securityhub:members/{self.account_id}/{region}"

            # Check if there are any members
            if not securityhub_members:
                yield self.passed(
                    region=region,
                    resource_id=resource_id,
                    checked_value="All Security Hub member accounts have Enabled status",
                    actual_value=f"No Security Hub member accounts found in region {region}",
                )
                continue

            # Find members that don't have Enabled status
            non_enabled_members = []
            for member in securityhub_members:
                member_id = member.get('AccountId')
                member_status = member.get('MemberStatus')

                if member_status != 'Enabled':
                    non_enabled_members.append(f"{member_id} (Status: {member_status})")

            if non_enabled_members:
                yield self.failed(
                    region=region,
                    resource_id=resource_id,
                    checked_value="All Security Hub member accounts have Enabled status",
                    actual_value=(
                        f"The following Security Hub member accounts do not have Enabled status in region {region}: "
                        f"{', '.join(non_enabled_members)}"
                    ),
                    remediation=(
                        f"Ensure all Security Hub member accounts have Enabled status in region {region}. "
                        f"For manually invited accounts, the member account needs to accept the invitation. "
                        f"For organization-based members, verify the account is properly configured. "
                        f"In the AWS Console, navigate to Security Hub in the audit account, go to Settings > Accounts, "
                        f"and check the status of each member account."
                    ),
                )
            else:
                yield self.passed(
                    region=region,
                    resource_id=resource_id,
                    checked_value="All Security Hub member accounts have Enabled status",
                    actual_value=f"All {len(securityhub_members)} Security Hub member accounts have Enabled status in region {region}",
                )
