"""
SRA-INSPECTOR-08: Inspector EC2 Auto-Enable is Configured.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.inspector.base import InspectorCheck


class SRA_INSPECTOR_08(InspectorCheck):
    """Check if Inspector EC2 auto-enable is configured."""

    meta = CheckMeta(
        check_id="SRA-INSPECTOR-08",
        title="Inspector EC2 auto-enable is configured",
        description=(
            "This check verifies whether Inspector is configured to automatically enable EC2 scanning for new accounts. "
            "Auto-enable ensures that EC2 instances in new accounts added to the organization are automatically scanned."
        ),
        check_logic=(
            "Check runs inspector2 describe-organization-configuration. Check PASS if autoEnable.ec2=true"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.AUDIT,
        service="Inspector",
        resource_type="AWS::Inspector::Assessment",
        remediation=Remediation(
            text=(
                "Turn on Amazon Inspector EC2 auto-enable in the organization "
                "configuration in every enabled Region."
            ),
            cli=(
                "aws inspector2 update-organization-configuration "
                "--auto-enable ec2=true --region <region>"
            ),
            console=(
                "Inspector console in the delegated administrator account, Settings, "
                "Account management, Automatically activate Inspector for new member "
                "accounts, enable Amazon EC2 scanning."
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
            # Get organization configuration for this region
            org_config = self.get_organization_configuration(region)

            # Check if EC2 auto-enable is configured
            ec2_enabled = org_config.get('autoEnable', {}).get('ec2', False)

            if not ec2_enabled:
                yield self.failed(
                    region=region,
                    resource_id=f"inspector2/{region}/organization-configuration/ec2",
                    checked_value="Inspector EC2 auto-enable is configured",
                    actual_value=f"EC2 auto-enable is not configured in {region}",
                    remediation=(
                        "Configure Inspector EC2 auto-enable using the AWS Console or CLI command: "
                        f"aws inspector2 update-organization-configuration --auto-enable ec2=true --region {region}"
                    ),
                )
            else:
                yield self.passed(
                    region=region,
                    resource_id=f"inspector2/{region}/organization-configuration/ec2",
                    checked_value="Inspector EC2 auto-enable is configured",
                    actual_value=f"EC2 auto-enable is configured in {region}",
                )
