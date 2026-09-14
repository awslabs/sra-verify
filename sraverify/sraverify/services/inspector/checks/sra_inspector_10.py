"""
SRA-INSPECTOR-10: Inspector Lambda Auto-Enable is Configured.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.inspector.base import InspectorCheck


class SRA_INSPECTOR_10(InspectorCheck):
    """Check if Inspector Lambda auto-enable is configured."""

    meta = CheckMeta(
        check_id="SRA-INSPECTOR-10",
        title="Inspector Lambda auto-enable is configured",
        description=(
            "This check verifies whether Inspector is configured to automatically enable Lambda scanning for new accounts. "
            "Auto-enable ensures that Lambda functions in new accounts added to the organization are automatically scanned."
        ),
        check_logic=(
            "Check runs inspector2 describe-organization-configuration. Check PASS if autoEnable.lambda=true"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.AUDIT,
        service="Inspector",
        resource_type="AWS::Inspector::Assessment",
        remediation=Remediation(
            text=(
                "Turn on Amazon Inspector Lambda auto-enable in the organization "
                "configuration in every enabled Region."
            ),
            cli=(
                "aws inspector2 update-organization-configuration "
                "--auto-enable lambda=true --region <region>"
            ),
            console=(
                "Inspector console in the delegated administrator account, Settings, "
                "Account management, Automatically activate Inspector for new member "
                "accounts, enable AWS Lambda standard scanning."
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

            # Check if Lambda auto-enable is configured
            lambda_enabled = org_config.get('autoEnable', {}).get('lambda', False)

            if not lambda_enabled:
                yield self.failed(
                    region=region,
                    resource_id=f"inspector2/{region}/organization-configuration/lambda",
                    checked_value="Inspector Lambda auto-enable is configured",
                    actual_value="Lambda auto-enable is not configured",
                    remediation=(
                        "Configure Inspector Lambda auto-enable using the AWS Console or CLI command: "
                        f"aws inspector2 update-organization-configuration --auto-enable lambda=true --region {region}"
                    ),
                )
            else:
                yield self.passed(
                    region=region,
                    resource_id=f"inspector2/{region}/organization-configuration/lambda",
                    checked_value="Inspector Lambda auto-enable is configured",
                    actual_value="Lambda auto-enable is configured",
                )
