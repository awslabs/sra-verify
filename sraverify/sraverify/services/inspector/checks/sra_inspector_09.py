"""
SRA-INSPECTOR-09: Inspector ECR Auto-Enable is Configured.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.inspector.base import InspectorCheck


class SRA_INSPECTOR_09(InspectorCheck):
    """Check if Inspector ECR auto-enable is configured."""

    meta = CheckMeta(
        check_id="SRA-INSPECTOR-09",
        title="Inspector ECR auto-enable is configured",
        description=(
            "This check verifies whether Inspector is configured to automatically enable ECR scanning for new accounts. "
            "Auto-enable ensures that container images in ECR repositories in new accounts added to the organization are automatically scanned."
        ),
        check_logic=(
            "Check runs inspector2 describe-organization-configuration. Check PASS if autoEnable.ecr=true"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.AUDIT,
        service="Inspector",
        resource_type="AWS::Inspector::Assessment",
        remediation=Remediation(
            text=(
                "Turn on Amazon Inspector ECR auto-enable in the organization "
                "configuration in every enabled Region."
            ),
            cli=(
                "aws inspector2 update-organization-configuration "
                "--auto-enable ecr=true --region <region>"
            ),
            console=(
                "Inspector console in the delegated administrator account, Settings, "
                "Account management, Automatically activate Inspector for new member "
                "accounts, enable Amazon ECR container image scanning."
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

            if "Error" in org_config:
                error = org_config['Error']
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"inspector2/{region}/organization-configuration/ecr",
                        checked_value="Inspector ECR auto-enable is configured",
                        actual_value=f"No Inspector organization configuration exists in {region}",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"inspector2/{region}/organization-configuration/ecr",
                        checked_value="Inspector ECR auto-enable is configured",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            # Check if ECR auto-enable is configured
            ecr_enabled = org_config.get('autoEnable', {}).get('ecr', False)

            if not ecr_enabled:
                yield self.failed(
                    region=region,
                    resource_id=f"inspector2/{region}/organization-configuration/ecr",
                    checked_value="Inspector ECR auto-enable is configured",
                    actual_value="ECR auto-enable is not configured",
                    remediation=(
                        "Configure Inspector ECR auto-enable using the AWS Console or CLI command: "
                        f"aws inspector2 update-organization-configuration --auto-enable ecr=true --region {region}"
                    ),
                )
            else:
                yield self.passed(
                    region=region,
                    resource_id=f"inspector2/{region}/organization-configuration/ecr",
                    checked_value="Inspector ECR auto-enable is configured",
                    actual_value="ECR auto-enable is configured",
                )
