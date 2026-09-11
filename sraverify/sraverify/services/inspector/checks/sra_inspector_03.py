"""
SRA-INSPECTOR-03: Inspector ECR Image Vulnerability Scanning.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.inspector.base import InspectorCheck


class SRA_INSPECTOR_03(InspectorCheck):
    """Check if Inspector ECR image vulnerability scanning is enabled for the account."""

    meta = CheckMeta(
        check_id="SRA-INSPECTOR-03",
        title="Inspector ECR image vulnerability scanning is enabled",
        description=(
            "This check verifies whether Inspector ECR image vulnerability scanning feature is enabled. "
            "Amazon Inspector scans container images stored in Amazon ECR for software vulnerabilities to generate findings."
        ),
        check_logic=(
            "Check runs inspector2 batch-get-account-status. Check PASS if ecr status = ENABLED"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="Inspector",
        resource_type="AWS::Inspector::Assessment",
        remediation=Remediation(
            text=(
                "Enable the Amazon Inspector ECR scan type for the account in every "
                "enabled Region."
            ),
            cli=(
                "aws inspector2 enable --account-ids <account-id> "
                "--resource-types ECR --region <region>"
            ),
            console=(
                "Inspector console, Settings, General settings, Scan types, "
                "enable Amazon ECR container image scanning. Repeat per Region."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Region.
        """

        for region in self.regions:
            # Get account status using the base class method with caching
            account_status = self.get_account_status(region)

            # Check if ECR scanning is enabled
            ecr_status = account_status.get('ecr', {}).get('status')

            if not account_status or ecr_status != 'ENABLED':
                yield self.failed(
                    region=region,
                    resource_id=f"inspector2/{self.account_id}/ecr",
                    checked_value="Inspector ECR scanning: ENABLED",
                    actual_value=f"Inspector ECR scanning: {ecr_status if ecr_status else 'NOT_ENABLED'}",
                    remediation=(
                        "Enable Amazon Inspector ECR scanning for your account using the AWS Console or CLI command: "
                        f"aws inspector2 enable --account-ids {self.account_id} --resource-types ECR --region {region}"
                    ),
                )
            else:
                yield self.passed(
                    region=region,
                    resource_id=f"inspector2/{self.account_id}/ecr",
                    checked_value="Inspector ECR scanning: ENABLED",
                    actual_value=f"Inspector ECR scanning: {ecr_status}",
                )
