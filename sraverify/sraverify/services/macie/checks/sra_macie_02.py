"""
SRA-MACIE-02: Macie publish classification findings to Security Hub is enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.macie.base import MacieCheck


class SRA_MACIE_02(MacieCheck):
    """Check if Macie publish classification findings to Security Hub is enabled."""

    meta = CheckMeta(
        check_id="SRA-MACIE-02",
        title="Macie publish classification findings to Security Hub is enabled",
        description=(
            "This check verifies whether Macie is configured to publish sensitive data findings to AWS Security Hub. "
            "Sensitive data findings denotes potential sensitive data in as S3 object. Macie continually evaluates your "
            "S3 bucket inventory and uses sampling techniques to identify and select representative S3 objects from your buckets. "
            "Macie then retrieves and analyzes the selected objects, inspecting them for sensitive data."
        ),
        check_logic=(
            "Check validates macie2 get-findings-publication-configuration. "
            "Check PASS if 'publishClassificationFindings': true"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="Macie",
        resource_type="AWS::Macie::Session",
        remediation=Remediation(
            text=(
                "Configure Macie to publish sensitive data (classification) findings to "
                "AWS Security Hub in every enabled Region."
            ),
            cli=(
                "aws macie2 put-findings-publication-configuration "
                "--security-hub-configuration publishClassificationFindings=true "
                "--region <region>"
            ),
            console=(
                "Macie console, Settings, Publish findings to AWS Security Hub, "
                "enable sensitive data findings. Repeat per Region."
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
            # Get findings publication configuration using the base class method with caching
            config = self.get_findings_publication_configuration(region)

            # Test for the error result before reading any success-path key.
            # "Failed to retrieve Macie findings publication configuration" used
            # to be reported as a FAIL for a denied permission, an unreachable
            # endpoint, and a Region where Macie is switched off alike.
            if "Error" in config:
                error = config['Error']
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"macie2/{self.account_id}/{region}",
                        checked_value="publishClassificationFindings: true",
                        actual_value=f"Macie is not enabled in {region}, so no findings are published to Security Hub",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"macie2/{self.account_id}/{region}",
                        checked_value="publishClassificationFindings: true",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            # Check if Security Hub configuration exists
            security_hub_config = config.get('securityHubConfiguration', {})
            if not security_hub_config:
                yield self.failed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="publishClassificationFindings: true",
                    actual_value="Security Hub configuration not found in Macie findings publication configuration",
                    remediation=(
                        f"Configure Macie to publish findings to Security Hub in region {region} using the AWS CLI command: "
                        f"aws macie2 put-findings-publication-configuration --security-hub-configuration publishClassificationFindings=true --region {region}"
                    )
                )
                continue

            # Check if classification findings are published to Security Hub
            publish_classification_findings = security_hub_config.get('publishClassificationFindings', False)

            if publish_classification_findings:
                yield self.passed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="publishClassificationFindings: true",
                    actual_value=f"Macie is configured to publish classification findings to Security Hub in region {region}"
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="publishClassificationFindings: true",
                    actual_value=f"Macie is not configured to publish classification findings to Security Hub in region {region}",
                    remediation=(
                        f"Configure Macie to publish classification findings to Security Hub in region {region} using the AWS CLI command: "
                        f"aws macie2 put-findings-publication-configuration --security-hub-configuration publishClassificationFindings=true --region {region}"
                    )
                )
