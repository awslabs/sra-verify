"""
SRA-MACIE-01: Macie publish policy findings to Security Hub is enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.macie.base import MacieCheck


class SRA_MACIE_01(MacieCheck):
    """Check if Macie publish policy findings to Security Hub is enabled."""

    meta = CheckMeta(
        check_id="SRA-MACIE-01",
        title="Macie publish policy findings to Security Hub is enabled",
        description=(
            "This check verifies whether Macie is configured to publish new and updated policy findings to AWS Security Hub. "
            "Policy findings denotes potential security or privacy issue with a S3 bucket."
        ),
        check_logic=(
            "Check validates macie2 get-findings-publication-configuration. "
            "Check PASS if 'publishPolicyFindings': true"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="Macie",
        resource_type="AWS::Macie::Session",
        remediation=Remediation(
            text=(
                "Configure Macie to publish policy findings to AWS Security Hub in "
                "every enabled Region."
            ),
            cli=(
                "aws macie2 put-findings-publication-configuration "
                "--security-hub-configuration publishPolicyFindings=true "
                "--region <region>"
            ),
            console=(
                "Macie console, Settings, Publish findings to AWS Security Hub, "
                "enable policy findings. Repeat per Region."
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

            # Check if the API call was successful
            if not config:
                yield self.failed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="publishPolicyFindings: true",
                    actual_value="Failed to retrieve Macie findings publication configuration",
                    remediation="Ensure Macie is enabled and you have the necessary permissions to call the Macie GetFindingsPublicationConfiguration API"
                )
                continue

            # Check if Security Hub configuration exists
            security_hub_config = config.get('securityHubConfiguration', {})
            if not security_hub_config:
                yield self.failed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="publishPolicyFindings: true",
                    actual_value="Security Hub configuration not found in Macie findings publication configuration",
                    remediation=(
                        f"Configure Macie to publish findings to Security Hub in region {region} using the AWS CLI command: "
                        f"aws macie2 put-findings-publication-configuration --security-hub-configuration publishPolicyFindings=true --region {region}"
                    )
                )
                continue

            # Check if policy findings are published to Security Hub
            publish_policy_findings = security_hub_config.get('publishPolicyFindings', False)

            if publish_policy_findings:
                yield self.passed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="publishPolicyFindings: true",
                    actual_value=f"Macie is configured to publish policy findings to Security Hub in region {region}"
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="publishPolicyFindings: true",
                    actual_value=f"Macie is not configured to publish policy findings to Security Hub in region {region}",
                    remediation=(
                        f"Configure Macie to publish policy findings to Security Hub in region {region} using the AWS CLI command: "
                        f"aws macie2 put-findings-publication-configuration --security-hub-configuration publishPolicyFindings=true --region {region}"
                    )
                )
