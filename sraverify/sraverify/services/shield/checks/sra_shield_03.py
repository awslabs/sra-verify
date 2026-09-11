"""
Check if Shield Advanced is configured for CloudFront distributions.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_03(ShieldCheck):
    """Check if Shield Advanced is configured for CloudFront distributions."""

    meta = CheckMeta(
        check_id="SRA-SHIELD-03",
        title="Shield Advanced is configured for CloudFront distributions",
        description=(
            "This check verifies that AWS Shield Advanced is protecting "
            "at least one CloudFront distribution."
        ),
        check_logic=(
            "List Shield protections filtered by CloudFront resource type. "
            "Check fails if no CloudFront distributions are protected."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="Shield",
        resource_type="AWS::Shield::Subscription",
        remediation=Remediation(
            text=(
                "Enable Shield Advanced protection for CloudFront distributions in "
                "the AWS Shield console."
            ),
            cli=(
                "aws shield create-protection --name <protection-name> "
                "--resource-arn arn:aws:cloudfront::<account-id>:distribution/<distribution-id> "
                "--region us-east-1"
            ),
            console=(
                "AWS WAF & Shield console, AWS Shield, Protected resources, "
                "Add resources to protect, select the CloudFront distribution."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding for the CloudFront protection posture.
        """
        # Shield is a global service, check only in us-east-1
        region = "us-east-1"
        protections = self.list_protections(region)

        if "Error" in protections:
            error_code = protections["Error"].get("Code", "")
            if error_code == "ResourceNotFoundException":
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value="Shield Advanced subscription not found",
                    remediation="Enable Shield Advanced subscription to protect resources"
                )
            else:
                yield self.error(
                    region=region,
                    resource_id=None,
                    actual_value=protections["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for Shield API access"
                )
        elif protections.get("Protections"):
            # Filter for CloudFront distributions by checking ResourceArn
            cloudfront_protections = [
                p for p in protections["Protections"]
                if "cloudfront" in p.get("ResourceArn", "").lower()
            ]

            if cloudfront_protections:
                protected_count = len(cloudfront_protections)
                yield self.passed(
                    region=region,
                    resource_id="shield:cloudfront-protections",
                    actual_value=f"{protected_count} CloudFront distribution(s) protected"
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value="No CloudFront distributions protected",
                    remediation="Enable Shield Advanced protection for CloudFront distributions in the AWS Shield console"
                )
        else:
            yield self.failed(
                region=region,
                resource_id=None,
                actual_value="No CloudFront distributions protected",
                remediation="Enable Shield Advanced protection for CloudFront distributions in the AWS Shield console"
            )
