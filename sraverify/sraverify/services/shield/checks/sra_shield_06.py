"""
Check if Shield Advanced is configured for Route 53 hosted zones.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_06(ShieldCheck):
    """Check if Shield Advanced is configured for Route 53 hosted zones."""

    meta = CheckMeta(
        check_id="SRA-SHIELD-06",
        title="Shield Advanced is configured for Route 53 hosted zones",
        description=(
            "This check verifies that AWS Shield Advanced is protecting "
            "at least one Route 53 hosted zone."
        ),
        check_logic=(
            "List Shield protections and filter by Route 53 ARNs. "
            "Check fails if no Route 53 hosted zones are protected."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="Shield",
        resource_type="AWS::Shield::Subscription",
        remediation=Remediation(
            text=(
                "Enable Shield Advanced protection for Route 53 hosted zones in the "
                "AWS Shield console."
            ),
            cli=(
                "aws shield create-protection --name <protection-name> "
                "--resource-arn arn:aws:route53:::hostedzone/<hosted-zone-id> "
                "--region us-east-1"
            ),
            console=(
                "AWS WAF & Shield console, AWS Shield, Protected resources, "
                "Add resources to protect, select the Route 53 hosted zone."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding for the Route 53 protection posture.
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
            # Filter for Route 53 hosted zones by checking ResourceArn
            route53_protections = [
                p for p in protections["Protections"]
                if "route53" in p.get("ResourceArn", "").lower() and "hostedzone" in p.get("ResourceArn", "").lower()
            ]

            if route53_protections:
                protected_count = len(route53_protections)
                yield self.passed(
                    region=region,
                    resource_id="shield:route53-protections",
                    actual_value=f"{protected_count} Route 53 hosted zone(s) protected"
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value="No Route 53 hosted zones protected",
                    remediation="Enable Shield Advanced protection for Route 53 hosted zones in the AWS Shield console"
                )
        else:
            yield self.failed(
                region=region,
                resource_id=None,
                actual_value="No Route 53 hosted zones protected",
                remediation="Enable Shield Advanced protection for Route 53 hosted zones in the AWS Shield console"
            )
