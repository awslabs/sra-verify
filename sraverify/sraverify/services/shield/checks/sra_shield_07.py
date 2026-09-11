"""
Check if Shield Advanced is configured for Global Accelerator.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_07(ShieldCheck):
    """Check if Shield Advanced is configured for Global Accelerator."""

    meta = CheckMeta(
        check_id="SRA-SHIELD-07",
        title="Shield Advanced is configured for Global Accelerator",
        description=(
            "This check verifies that AWS Shield Advanced is protecting "
            "at least one Global Accelerator accelerator."
        ),
        check_logic=(
            "List Shield protections and filter by Global Accelerator ARNs. "
            "Check fails if no Global Accelerator accelerators are protected."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="Shield",
        resource_type="AWS::Shield::Subscription",
        remediation=Remediation(
            text=(
                "Enable Shield Advanced protection for Global Accelerator "
                "accelerators in the AWS Shield console."
            ),
            cli=(
                "aws shield create-protection --name <protection-name> "
                "--resource-arn arn:aws:globalaccelerator::<account-id>:accelerator/<accelerator-id> "
                "--region us-east-1"
            ),
            console=(
                "AWS WAF & Shield console, AWS Shield, Protected resources, "
                "Add resources to protect, select the Global Accelerator accelerator."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding for the Global Accelerator protection posture.
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
            # Filter for Global Accelerator by checking ResourceArn
            ga_protections = [
                p for p in protections["Protections"]
                if "globalaccelerator" in p.get("ResourceArn", "").lower()
            ]

            if ga_protections:
                protected_count = len(ga_protections)
                yield self.passed(
                    region=region,
                    resource_id="shield:globalaccelerator-protections",
                    actual_value=f"{protected_count} Global Accelerator accelerator(s) protected"
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value="No Global Accelerator accelerators protected",
                    remediation="Enable Shield Advanced protection for Global Accelerator accelerators in the AWS Shield console"
                )
        else:
            yield self.failed(
                region=region,
                resource_id=None,
                actual_value="No Global Accelerator accelerators protected",
                remediation="Enable Shield Advanced protection for Global Accelerator accelerators in the AWS Shield console"
            )
