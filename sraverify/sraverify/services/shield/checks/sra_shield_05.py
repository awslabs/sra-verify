"""
Check if Shield Advanced is configured for Elastic IP addresses.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_05(ShieldCheck):
    """Check if Shield Advanced is configured for Elastic IP addresses."""

    meta = CheckMeta(
        check_id="SRA-SHIELD-05",
        title="Shield Advanced is configured for Elastic IP addresses",
        description=(
            "This check verifies that AWS Shield Advanced is protecting "
            "at least one Elastic IP address."
        ),
        check_logic=(
            "List Shield protections and filter by Elastic IP ARNs. "
            "Check fails if no Elastic IP addresses are protected."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="Shield",
        resource_type="AWS::Shield::Subscription",
        remediation=Remediation(
            text=(
                "Enable Shield Advanced protection for Elastic IP addresses in the "
                "AWS Shield console."
            ),
            cli=(
                "aws shield create-protection --name <protection-name> "
                "--resource-arn arn:aws:ec2:<region>:<account-id>:eip-allocation/<allocation-id> "
                "--region us-east-1"
            ),
            console=(
                "AWS WAF & Shield console, AWS Shield, Protected resources, "
                "Add resources to protect, select the Elastic IP address."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding for the Elastic IP protection posture.
        """
        # Shield is a global service, check only in us-east-1
        region = "us-east-1"
        protections = self.list_protections(region)

        if "Error" in protections:
            error = protections["Error"]
            if self.is_not_configured(error):
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
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
        elif protections.get("Protections"):
            # Filter for Elastic IPs by checking ResourceArn
            eip_protections = [
                p for p in protections["Protections"]
                if "eip-allocation" in p.get("ResourceArn", "").lower()
            ]

            if eip_protections:
                protected_count = len(eip_protections)
                yield self.passed(
                    region=region,
                    resource_id="shield:eip-protections",
                    actual_value=f"{protected_count} Elastic IP address(es) protected"
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value="No Elastic IP addresses protected",
                    remediation="Enable Shield Advanced protection for Elastic IP addresses in the AWS Shield console"
                )
        else:
            yield self.failed(
                region=region,
                resource_id=None,
                actual_value="No Elastic IP addresses protected",
                remediation="Enable Shield Advanced protection for Elastic IP addresses in the AWS Shield console"
            )
