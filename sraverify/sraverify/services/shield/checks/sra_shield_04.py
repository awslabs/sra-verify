"""
Check if Shield Advanced is configured for load balancers.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_04(ShieldCheck):
    """Check if Shield Advanced is configured for load balancers."""

    meta = CheckMeta(
        check_id="SRA-SHIELD-04",
        title="Shield Advanced is configured for load balancers",
        description=(
            "This check verifies that AWS Shield Advanced is protecting "
            "at least one load balancer (Application or Classic Load Balancer)."
        ),
        check_logic=(
            "List Shield protections and filter by load balancer ARNs. "
            "Check fails if no load balancers are protected."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="Shield",
        resource_type="AWS::Shield::Subscription",
        remediation=Remediation(
            text=(
                "Enable Shield Advanced protection for Application or Classic Load "
                "Balancers in the AWS Shield console."
            ),
            cli=(
                "aws shield create-protection --name <protection-name> "
                "--resource-arn <load-balancer-arn> --region us-east-1"
            ),
            console=(
                "AWS WAF & Shield console, AWS Shield, Protected resources, "
                "Add resources to protect, select the load balancer."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding for the load balancer protection posture.
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
            # Filter for load balancers by checking ResourceArn
            lb_protections = [
                p for p in protections["Protections"]
                if "elasticloadbalancing" in p.get("ResourceArn", "").lower()
            ]

            if lb_protections:
                protected_count = len(lb_protections)
                yield self.passed(
                    region=region,
                    resource_id="shield:loadbalancer-protections",
                    actual_value=f"{protected_count} load balancer(s) protected"
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value="No load balancers protected",
                    remediation="Enable Shield Advanced protection for Application or Classic Load Balancers in the AWS Shield console"
                )
        else:
            yield self.failed(
                region=region,
                resource_id=None,
                actual_value="No load balancers protected",
                remediation="Enable Shield Advanced protection for Application or Classic Load Balancers in the AWS Shield console"
            )
