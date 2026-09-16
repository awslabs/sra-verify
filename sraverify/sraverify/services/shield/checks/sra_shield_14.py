"""
Check if Shield Advanced protected resources have automatic application layer DDoS mitigation enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_14(ShieldCheck):
    """Check if Shield Advanced protected resources have automatic application layer DDoS mitigation enabled."""

    meta = CheckMeta(
        check_id="SRA-SHIELD-14",
        title=(
            "Shield Advanced protected resources have automatic application layer "
            "DDoS mitigation enabled"
        ),
        description=(
            "This check verifies that Shield Advanced protected application layer resources "
            "(CloudFront distributions and Application Load Balancers) have automatic "
            "application layer DDoS mitigation enabled with Block action for effective protection."
        ),
        check_logic=(
            "List Shield protections and check ApplicationLayerAutomaticResponseConfiguration "
            "status and action for application layer resources."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="Shield",
        resource_type="AWS::Shield::Subscription",
        remediation=Remediation(
            text=(
                "Enable automatic application layer DDoS mitigation with the Block "
                "action for every protected CloudFront distribution and Application "
                "Load Balancer."
            ),
            cli=(
                "aws shield enable-application-layer-automatic-response "
                "--resource-arn <resource-arn> --action Block={} --region us-east-1"
            ),
            console=(
                "AWS WAF & Shield console, AWS Shield, Protected resources, select "
                "the resource, Automatic application layer DDoS mitigation, Edit, "
                "Enable and choose Block."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per application layer Shield Advanced protected resource.
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
            # Filter for application layer resources (CloudFront and ALB)
            app_layer_protections = [
                p for p in protections["Protections"]
                if ("cloudfront" in p.get("ResourceArn", "").lower() or
                    "elasticloadbalancing" in p.get("ResourceArn", "").lower())
            ]

            if not app_layer_protections:
                yield self.passed(
                    region=region,
                    resource_id="shield:automatic-mitigation",
                    actual_value="No application layer protected resources found"
                )
                return

            # Check each application layer resource for automatic mitigation
            for protection in app_layer_protections:
                resource_arn = protection.get("ResourceArn", "")

                # Check if ApplicationLayerAutomaticResponseConfiguration exists in the protection
                auto_response_config = protection.get("ApplicationLayerAutomaticResponseConfiguration")

                if auto_response_config and auto_response_config.get("Status") == "ENABLED":
                    if "Block" in auto_response_config.get("Action", {}):
                        yield self.passed(
                            region=region,
                            resource_id=resource_arn,
                            actual_value="Automatic mitigation enabled with Block action"
                        )
                    else:
                        yield self.failed(
                            region=region,
                            resource_id=resource_arn,
                            actual_value="Automatic mitigation enabled but using Count action",
                            remediation="Change automatic mitigation action from Count to Block for effective protection"
                        )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=resource_arn,
                        actual_value="Automatic application layer DDoS mitigation not enabled",
                        remediation="Enable automatic application layer DDoS mitigation with Block action in Shield Advanced console"
                    )
        else:
            yield self.passed(
                region=region,
                resource_id=None,
                actual_value="No Shield Advanced protections found"
            )
