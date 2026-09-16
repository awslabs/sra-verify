"""
Check if health checks are configured for Shield Advanced protected resources.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_10(ShieldCheck):
    """Check if health checks are configured for Shield Advanced protected resources."""

    meta = CheckMeta(
        check_id="SRA-SHIELD-10",
        title="Health checks are configured for Shield Advanced protected resources",
        description=(
            "This check verifies that Route 53 health checks are associated "
            "with Shield Advanced protected resources to enable health-based detection. "
            "Route 53 hosted zones are excluded as they don't support health-based detection."
        ),
        check_logic=(
            "List Shield protections and check HealthCheckIds field. "
            "Check fails if protected resources (excluding Route 53 hosted zones) lack health checks."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service="Shield",
        resource_type="AWS::Shield::Subscription",
        remediation=Remediation(
            text=(
                "Associate a Route 53 health check with each Shield Advanced protected "
                "resource."
            ),
            cli=(
                "aws shield associate-health-check --protection-id <protection-id> "
                "--health-check-arn arn:aws:route53:::healthcheck/<health-check-id> "
                "--region us-east-1"
            ),
            console=(
                "AWS WAF & Shield console, AWS Shield, Protected resources, select "
                "the resource, Health check, Associate health check."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per eligible Shield Advanced protected resource.
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
            # Filter out Route 53 hosted zones as they don't support health-based detection
            eligible_protections = [
                p for p in protections["Protections"]
                if not ("route53" in p.get("ResourceArn", "").lower() and "hostedzone" in p.get("ResourceArn", "").lower())
            ]

            if not eligible_protections:
                yield self.passed(
                    region=region,
                    resource_id="shield:health-checks",
                    actual_value="No resources requiring health checks found (only Route 53 hosted zones protected)"
                )
                return

            # Create a finding for each eligible protected resource
            for protection in eligible_protections:
                resource_arn = protection.get("ResourceArn", "")
                protection_name = protection.get("Name", "Unknown")
                health_check_ids = protection.get("HealthCheckIds", [])

                if health_check_ids:
                    yield self.passed(
                        region=region,
                        resource_id=resource_arn,
                        actual_value=f"Health check configured: {len(health_check_ids)} health check(s)"
                    )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=resource_arn,
                        actual_value="No health check configured",
                        remediation="Associate a Route 53 health check with this Shield Advanced protected resource"
                    )
        else:
            yield self.failed(
                region=region,
                resource_id=None,
                actual_value="No Shield Advanced protections found",
                remediation="Enable Shield Advanced protection for resources and configure health checks"
            )
