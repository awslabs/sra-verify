"""
Check if health checks are configured for Shield Advanced protected resources.
"""
from typing import Dict, List, Any
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_10(ShieldCheck):
    """Check if health checks are configured for Shield Advanced protected resources."""

    def __init__(self):
        """Initialize Shield Advanced health checks check."""
        super().__init__()
        self.check_id = "SRA-SHIELD-10"
        self.check_name = "Health checks are configured for Shield Advanced protected resources"
        self.description = ("This check verifies that Route 53 health checks are associated "
                            "with Shield Advanced protected resources to enable health-based detection. "
                            "Route 53 hosted zones are excluded as they don't support health-based detection.")
        self.severity = "MEDIUM"
        self.check_logic = ("List Shield protections and check HealthCheckIds field. "
                            "Check fails if protected resources (excluding Route 53 hosted zones) lack health checks.")

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """
        # Shield is a global service, check only in us-east-1
        region = "us-east-1"
        protections = self.list_protections(region)

        if "Error" in protections:
            self.findings.append(self.create_finding(
                status="ERROR",
                region=region,
                resource_id=None,
                actual_value=protections["Error"].get("Message", "Unknown error"),
                remediation="Check IAM permissions for Shield API access"
            ))
        elif protections.get("Protections"):
            # Filter out Route 53 hosted zones as they don't support health-based detection
            eligible_protections = [
                p for p in protections["Protections"]
                if not ("route53" in p.get("ResourceArn", "").lower() and "hostedzone" in p.get("ResourceArn", "").lower())
            ]

            if not eligible_protections:
                self.findings.append(self.create_finding(
                    status="PASS",
                    region=region,
                    resource_id="shield:health-checks",
                    actual_value="No resources requiring health checks found (only Route 53 hosted zones protected)",
                    remediation=""
                ))
                return self.findings

            # Create a finding for each eligible protected resource
            for protection in eligible_protections:
                resource_arn = protection.get("ResourceArn", "")
                protection_name = protection.get("Name", "Unknown")
                health_check_ids = protection.get("HealthCheckIds", [])

                if health_check_ids:
                    self.findings.append(self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=resource_arn,
                        actual_value=f"Health check configured: {len(health_check_ids)} health check(s)",
                        remediation=""
                    ))
                else:
                    self.findings.append(self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_arn,
                        actual_value="No health check configured",
                        remediation="Associate a Route 53 health check with this Shield Advanced protected resource"
                    ))
        else:
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=None,
                actual_value="No Shield Advanced protections found",
                remediation="Enable Shield Advanced protection for resources and configure health checks"
            ))

        return self.findings
