"""
Check if Shield Advanced is configured for Route 53 hosted zones.
"""
from typing import Dict, List, Any
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_06(ShieldCheck):
    """Check if Shield Advanced is configured for Route 53 hosted zones."""

    def __init__(self):
        """Initialize Shield Advanced Route 53 protection check."""
        super().__init__()
        self.check_id = "SRA-SHIELD-06"
        self.check_name = "Shield Advanced is configured for Route 53 hosted zones"
        self.description = ("This check verifies that AWS Shield Advanced is protecting "
                            "at least one Route 53 hosted zone.")
        self.severity = "HIGH"
        self.check_logic = ("List Shield protections and filter by Route 53 ARNs. "
                            "Check fails if no Route 53 hosted zones are protected.")

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
            error_code = protections["Error"].get("Code", "")
            if error_code == "ResourceNotFoundException":
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id=None,
                    actual_value="Shield Advanced subscription not found",
                    remediation="Enable Shield Advanced subscription to protect resources"
                ))
            else:
                self.findings.append(self.create_finding(
                    status="ERROR",
                    region=region,
                    resource_id=None,
                    actual_value=protections["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for Shield API access"
                ))
        elif protections.get("Protections"):
            # Filter for Route 53 hosted zones by checking ResourceArn
            route53_protections = [
                p for p in protections["Protections"]
                if "route53" in p.get("ResourceArn", "").lower() and "hostedzone" in p.get("ResourceArn", "").lower()
            ]

            if route53_protections:
                protected_count = len(route53_protections)
                self.findings.append(self.create_finding(
                    status="PASS",
                    region=region,
                    resource_id="shield:route53-protections",
                    actual_value=f"{protected_count} Route 53 hosted zone(s) protected",
                    remediation=""
                ))
            else:
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id=None,
                    actual_value="No Route 53 hosted zones protected",
                    remediation="Enable Shield Advanced protection for Route 53 hosted zones in the AWS Shield console"
                ))
        else:
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=None,
                actual_value="No Route 53 hosted zones protected",
                remediation="Enable Shield Advanced protection for Route 53 hosted zones in the AWS Shield console"
            ))

        return self.findings
