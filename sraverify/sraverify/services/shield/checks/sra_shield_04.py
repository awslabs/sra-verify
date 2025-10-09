"""
Check if Shield Advanced is configured for load balancers.
"""
from typing import Dict, List, Any
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_04(ShieldCheck):
    """Check if Shield Advanced is configured for load balancers."""

    def __init__(self):
        """Initialize Shield Advanced load balancer protection check."""
        super().__init__()
        self.check_id = "SRA-SHIELD-04"
        self.check_name = "Shield Advanced is configured for load balancers"
        self.description = ("This check verifies that AWS Shield Advanced is protecting "
                            "at least one load balancer (Application or Classic Load Balancer).")
        self.severity = "HIGH"
        self.check_logic = ("List Shield protections and filter by load balancer ARNs. "
                            "Check fails if no load balancers are protected.")

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
            # Filter for load balancers by checking ResourceArn
            lb_protections = [
                p for p in protections["Protections"]
                if "elasticloadbalancing" in p.get("ResourceArn", "").lower()
            ]

            if lb_protections:
                protected_count = len(lb_protections)
                self.findings.append(self.create_finding(
                    status="PASS",
                    region=region,
                    resource_id="shield:loadbalancer-protections",
                    actual_value=f"{protected_count} load balancer(s) protected",
                    remediation=""
                ))
            else:
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id=None,
                    actual_value="No load balancers protected",
                    remediation="Enable Shield Advanced protection for Application or Classic Load Balancers in the AWS Shield console"
                ))
        else:
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=None,
                actual_value="No load balancers protected",
                remediation="Enable Shield Advanced protection for Application or Classic Load Balancers in the AWS Shield console"
            ))

        return self.findings
