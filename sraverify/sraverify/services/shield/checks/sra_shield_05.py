"""
Check if Shield Advanced is configured for Elastic IP addresses.
"""
from typing import Dict, List, Any
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_05(ShieldCheck):
    """Check if Shield Advanced is configured for Elastic IP addresses."""

    def __init__(self):
        """Initialize Shield Advanced Elastic IP protection check."""
        super().__init__()
        self.check_id = "SRA-SHIELD-05"
        self.check_name = "Shield Advanced is configured for Elastic IP addresses"
        self.description = ("This check verifies that AWS Shield Advanced is protecting "
                            "at least one Elastic IP address.")
        self.severity = "HIGH"
        self.check_logic = ("List Shield protections and filter by Elastic IP ARNs. "
                            "Check fails if no Elastic IP addresses are protected.")

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
            # Filter for Elastic IPs by checking ResourceArn
            eip_protections = [
                p for p in protections["Protections"]
                if "eip-allocation" in p.get("ResourceArn", "").lower()
            ]

            if eip_protections:
                protected_count = len(eip_protections)
                self.findings.append(self.create_finding(
                    status="PASS",
                    region=region,
                    resource_id="shield:eip-protections",
                    actual_value=f"{protected_count} Elastic IP address(es) protected",
                    remediation=""
                ))
            else:
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id=None,
                    actual_value="No Elastic IP addresses protected",
                    remediation="Enable Shield Advanced protection for Elastic IP addresses in the AWS Shield console"
                ))
        else:
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=None,
                actual_value="No Elastic IP addresses protected",
                remediation="Enable Shield Advanced protection for Elastic IP addresses in the AWS Shield console"
            ))

        return self.findings
