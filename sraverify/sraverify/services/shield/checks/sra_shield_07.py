"""
Check if Shield Advanced is configured for Global Accelerator.
"""
from typing import Dict, List, Any
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_07(ShieldCheck):
    """Check if Shield Advanced is configured for Global Accelerator."""

    def __init__(self):
        """Initialize Shield Advanced Global Accelerator protection check."""
        super().__init__()
        self.check_id = "SRA-SHIELD-07"
        self.check_name = "Shield Advanced is configured for Global Accelerator"
        self.description = ("This check verifies that AWS Shield Advanced is protecting "
                            "at least one Global Accelerator accelerator.")
        self.severity = "HIGH"
        self.check_logic = ("List Shield protections and filter by Global Accelerator ARNs. "
                            "Check fails if no Global Accelerator accelerators are protected.")

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
            # Filter for Global Accelerator by checking ResourceArn
            ga_protections = [
                p for p in protections["Protections"]
                if "globalaccelerator" in p.get("ResourceArn", "").lower()
            ]

            if ga_protections:
                protected_count = len(ga_protections)
                self.findings.append(self.create_finding(
                    status="PASS",
                    region=region,
                    resource_id="shield:globalaccelerator-protections",
                    actual_value=f"{protected_count} Global Accelerator accelerator(s) protected",
                    remediation=""
                ))
            else:
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id=None,
                    actual_value="No Global Accelerator accelerators protected",
                    remediation="Enable Shield Advanced protection for Global Accelerator accelerators in the AWS Shield console"
                ))
        else:
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=None,
                actual_value="No Global Accelerator accelerators protected",
                remediation="Enable Shield Advanced protection for Global Accelerator accelerators in the AWS Shield console"
            ))

        return self.findings
