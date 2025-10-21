"""
Check if Shield Advanced is configured for CloudFront distributions.
"""
from typing import Dict, List, Any
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_03(ShieldCheck):
    """Check if Shield Advanced is configured for CloudFront distributions."""

    def __init__(self):
        """Initialize Shield Advanced CloudFront protection check."""
        super().__init__()
        self.check_id = "SRA-SHIELD-03"
        self.check_name = "Shield Advanced is configured for CloudFront distributions"
        self.description = ("This check verifies that AWS Shield Advanced is protecting "
                            "at least one CloudFront distribution.")
        self.severity = "HIGH"
        self.check_logic = ("List Shield protections filtered by CloudFront resource type. "
                            "Check fails if no CloudFront distributions are protected.")

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
            # Filter for CloudFront distributions by checking ResourceArn
            cloudfront_protections = [
                p for p in protections["Protections"]
                if "cloudfront" in p.get("ResourceArn", "").lower()
            ]

            if cloudfront_protections:
                protected_count = len(cloudfront_protections)
                self.findings.append(self.create_finding(
                    status="PASS",
                    region=region,
                    resource_id="shield:cloudfront-protections",
                    actual_value=f"{protected_count} CloudFront distribution(s) protected",
                    remediation=""
                ))
            else:
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id=None,
                    actual_value="No CloudFront distributions protected",
                    remediation="Enable Shield Advanced protection for CloudFront distributions in the AWS Shield console"
                ))
        else:
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=None,
                actual_value="No CloudFront distributions protected",
                remediation="Enable Shield Advanced protection for CloudFront distributions in the AWS Shield console"
            ))

        return self.findings
