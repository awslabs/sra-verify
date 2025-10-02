"""
Check if Shield Advanced protected resources have WAF web ACLs associated.
"""
from typing import Dict, List, Any
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_12(ShieldCheck):
    """Check if Shield Advanced protected resources have WAF web ACLs associated."""

    def __init__(self):
        """Initialize Shield Advanced WAF association check."""
        super().__init__()
        self.check_id = "SRA-SHIELD-12"
        self.check_name = "Shield Advanced protected resources have WAF web ACLs associated"
        self.description = ("This check verifies that Shield Advanced protected resources "
                            "that support WAF (CloudFront distributions and Application Load Balancers) "
                            "have web ACLs associated for enhanced application layer protection.")
        self.severity = "HIGH"
        self.check_logic = ("List Shield protections and check WAF web ACL associations "
                            "for CloudFront distributions and Application Load Balancers.")

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
            # Filter for resources that support WAF (CloudFront and ALB)
            waf_eligible_protections = [
                p for p in protections["Protections"]
                if ("cloudfront" in p.get("ResourceArn", "").lower() or
                    "elasticloadbalancing" in p.get("ResourceArn", "").lower())
            ]

            if not waf_eligible_protections:
                self.findings.append(self.create_finding(
                    status="PASS",
                    region=region,
                    resource_id="shield:waf-associations",
                    actual_value="No WAF-eligible protected resources found",
                    remediation=""
                ))
                return self.findings

            # Check each eligible resource for WAF association
            for protection in waf_eligible_protections:
                resource_arn = protection.get("ResourceArn", "")
                protection_name = protection.get("Name", "Unknown")

                # Determine the correct region for the WAF check
                check_region = region
                if "elasticloadbalancing" in resource_arn.lower():
                    # Extract region from ALB ARN: arn:aws:elasticloadbalancing:region:...
                    arn_parts = resource_arn.split(":")
                    if len(arn_parts) >= 4:
                        check_region = arn_parts[3]

                web_acl = self.get_web_acl_for_resource(check_region, resource_arn)

                if "Error" in web_acl:
                    error_code = web_acl["Error"].get("Code", "")
                    if error_code == "WAFNonexistentItemException":
                        self.findings.append(self.create_finding(
                            status="FAIL",
                            region=check_region,
                            resource_id=resource_arn,
                            actual_value="No WAF web ACL associated",
                            remediation="Associate a WAF web ACL with this resource for enhanced application layer protection"
                        ))
                    else:
                        self.findings.append(self.create_finding(
                            status="ERROR",
                            region=check_region,
                            resource_id=resource_arn,
                            actual_value=web_acl["Error"].get("Message", "Unknown error"),
                            remediation="Check IAM permissions for WAF API access"
                        ))
                elif web_acl.get("WebACL"):
                    web_acl_name = web_acl["WebACL"].get("Name", "Unknown")
                    web_acl_id = web_acl["WebACL"].get("Id", "")
                    self.findings.append(self.create_finding(
                        status="PASS",
                        region=check_region,
                        resource_id=resource_arn,
                        actual_value=f"WAF web ACL associated: {web_acl_name} ({web_acl_id})",
                        remediation=""
                    ))
                else:
                    self.findings.append(self.create_finding(
                        status="FAIL",
                        region=check_region,
                        resource_id=resource_arn,
                        actual_value="No WAF web ACL associated",
                        remediation="Associate a WAF web ACL with this resource for enhanced application layer protection"
                    ))
        else:
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=None,
                actual_value="No Shield Advanced protections found",
                remediation="Enable Shield Advanced protection for resources and associate WAF web ACLs"
            ))

        return self.findings
