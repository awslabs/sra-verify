"""
Check if Shield Advanced protected resources have WAF web ACLs associated.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_12(ShieldCheck):
    """Check if Shield Advanced protected resources have WAF web ACLs associated."""

    meta = CheckMeta(
        check_id="SRA-SHIELD-12",
        title="Shield Advanced protected resources have WAF web ACLs associated",
        description=(
            "This check verifies that Shield Advanced protected resources "
            "that support WAF (CloudFront distributions and Application Load Balancers) "
            "have web ACLs associated for enhanced application layer protection."
        ),
        check_logic=(
            "List Shield protections and check WAF web ACL associations "
            "for CloudFront distributions and Application Load Balancers."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="Shield",
        resource_type="AWS::Shield::Subscription",
        remediation=Remediation(
            text=(
                "Associate a WAF web ACL with each WAF-eligible Shield Advanced "
                "protected resource for enhanced application layer protection."
            ),
            cli=(
                "aws wafv2 associate-web-acl --web-acl-arn <web-acl-arn> "
                "--resource-arn <resource-arn> --region <region>"
            ),
            console=(
                "AWS WAF & Shield console, Web ACLs, select the web ACL, "
                "Associated AWS resources, Add AWS resources."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per WAF-eligible Shield Advanced protected resource.
        """
        # Shield is a global service, check only in us-east-1
        region = "us-east-1"
        protections = self.list_protections(region)

        if "Error" in protections:
            error_code = protections["Error"].get("Code", "")
            if error_code == "ResourceNotFoundException":
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
                    actual_value=protections["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for Shield API access"
                )
        elif protections.get("Protections"):
            # Filter for resources that support WAF (CloudFront and ALB)
            waf_eligible_protections = [
                p for p in protections["Protections"]
                if ("cloudfront" in p.get("ResourceArn", "").lower() or
                    "elasticloadbalancing" in p.get("ResourceArn", "").lower())
            ]

            if not waf_eligible_protections:
                yield self.passed(
                    region=region,
                    resource_id="shield:waf-associations",
                    actual_value="No WAF-eligible protected resources found"
                )
                return

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
                        yield self.failed(
                            region=check_region,
                            resource_id=resource_arn,
                            actual_value="No WAF web ACL associated",
                            remediation="Associate a WAF web ACL with this resource for enhanced application layer protection"
                        )
                    else:
                        yield self.error(
                            region=check_region,
                            resource_id=resource_arn,
                            actual_value=web_acl["Error"].get("Message", "Unknown error"),
                            remediation="Check IAM permissions for WAF API access"
                        )
                elif web_acl.get("WebACL"):
                    web_acl_name = web_acl["WebACL"].get("Name", "Unknown")
                    web_acl_id = web_acl["WebACL"].get("Id", "")
                    yield self.passed(
                        region=check_region,
                        resource_id=resource_arn,
                        actual_value=f"WAF web ACL associated: {web_acl_name} ({web_acl_id})"
                    )
                else:
                    yield self.failed(
                        region=check_region,
                        resource_id=resource_arn,
                        actual_value="No WAF web ACL associated",
                        remediation="Associate a WAF web ACL with this resource for enhanced application layer protection"
                    )
        else:
            yield self.failed(
                region=region,
                resource_id=None,
                actual_value="No Shield Advanced protections found",
                remediation="Enable Shield Advanced protection for resources and associate WAF web ACLs"
            )
