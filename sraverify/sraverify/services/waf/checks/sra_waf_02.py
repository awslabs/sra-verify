"""
Check if Application Load Balancers are associated with AWS WAF.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.waf.base import WAFCheck


class SRA_WAF_02(WAFCheck):
    """Check if Application Load Balancers are associated with AWS WAF."""

    meta = CheckMeta(
        check_id="SRA-WAF-02",
        title="Application Load Balancers should be associated with AWS WAF",
        description=(
            "Ensures that all Application Load Balancers are protected by AWS WAF "
            "web ACLs to filter malicious traffic"
        ),
        check_logic=(
            "Lists all Application Load Balancers and verifies each has a WAF "
            "web ACL associated"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="WAF",
        resource_type="AWS::ElasticLoadBalancingV2::LoadBalancer",
        remediation=Remediation(
            text=(
                "Associate a regional WAF Web ACL with every Application Load "
                "Balancer so that malicious requests are filtered before they "
                "reach the target group."
            ),
            cli=(
                "aws wafv2 associate-web-acl "
                "--web-acl-arn arn:aws:wafv2:<region>:<account-id>:regional/webacl/<name>/<id> "
                "--resource-arn <load-balancer-arn> --region <region>"
            ),
            console=(
                "AWS WAF console, Web ACLs, select the web ACL, "
                "Associated AWS resources, Add AWS resources, "
                "select the Application Load Balancer."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Application Load Balancer.
        """
        for region in self.regions:
            load_balancers_response = self.get_load_balancers(region)

            if "Error" in load_balancers_response:
                yield self.error(
                    region=region,
                    resource_id=None,
                    actual_value=load_balancers_response["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for ELB and WAF API access"
                )
                continue

            load_balancers = load_balancers_response.get("LoadBalancers", [])

            # Filter for Application Load Balancers only
            albs = [lb for lb in load_balancers if lb.get("Type") == "application"]

            if not albs:
                yield self.passed(
                    region=region,
                    resource_id="No ALBs",
                    actual_value="No Application Load Balancers found"
                )
                continue

            for alb in albs:
                alb_arn = alb.get("LoadBalancerArn")
                alb_name = alb.get("LoadBalancerName")

                client = self.get_client(region)
                if not client:
                    continue

                web_acl_response = client.get_web_acl_for_resource(alb_arn)

                if "Error" in web_acl_response:
                    yield self.error(
                        region=region,
                        resource_id=alb_name,
                        actual_value=web_acl_response["Error"].get("Message", "Unknown error"),
                        remediation="Check IAM permissions for WAF API access"
                    )
                    continue

                web_acl = web_acl_response.get("WebACL")

                if web_acl:
                    web_acl_name = web_acl.get("Name", "Unknown")
                    yield self.passed(
                        region=region,
                        resource_id=alb_name,
                        actual_value=f"WAF Web ACL associated: {web_acl_name}"
                    )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=alb_name,
                        actual_value="No WAF Web ACL associated",
                        remediation="Associate a WAF Web ACL with this Application Load Balancer using the AWS Console, CLI, or API"
                    )
