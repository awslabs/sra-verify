"""
Check if CloudFront distributions are associated with AWS WAF.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.waf.base import WAFCheck


class SRA_WAF_01(WAFCheck):
    """Check if CloudFront distributions are associated with AWS WAF."""

    meta = CheckMeta(
        check_id="SRA-WAF-01",
        title="CloudFront distributions should be associated with AWS WAF",
        description=(
            "Ensures that all CloudFront distributions are protected by AWS WAF "
            "web ACLs to filter malicious traffic"
        ),
        check_logic=(
            "Lists all CloudFront distributions and verifies each has a "
            "WebACLId configured"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="WAF",
        resource_type="AWS::CloudFront::Distribution",
        remediation=Remediation(
            text=(
                "Associate a WAF Web ACL with every CloudFront distribution so "
                "that malicious requests are filtered at the edge."
            ),
            cli=(
                "aws wafv2 associate-web-acl "
                "--web-acl-arn arn:aws:wafv2:us-east-1:<account-id>:global/webacl/<name>/<id> "
                "--resource-arn arn:aws:cloudfront::<account-id>:distribution/<distribution-id>"
            ),
            console=(
                "CloudFront console, Distributions, select the distribution, "
                "Security, AWS WAF, Edit, associate a web ACL."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per CloudFront distribution.
        """
        region = "us-east-1"  # CloudFront is global service

        distributions_response = self.get_distributions()

        if "Error" in distributions_response:
            yield self.error(
                region=region,
                resource_id=None,
                actual_value=distributions_response["Error"].get("Message", "Unknown error"),
                remediation="Check IAM permissions for CloudFront API access"
            )
            return

        distribution_list = distributions_response.get("DistributionList", {})
        distributions = distribution_list.get("Items", [])

        if not distributions:
            yield self.passed(
                region=region,
                resource_id="No distributions",
                actual_value="No CloudFront distributions found"
            )
            return

        for distribution in distributions:
            distribution_id = distribution.get("Id")
            web_acl_id = distribution.get("WebACLId")

            if web_acl_id:
                yield self.passed(
                    region=region,
                    resource_id=distribution_id,
                    actual_value=f"WAF Web ACL associated: {web_acl_id}"
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=distribution_id,
                    actual_value="No WAF Web ACL associated",
                    remediation="Associate a WAF Web ACL with this CloudFront distribution using the AWS Console, CLI, or API"
                )
