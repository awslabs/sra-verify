from typing import Dict, List, Any
from sraverify.services.waf.base import WAFCheck

class SRA_WAF_01(WAFCheck):
    def __init__(self):
        super().__init__()
        self.resource_type = "AWS::CloudFront::Distribution"
        self.check_id = "SRA-WAF-01"
        self.check_name = "CloudFront distributions should be associated with AWS WAF"
        self.description = "Ensures that all CloudFront distributions are protected by AWS WAF web ACLs to filter malicious traffic"
        self.severity = "HIGH"
        self.check_logic = "Lists all CloudFront distributions and verifies each has a WebACLId configured"

    def execute(self) -> List[Dict[str, Any]]:
        region = "us-east-1"  # CloudFront is global service

        distributions_response = self.get_distributions()

        if "Error" in distributions_response:
            self.findings.append(self.create_finding(
                status="ERROR",
                region=region,
                resource_id=None,
                actual_value=distributions_response["Error"].get("Message", "Unknown error"),
                remediation="Check IAM permissions for CloudFront API access"
            ))
            return self.findings

        distribution_list = distributions_response.get("DistributionList", {})
        distributions = distribution_list.get("Items", [])

        if not distributions:
            self.findings.append(self.create_finding(
                status="PASS",
                region=region,
                resource_id="No distributions",
                actual_value="No CloudFront distributions found",
                remediation="No action needed"
            ))
            return self.findings

        for distribution in distributions:
            distribution_id = distribution.get("Id")
            web_acl_id = distribution.get("WebACLId")

            if web_acl_id:
                self.findings.append(self.create_finding(
                    status="PASS",
                    region=region,
                    resource_id=distribution_id,
                    actual_value=f"WAF Web ACL associated: {web_acl_id}",
                    remediation="No action needed"
                ))
            else:
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id=distribution_id,
                    actual_value="No WAF Web ACL associated",
                    remediation="Associate a WAF Web ACL with this CloudFront distribution using the AWS Console, CLI, or API"
                ))

        return self.findings
