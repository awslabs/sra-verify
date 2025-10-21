from typing import Dict, List, Any
from sraverify.services.waf.base import WAFCheck

class SRA_WAF_02(WAFCheck):
    def __init__(self):
        super().__init__()
        self.check_id = "SRA-WAF-02"
        self.check_name = "Application Load Balancers should be associated with AWS WAF"
        self.description = "Ensures that all Application Load Balancers are protected by AWS WAF web ACLs to filter malicious traffic"
        self.severity = "HIGH"
        self.check_logic = "Lists all Application Load Balancers and verifies each has a WAF web ACL associated"

    def execute(self) -> List[Dict[str, Any]]:
        for region in self.regions:
            load_balancers_response = self.get_load_balancers(region)

            if "Error" in load_balancers_response:
                self.findings.append(self.create_finding(
                    status="ERROR",
                    region=region,
                    resource_id=None,
                    actual_value=load_balancers_response["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for ELB and WAF API access"
                ))
                continue

            load_balancers = load_balancers_response.get("LoadBalancers", [])
            
            # Filter for Application Load Balancers only
            albs = [lb for lb in load_balancers if lb.get("Type") == "application"]

            if not albs:
                self.findings.append(self.create_finding(
                    status="PASS",
                    region=region,
                    resource_id="No ALBs",
                    actual_value="No Application Load Balancers found",
                    remediation="No action needed"
                ))
                continue

            for alb in albs:
                alb_arn = alb.get("LoadBalancerArn")
                alb_name = alb.get("LoadBalancerName")
                
                client = self.get_client(region)
                if not client:
                    continue

                web_acl_response = client.get_web_acl_for_resource(alb_arn)

                if "Error" in web_acl_response:
                    self.findings.append(self.create_finding(
                        status="ERROR",
                        region=region,
                        resource_id=alb_name,
                        actual_value=web_acl_response["Error"].get("Message", "Unknown error"),
                        remediation="Check IAM permissions for WAF API access"
                    ))
                    continue

                web_acl = web_acl_response.get("WebACL")

                if web_acl:
                    web_acl_name = web_acl.get("Name", "Unknown")
                    self.findings.append(self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=alb_name,
                        actual_value=f"WAF Web ACL associated: {web_acl_name}",
                        remediation="No action needed"
                    ))
                else:
                    self.findings.append(self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=alb_name,
                        actual_value="No WAF Web ACL associated",
                        remediation="Associate a WAF Web ACL with this Application Load Balancer using the AWS Console, CLI, or API"
                    ))

        return self.findings
