from typing import Dict, List, Any
from sraverify.services.waf.base import WAFCheck

class SRA_WAF_06(WAFCheck):
    def __init__(self):
        super().__init__()
        self.resource_type = "AWS::AppRunner::Service"
        self.check_id = "SRA-WAF-06"
        self.check_name = "App Runner services should be associated with AWS WAF"
        self.description = "Ensures that all App Runner services are protected by AWS WAF web ACLs to filter malicious traffic"
        self.severity = "HIGH"
        self.check_logic = "Lists all App Runner services and verifies each has a WAF web ACL associated"

    def execute(self) -> List[Dict[str, Any]]:
        for region in self.regions:
            services_response = self.get_apprunner_services(region)

            if "Error" in services_response:
                self.findings.append(self.create_finding(
                    status="ERROR",
                    region=region,
                    resource_id=None,
                    actual_value=services_response["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for App Runner and WAF API access"
                ))
                continue

            services = services_response.get("ServiceSummaryList", [])

            if not services:
                self.findings.append(self.create_finding(
                    status="PASS",
                    region=region,
                    resource_id="No App Runner services",
                    actual_value="No App Runner services found",
                    remediation="No action needed"
                ))
                continue

            for service in services:
                service_arn = service.get("ServiceArn")
                service_name = service.get("ServiceName")
                service_id = service.get("ServiceId")
                
                client = self.get_client(region)
                if not client:
                    continue

                web_acl_response = client.get_web_acl_for_resource(service_arn)

                if "Error" in web_acl_response:
                    error_code = web_acl_response["Error"].get("Code")
                    if error_code == "AccessDeniedException":
                        self.findings.append(self.create_finding(
                            status="ERROR",
                            region=region,
                            resource_id=service_name or service_id,
                            actual_value=web_acl_response["Error"].get("Message", "Access denied"),
                            remediation="Check IAM permissions for wafv2:GetWebACLForResource and apprunner:DescribeWebAclForService"
                        ))
                    else:
                        self.findings.append(self.create_finding(
                            status="FAIL",
                            region=region,
                            resource_id=service_name or service_id,
                            actual_value="No WAF Web ACL associated",
                            remediation="Associate a WAF Web ACL with this App Runner service using the AWS Console, CLI, or API"
                        ))
                    continue

                web_acl = web_acl_response.get("WebACL")

                if web_acl:
                    web_acl_name = web_acl.get("Name", "Unknown")
                    self.findings.append(self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=service_name or service_id,
                        actual_value=f"WAF Web ACL associated: {web_acl_name}",
                        remediation="No action needed"
                    ))
                else:
                    self.findings.append(self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=service_name or service_id,
                        actual_value="No WAF Web ACL associated",
                        remediation="Associate a WAF Web ACL with this App Runner service using the AWS Console, CLI, or API"
                    ))

        return self.findings
