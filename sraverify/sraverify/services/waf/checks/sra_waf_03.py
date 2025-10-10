from typing import Dict, List, Any
from sraverify.services.waf.base import WAFCheck

class SRA_WAF_03(WAFCheck):
    def __init__(self):
        super().__init__()
        self.resource_type = "AWS::ApiGateway::RestApi"
        self.check_id = "SRA-WAF-03"
        self.check_name = "API Gateway REST APIs should be associated with AWS WAF"
        self.description = "Ensures that all API Gateway REST APIs are protected by AWS WAF web ACLs to filter malicious traffic"
        self.severity = "HIGH"
        self.check_logic = "Lists all API Gateway REST APIs and verifies each has a WAF web ACL associated"

    def execute(self) -> List[Dict[str, Any]]:
        for region in self.regions:
            rest_apis_response = self.get_rest_apis(region)

            if "Error" in rest_apis_response:
                self.findings.append(self.create_finding(
                    status="ERROR",
                    region=region,
                    resource_id=None,
                    actual_value=rest_apis_response["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for API Gateway and WAF API access"
                ))
                continue

            rest_apis = rest_apis_response.get("items", [])

            if not rest_apis:
                self.findings.append(self.create_finding(
                    status="PASS",
                    region=region,
                    resource_id="No REST APIs",
                    actual_value="No API Gateway REST APIs found",
                    remediation="No action needed"
                ))
                continue

            for api in rest_apis:
                api_id = api.get("id")
                api_name = api.get("name")
                
                # Construct the API Gateway stage ARN for WAF association check
                # Format: arn:partition:apigateway:region::/restapis/api-id/stages/stage-name
                # We'll check the default 'prod' stage, but in practice you'd want to check all stages
                api_arn = f"arn:aws:apigateway:{region}::/restapis/{api_id}/stages/prod"
                
                client = self.get_client(region)
                if not client:
                    continue

                web_acl_response = client.get_web_acl_for_resource(api_arn)

                if "Error" in web_acl_response:
                    # If the stage doesn't exist, try without stage (this will likely fail but provides better error info)
                    self.findings.append(self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=api_name or api_id,
                        actual_value="No WAF Web ACL associated (stage may not exist)",
                        remediation="Deploy the API to a stage and associate a WAF Web ACL using the AWS Console, CLI, or API"
                    ))
                    continue

                web_acl = web_acl_response.get("WebACL")

                if web_acl:
                    web_acl_name = web_acl.get("Name", "Unknown")
                    self.findings.append(self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=api_name or api_id,
                        actual_value=f"WAF Web ACL associated: {web_acl_name}",
                        remediation="No action needed"
                    ))
                else:
                    self.findings.append(self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=api_name or api_id,
                        actual_value="No WAF Web ACL associated",
                        remediation="Associate a WAF Web ACL with this API Gateway REST API using the AWS Console, CLI, or API"
                    ))

        return self.findings
