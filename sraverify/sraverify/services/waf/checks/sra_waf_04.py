from typing import Dict, List, Any
from sraverify.services.waf.base import WAFCheck

class SRA_WAF_04(WAFCheck):
    def __init__(self):
        super().__init__()
        self.resource_type = "AWS::AppSync::GraphQLApi"
        self.check_id = "SRA-WAF-04"
        self.check_name = "AppSync GraphQL APIs should be associated with AWS WAF"
        self.description = "Ensures that all AppSync GraphQL APIs are protected by AWS WAF web ACLs to filter malicious traffic"
        self.severity = "HIGH"
        self.check_logic = "Lists all AppSync GraphQL APIs and verifies each has a WAF web ACL associated"

    def execute(self) -> List[Dict[str, Any]]:
        for region in self.regions:
            graphql_apis_response = self.get_graphql_apis(region)

            if "Error" in graphql_apis_response:
                self.findings.append(self.create_finding(
                    status="ERROR",
                    region=region,
                    resource_id=None,
                    actual_value=graphql_apis_response["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for AppSync and WAF API access"
                ))
                continue

            graphql_apis = graphql_apis_response.get("graphqlApis", [])

            if not graphql_apis:
                self.findings.append(self.create_finding(
                    status="PASS",
                    region=region,
                    resource_id="No GraphQL APIs",
                    actual_value="No AppSync GraphQL APIs found",
                    remediation="No action needed"
                ))
                continue

            for api in graphql_apis:
                api_arn = api.get("arn")
                api_name = api.get("name")
                api_id = api.get("apiId")
                
                # Check if WAF is already associated (wafWebAclArn field)
                waf_web_acl_arn = api.get("wafWebAclArn")
                
                if waf_web_acl_arn:
                    self.findings.append(self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=api_name or api_id,
                        actual_value=f"WAF Web ACL associated: {waf_web_acl_arn}",
                        remediation="No action needed"
                    ))
                else:
                    # Double-check using WAF API
                    client = self.get_client(region)
                    if not client:
                        continue

                    web_acl_response = client.get_web_acl_for_resource(api_arn)

                    if "Error" in web_acl_response:
                        self.findings.append(self.create_finding(
                            status="FAIL",
                            region=region,
                            resource_id=api_name or api_id,
                            actual_value="No WAF Web ACL associated",
                            remediation="Associate a WAF Web ACL with this AppSync GraphQL API using the AWS Console, CLI, or API"
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
                            remediation="Associate a WAF Web ACL with this AppSync GraphQL API using the AWS Console, CLI, or API"
                        ))

        return self.findings
