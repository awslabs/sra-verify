from typing import Dict, List, Any
from sraverify.services.waf.base import WAFCheck

class SRA_WAF_05(WAFCheck):
    def __init__(self):
        super().__init__()
        self.resource_type = "AWS::Cognito::UserPool"
        self.check_id = "SRA-WAF-05"
        self.check_name = "Cognito user pools should be associated with AWS WAF"
        self.description = "Ensures that all Cognito user pools are protected by AWS WAF web ACLs to filter malicious traffic"
        self.severity = "HIGH"
        self.check_logic = "Lists all Cognito user pools and verifies each has a WAF web ACL associated"

    def execute(self) -> List[Dict[str, Any]]:
        for region in self.regions:
            user_pools_response = self.get_user_pools(region)

            if "Error" in user_pools_response:
                self.findings.append(self.create_finding(
                    status="ERROR",
                    region=region,
                    resource_id=None,
                    actual_value=user_pools_response["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for Cognito and WAF API access"
                ))
                continue

            user_pools = user_pools_response.get("UserPools", [])

            if not user_pools:
                self.findings.append(self.create_finding(
                    status="PASS",
                    region=region,
                    resource_id="No user pools",
                    actual_value="No Cognito user pools found",
                    remediation="No action needed"
                ))
                continue

            for pool in user_pools:
                pool_id = pool.get("Id")
                pool_name = pool.get("Name")
                
                # Construct the Cognito user pool ARN for WAF association check
                # Format: arn:partition:cognito-idp:region:account-id:userpool/user-pool-id
                pool_arn = f"arn:aws:cognito-idp:{region}:{self.account_id}:userpool/{pool_id}"
                
                client = self.get_client(region)
                if not client:
                    continue

                web_acl_response = client.get_web_acl_for_resource(pool_arn)

                if "Error" in web_acl_response:
                    self.findings.append(self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=pool_name or pool_id,
                        actual_value="No WAF Web ACL associated",
                        remediation="Associate a WAF Web ACL with this Cognito user pool using the AWS Console, CLI, or API"
                    ))
                    continue

                web_acl = web_acl_response.get("WebACL")

                if web_acl:
                    web_acl_name = web_acl.get("Name", "Unknown")
                    self.findings.append(self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=pool_name or pool_id,
                        actual_value=f"WAF Web ACL associated: {web_acl_name}",
                        remediation="No action needed"
                    ))
                else:
                    self.findings.append(self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=pool_name or pool_id,
                        actual_value="No WAF Web ACL associated",
                        remediation="Associate a WAF Web ACL with this Cognito user pool using the AWS Console, CLI, or API"
                    ))

        return self.findings
