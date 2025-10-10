from typing import Dict, List, Any
from sraverify.services.waf.base import WAFCheck

class SRA_WAF_08(WAFCheck):
    def __init__(self):
        super().__init__()
        self.resource_type = "AWS::Amplify::App"
        self.check_id = "SRA-WAF-08"
        self.check_name = "Amplify applications should be associated with AWS WAF"
        self.description = "Ensures that all Amplify applications are protected by AWS WAF web ACLs to filter malicious traffic"
        self.severity = "HIGH"
        self.check_logic = "Lists all Amplify applications and verifies each has a WAF web ACL associated"

    def execute(self) -> List[Dict[str, Any]]:
        for region in self.regions:
            apps_response = self.get_amplify_apps(region)

            if "Error" in apps_response:
                self.findings.append(self.create_finding(
                    status="ERROR",
                    region=region,
                    resource_id=None,
                    actual_value=apps_response["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for Amplify and WAF API access"
                ))
                continue

            apps = apps_response.get("apps", [])

            if not apps:
                self.findings.append(self.create_finding(
                    status="PASS",
                    region=region,
                    resource_id="No Amplify apps",
                    actual_value="No Amplify applications found",
                    remediation="No action needed"
                ))
                continue

            for app in apps:
                app_id = app.get("appId")
                app_name = app.get("name")
                waf_config = app.get("wafConfiguration", {})
                
                # Check WAF configuration from the app response
                waf_status = waf_config.get("wafStatus")
                web_acl_arn = waf_config.get("webAclArn")
                
                if waf_status == "ENABLED" and web_acl_arn:
                    self.findings.append(self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=app_name or app_id,
                        actual_value=f"WAF Web ACL associated: {web_acl_arn}",
                        remediation="No action needed"
                    ))
                else:
                    self.findings.append(self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=app_name or app_id,
                        actual_value="No WAF Web ACL associated",
                        remediation="Associate a WAF Web ACL with this Amplify application using the AWS Console, CLI, or API"
                    ))

        return self.findings
