from typing import Dict, List, Any
from sraverify.services.waf.base import WAFCheck

class SRA_WAF_07(WAFCheck):
    def __init__(self):
        super().__init__()
        self.resource_type = "AWS::EC2::VerifiedAccessInstance"
        self.check_id = "SRA-WAF-07"
        self.check_name = "Verified Access instances should be associated with AWS WAF"
        self.description = "Ensures that all Verified Access instances are protected by AWS WAF web ACLs to filter malicious traffic"
        self.severity = "HIGH"
        self.check_logic = "Lists all Verified Access instances and verifies each has a WAF web ACL associated"

    def execute(self) -> List[Dict[str, Any]]:
        for region in self.regions:
            instances_response = self.get_verified_access_instances(region)

            if "Error" in instances_response:
                self.findings.append(self.create_finding(
                    status="ERROR",
                    region=region,
                    resource_id=None,
                    actual_value=instances_response["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for EC2 and WAF API access"
                ))
                continue

            instances = instances_response.get("VerifiedAccessInstances", [])

            if not instances:
                self.findings.append(self.create_finding(
                    status="PASS",
                    region=region,
                    resource_id="No Verified Access instances",
                    actual_value="No Verified Access instances found",
                    remediation="No action needed"
                ))
                continue

            for instance in instances:
                instance_id = instance.get("VerifiedAccessInstanceId")
                description = instance.get("Description", "")
                
                # Construct the Verified Access instance ARN for WAF association check
                # Format: arn:partition:ec2:region:account-id:verified-access-instance/instance-id
                instance_arn = f"arn:aws:ec2:{region}:{self.account_id}:verified-access-instance/{instance_id}"
                
                client = self.get_client(region)
                if not client:
                    continue

                web_acl_response = client.get_web_acl_for_resource(instance_arn)

                if "Error" in web_acl_response:
                    error_code = web_acl_response["Error"].get("Code")
                    if error_code == "AccessDeniedException":
                        self.findings.append(self.create_finding(
                            status="ERROR",
                            region=region,
                            resource_id=instance_id,
                            actual_value=web_acl_response["Error"].get("Message", "Access denied"),
                            remediation="Check IAM permissions for wafv2:GetWebACLForResource and ec2:GetVerifiedAccessInstanceWebAcl"
                        ))
                    else:
                        self.findings.append(self.create_finding(
                            status="FAIL",
                            region=region,
                            resource_id=instance_id,
                            actual_value="No WAF Web ACL associated",
                            remediation="Associate a WAF Web ACL with this Verified Access instance using the AWS Console, CLI, or API"
                        ))
                    continue

                web_acl = web_acl_response.get("WebACL")

                if web_acl:
                    web_acl_name = web_acl.get("Name", "Unknown")
                    self.findings.append(self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=instance_id,
                        actual_value=f"WAF Web ACL associated: {web_acl_name}",
                        remediation="No action needed"
                    ))
                else:
                    self.findings.append(self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=instance_id,
                        actual_value="No WAF Web ACL associated",
                        remediation="Associate a WAF Web ACL with this Verified Access instance using the AWS Console, CLI, or API"
                    ))

        return self.findings
