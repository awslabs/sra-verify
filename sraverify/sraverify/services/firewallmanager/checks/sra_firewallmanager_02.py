from typing import Dict, List, Any
from sraverify.services.firewallmanager.base import FirewallManagerCheck

class SRA_FIREWALLMANAGER_02(FirewallManagerCheck):
    def __init__(self):
        super().__init__()
        self.check_id = "SRA-FIREWALLMANAGER-02"
        self.check_name = "Firewall Manager manages security groups"
        self.description = "Verifies that AWS Firewall Manager has security group policies configured in each region"
        self.severity = "MEDIUM"
        self.check_logic = "Calls list_policies() per region and checks for policies with SecurityServiceType of SECURITY_GROUPS_COMMON, SECURITY_GROUPS_CONTENT_AUDIT, or SECURITY_GROUPS_USAGE_AUDIT"

    def execute(self) -> List[Dict[str, Any]]:
        account_id = self.account_id
        
        for region in self.regions:
            policies_response = self.list_policies(region)
            
            if "Error" in policies_response:
                self.findings.append(self.create_finding(
                    status="ERROR",
                    region=region,
                    resource_id=None,
                    actual_value=policies_response["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for Firewall Manager API access"
                ))
                continue
            
            policies = policies_response.get("PolicyList", [])
            sg_policies = [
                p for p in policies 
                if p.get("SecurityServiceType") in [
                    "SECURITY_GROUPS_COMMON",
                    "SECURITY_GROUPS_CONTENT_AUDIT", 
                    "SECURITY_GROUPS_USAGE_AUDIT"
                ]
            ]
            
            if not sg_policies:
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id=None,
                    actual_value="No security group policies configured",
                    remediation="Create Firewall Manager security group policies: https://docs.aws.amazon.com/waf/latest/developerguide/security-group-policies.html"
                ))
            else:
                policy_names = [p.get("PolicyName", "Unknown") for p in sg_policies]
                self.findings.append(self.create_finding(
                    status="PASS",
                    region=region,
                    resource_id=",".join([p.get("PolicyId", "") for p in sg_policies]),
                    actual_value=f"{len(sg_policies)} security group policy(ies) configured: {', '.join(policy_names)}",
                    remediation="No remediation needed"
                ))
        
        return self.findings
