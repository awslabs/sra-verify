from typing import Dict, List, Any
from sraverify.services.firewallmanager.base import FirewallManagerCheck

class SRA_FIREWALLMANAGER_04(FirewallManagerCheck):
    def __init__(self):
        super().__init__()
        self.check_id = "SRA-FIREWALLMANAGER-04"
        self.check_name = "Firewall Manager manages Shield Advanced policies"
        self.description = "Verifies that AWS Firewall Manager has Shield Advanced policies configured in each region"
        self.severity = "MEDIUM"
        self.check_logic = "Calls list_policies() per region and checks for policies with SecurityServiceType of SHIELD_ADVANCED"

    def execute(self) -> List[Dict[str, Any]]:
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
            shield_policies = [
                p for p in policies 
                if p.get("SecurityServiceType") == "SHIELD_ADVANCED"
            ]
            
            if not shield_policies:
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id=None,
                    actual_value="No Shield Advanced policies configured",
                    remediation="Create Firewall Manager Shield Advanced policies: https://docs.aws.amazon.com/waf/latest/developerguide/shield-policies.html"
                ))
            else:
                policy_names = [p.get("PolicyName", "Unknown") for p in shield_policies]
                self.findings.append(self.create_finding(
                    status="PASS",
                    region=region,
                    resource_id=",".join([p.get("PolicyId", "") for p in shield_policies]),
                    actual_value=f"{len(shield_policies)} Shield Advanced policy(ies) configured: {', '.join(policy_names)}",
                    remediation="No remediation needed"
                ))
        
        return self.findings
