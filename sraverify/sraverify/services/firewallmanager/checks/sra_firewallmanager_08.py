from typing import Dict, List, Any
from sraverify.services.firewallmanager.base import FirewallManagerCheck

class SRA_FIREWALLMANAGER_08(FirewallManagerCheck):
    def __init__(self):
        super().__init__()
        self.check_id = "SRA-FIREWALLMANAGER-08"
        self.check_name = "Firewall Manager policy remediation is enabled"
        self.description = "Verifies that AWS Firewall Manager policies have remediation enabled to automatically apply to new resources"
        self.severity = "MEDIUM"
        self.check_logic = "Calls list_policies() per region and checks that all policies have RemediationEnabled set to true"

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
            
            if not policies:
                self.findings.append(self.create_finding(
                    status="PASS",
                    region=region,
                    resource_id=None,
                    actual_value="No Firewall Manager policies configured in region",
                    remediation="No remediation needed"
                ))
                continue
            
            for policy in policies:
                policy_id = policy.get("PolicyId", "")
                policy_name = policy.get("PolicyName", "Unknown")
                remediation_enabled = policy.get("RemediationEnabled", False)
                
                if not remediation_enabled:
                    self.findings.append(self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=policy_id,
                        actual_value=f"Policy '{policy_name}' has remediation disabled",
                        remediation=f"Enable remediation on policy '{policy_name}' to automatically apply to new resources"
                    ))
                else:
                    self.findings.append(self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=policy_id,
                        actual_value=f"Policy '{policy_name}' has remediation enabled",
                        remediation="No remediation needed"
                    ))
        
        return self.findings
