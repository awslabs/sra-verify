from typing import Dict, List, Any
from sraverify.services.firewallmanager.base import FirewallManagerCheck

class SRA_FIREWALLMANAGER_10(FirewallManagerCheck):
    def __init__(self):
        super().__init__()
        self.check_id = "SRA-FIREWALLMANAGER-10"
        self.check_name = "Firewall Manager policy cleanup is enabled"
        self.description = "Verifies that AWS Firewall Manager policies have cleanup enabled to remove protections from resources that leave policy scope"
        self.severity = "MEDIUM"
        self.check_logic = "Calls list_policies() per region and checks that policies have DeleteUnusedFMManagedResources set to true"

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
                security_service_type = policy.get("SecurityServiceType", "")
                cleanup_enabled = policy.get("DeleteUnusedFMManagedResources", False)
                
                # Shield Advanced and WAF Classic don't support cleanup
                if security_service_type in ["SHIELD_ADVANCED", "WAF"]:
                    self.findings.append(self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=policy_id,
                        actual_value=f"Policy '{policy_name}' ({security_service_type}) does not support cleanup",
                        remediation="No remediation needed - cleanup not available for this policy type"
                    ))
                elif not cleanup_enabled:
                    self.findings.append(self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=policy_id,
                        actual_value=f"Policy '{policy_name}' has cleanup disabled",
                        remediation=f"Enable cleanup on policy '{policy_name}' to automatically remove protections from out-of-scope resources"
                    ))
                else:
                    self.findings.append(self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=policy_id,
                        actual_value=f"Policy '{policy_name}' has cleanup enabled",
                        remediation="No remediation needed"
                    ))
        
        return self.findings
