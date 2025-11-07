from typing import Dict, List, Any
from sraverify.services.securityincidentresponse.base import SecurityIncidentResponseCheck

class SRA_SECURITYINCIDENTRESPONSE_02(SecurityIncidentResponseCheck):
    def __init__(self):
        super().__init__()
        self.account_type = "audit"
        self.check_id = "SRA-SECURITYINCIDENTRESPONSE-02"
        self.check_name = "Security Incident Response membership active"
        self.description = "Verifies that Security Incident Response membership is active"
        self.severity = "HIGH"
        self.check_logic = "Lists memberships and verifies status is Active"

    def execute(self) -> List[Dict[str, Any]]:
        region = self.regions[0] if self.regions else "us-east-1"
        
        response = self.list_memberships()
        
        if "Error" in response:
            self.findings.append(self.create_finding(
                status="ERROR",
                region=region,
                resource_id=None,
                actual_value=response["Error"].get("Message", "Unknown error"),
                remediation="Check IAM permissions for Security Incident Response API access"
            ))
            return self.findings

        memberships = response.get("items", [])
        
        if not memberships:
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=None,
                actual_value="No Security Incident Response memberships found",
                remediation="Create a Security Incident Response membership through the AWS console or API"
            ))
        else:
            active_found = False
            for membership in memberships:
                membership_id = membership.get("membershipId")
                status = membership.get("membershipStatus")
                
                if status == "Active":
                    active_found = True
                    self.findings.append(self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=membership_id,
                        actual_value=f"Membership {membership_id} is Active",
                        remediation="No remediation needed"
                    ))
                else:
                    self.findings.append(self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=membership_id,
                        actual_value=f"Membership {membership_id} status is {status}",
                        remediation="Activate the Security Incident Response membership through the AWS console"
                    ))
            
            if not active_found:
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id=None,
                    actual_value="No active Security Incident Response memberships found",
                    remediation="Activate an existing membership or create a new active membership"
                ))

        return self.findings
