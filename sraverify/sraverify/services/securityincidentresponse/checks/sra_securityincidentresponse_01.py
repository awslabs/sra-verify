from typing import Dict, List, Any
from sraverify.services.securityincidentresponse.base import SecurityIncidentResponseCheck

class SRA_SECURITYINCIDENTRESPONSE_01(SecurityIncidentResponseCheck):
    def __init__(self):
        super().__init__()
        self.check_id = "SRA-SECURITYINCIDENTRESPONSE-01"
        self.check_name = "Security Incident Response delegated admin is audit account"
        self.description = "Verifies that the Security Incident Response delegated administrator is configured and is the audit account"
        self.severity = "HIGH"
        self.check_logic = "Lists delegated administrators for security-ir.amazonaws.com and verifies the audit account is designated"

    def execute(self) -> List[Dict[str, Any]]:
        region = self.regions[0] if self.regions else "us-east-1"
        
        # Check if audit accounts are provided
        audit_accounts = getattr(self, '_audit_accounts', None)
        if not audit_accounts:
            self.findings.append(self.create_finding(
                status="ERROR",
                region=region,
                resource_id=None,
                actual_value="No audit accounts specified",
                remediation="Run with --audit-account parameter to specify audit account IDs"
            ))
            return self.findings
        
        response = self.get_delegated_administrators()
        
        if "Error" in response:
            self.findings.append(self.create_finding(
                status="ERROR",
                region=region,
                resource_id=None,
                actual_value=response["Error"].get("Message", "Unknown error"),
                remediation="Check IAM permissions for Organizations API access"
            ))
            return self.findings

        delegated_admins = response.get("DelegatedAdministrators", [])
        
        if not delegated_admins:
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=None,
                actual_value="No delegated administrator configured for Security Incident Response",
                remediation="Configure a delegated administrator for Security Incident Response using: aws organizations register-delegated-administrator --account-id <audit-account-id> --service-principal security-ir.amazonaws.com"
            ))
        else:
            # Check if any of the delegated admins is the audit account
            audit_admin_found = False
            
            for admin in delegated_admins:
                admin_id = admin.get("Id")
                if admin_id in audit_accounts:
                    audit_admin_found = True
                    self.findings.append(self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=admin_id,
                        actual_value=f"Audit account {admin_id} is configured as delegated administrator",
                        remediation="No remediation needed"
                    ))
                    break
            
            if not audit_admin_found:
                admin_ids = [admin.get("Id") for admin in delegated_admins]
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id=None,
                    actual_value=f"Delegated administrators found: {admin_ids}, but none are audit accounts: {audit_accounts}",
                    remediation="Register the audit account as delegated administrator: aws organizations register-delegated-administrator --account-id <audit-account-id> --service-principal security-ir.amazonaws.com"
                ))

        return self.findings
