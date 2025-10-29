from typing import Dict, List, Any
from sraverify.services.firewallmanager.base import FirewallManagerCheck

class SRA_FIREWALLMANAGER_01(FirewallManagerCheck):
    def __init__(self):
        super().__init__()
        # Override account type for this specific check
        self.account_type = "management"
        self.resource_type = "AWS::FMS::AdminAccount"
        self.check_id = "SRA-FIREWALLMANAGER-01"
        self.check_name = "Firewall Manager delegated administrator is the audit account"
        self.description = "Verifies that AWS Firewall Manager delegated administrator is configured and set to the audit account"
        self.severity = "HIGH"
        self.check_logic = "Calls get_admin_account() to retrieve the Firewall Manager administrator account and verifies it matches the audit account ID"

    def execute(self) -> List[Dict[str, Any]]:
        region = "us-east-1"

        admin_response = self.get_admin_account()

        if "Error" in admin_response:
            self.findings.append(self.create_finding(
                status="ERROR",
                region=region,
                resource_id=None,
                actual_value=admin_response["Error"].get("Message", "Unknown error"),
                remediation="Configure Firewall Manager delegated administrator: https://docs.aws.amazon.com/waf/latest/developerguide/fms-prereq.html"
            ))
            return self.findings

        admin_account = admin_response.get("AdminAccount")
        role_status = admin_response.get("RoleStatus")

        if not admin_account:
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=None,
                actual_value="No Firewall Manager administrator configured",
                remediation="Set up Firewall Manager administrator account: https://docs.aws.amazon.com/waf/latest/developerguide/fms-prereq.html"
            ))
        elif not hasattr(self, '_audit_accounts'):
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=admin_account,
                actual_value=f"Firewall Manager administrator is {admin_account}, but audit account not specified",
                remediation="Run check with --audit-account parameter to verify delegated administrator"
            ))
        elif admin_account not in self._audit_accounts:
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=admin_account,
                actual_value=f"Firewall Manager administrator is {admin_account}, expected one of {self._audit_accounts}",
                remediation=f"Change Firewall Manager administrator to audit account using PutAdminAccount API"
            ))
        elif role_status != "READY":
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=admin_account,
                actual_value=f"Firewall Manager administrator status is {role_status}",
                remediation="Wait for administrator account to reach READY status or reconfigure if in error state"
            ))
        else:
            self.findings.append(self.create_finding(
                status="PASS",
                region=region,
                resource_id=admin_account,
                actual_value=f"Firewall Manager administrator is audit account {admin_account} with status {role_status}",
                remediation="No remediation needed"
            ))

        return self.findings
