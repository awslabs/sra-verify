from typing import Dict, List, Any
from sraverify.services.securityincidentresponse.base import SecurityIncidentResponseCheck

class SRA_SECURITYINCIDENTRESPONSE_04(SecurityIncidentResponseCheck):
    def __init__(self):
        super().__init__()
        self.account_type = "audit"
        self.check_id = "SRA-SECURITYINCIDENTRESPONSE-04"
        self.check_name = "Security Incident Response enabled for all organization accounts"
        self.description = "Verifies that all active organization accounts are covered by Security Incident Response"
        self.severity = "HIGH"
        self.check_logic = "Gets all organization accounts and checks if each is associated with Security Incident Response membership"

    def execute(self) -> List[Dict[str, Any]]:
        region = self.regions[0] if self.regions else "us-east-1"
        
        # Get all organization accounts
        org_accounts = self.get_organization_accounts()
        if not org_accounts:
            self.findings.append(self.create_finding(
                status="ERROR",
                region=region,
                resource_id=None,
                actual_value="Unable to retrieve organization accounts",
                remediation="Check IAM permissions for Organizations API access"
            ))
            return self.findings

        # Get active memberships
        memberships_response = self.list_memberships()
        if "Error" in memberships_response:
            self.findings.append(self.create_finding(
                status="ERROR",
                region=region,
                resource_id=None,
                actual_value=memberships_response["Error"].get("Message", "Unknown error"),
                remediation="Check IAM permissions for Security Incident Response API access"
            ))
            return self.findings

        memberships = memberships_response.get("items", [])
        active_memberships = [m for m in memberships if m.get("membershipStatus") == "Active"]
        
        if not active_memberships:
            self.findings.append(self.create_finding(
                status="ERROR",
                region=region,
                resource_id=None,
                actual_value="No active Security Incident Response memberships found",
                remediation="Create and activate a Security Incident Response membership first"
            ))
            return self.findings

        # Use first active membership
        membership_id = active_memberships[0].get("membershipId")
        
        # Get active organization accounts
        active_accounts = [acc for acc in org_accounts if acc.get("Status") == "ACTIVE"]
        account_ids = [acc.get("Id") for acc in active_accounts]
        
        # Process accounts in batches of 100 (API limit)
        batch_size = 100
        for i in range(0, len(account_ids), batch_size):
            batch_account_ids = account_ids[i:i + batch_size]
            
            response = self.batch_get_member_account_details(membership_id, batch_account_ids)
            
            if "Error" in response:
                for account_id in batch_account_ids:
                    self.findings.append(self.create_finding(
                        status="ERROR",
                        region=region,
                        resource_id=account_id,
                        actual_value=response["Error"].get("Message", "Unknown error"),
                        remediation="Check IAM permissions for Security Incident Response BatchGetMemberAccountDetails API access"
                    ))
                continue
            
            # Process results
            items = response.get("items", [])
            errors = response.get("errors", [])
            
            # Handle errors
            for error in errors:
                account_id = error.get("accountId")
                self.findings.append(self.create_finding(
                    status="ERROR",
                    region=region,
                    resource_id=account_id,
                    actual_value=error.get("message", "Unknown error"),
                    remediation="Check account status and Security Incident Response configuration"
                ))
            
            # Check each account's association status
            for item in items:
                account_id = item.get("accountId")
                relationship_status = item.get("relationshipStatus")
                
                if relationship_status == "Associated":
                    self.findings.append(self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=account_id,
                        actual_value=f"Account {account_id} is associated with Security Incident Response",
                        remediation="No remediation needed"
                    ))
                else:
                    self.findings.append(self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=account_id,
                        actual_value=f"Account {account_id} relationship status is {relationship_status}",
                        remediation="Associate the account with Security Incident Response membership through organizational units or direct association"
                    ))

        return self.findings
