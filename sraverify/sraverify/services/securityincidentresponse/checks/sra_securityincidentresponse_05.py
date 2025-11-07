from typing import Dict, List, Any
from sraverify.services.securityincidentresponse.base import SecurityIncidentResponseCheck

class SRA_SECURITYINCIDENTRESPONSE_05(SecurityIncidentResponseCheck):
    def __init__(self):
        super().__init__()
        self.account_type = "application"
        self.check_id = "SRA-SECURITYINCIDENTRESPONSE-05"
        self.check_name = "Security Incident Response triage service linked role exists"
        self.description = "Verifies that the AWSServiceRoleForSecurityIncidentResponse_Triage service linked role exists"
        self.severity = "MEDIUM"
        self.check_logic = "Checks if the AWSServiceRoleForSecurityIncidentResponse_Triage IAM role exists in the account"

    def execute(self) -> List[Dict[str, Any]]:
        region = "global"  # IAM is global
        role_name = "AWSServiceRoleForSecurityIncidentResponse_Triage"
        management_account_id = self.get_management_accountId(self.session)
        is_management_account = self.account_id == management_account_id
        
        response = self.get_role(role_name)
        
        if "Error" in response:
            error_code = response["Error"].get("Code")
            if error_code == "NoSuchEntity":
                if is_management_account:
                    remediation = "Security Incident Response cannot automatically create the triage service linked role in the management account. Create it manually using: aws iam create-service-linked-role --aws-service-name triage.security-ir.amazonaws.com"
                else:
                    remediation = "The triage service linked role is created when onboarding to Security Incident Response. If deleted, recreate by onboarding to the service again or manually using: aws iam create-service-linked-role --aws-service-name triage.security-ir.amazonaws.com"
                
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id=f"arn:aws:iam::{self.account_id}:role/{role_name}",
                    actual_value=f"Service linked role {role_name} does not exist",
                    remediation=remediation
                ))
            else:
                self.findings.append(self.create_finding(
                    status="ERROR",
                    region=region,
                    resource_id=f"arn:aws:iam::{self.account_id}:role/{role_name}",
                    actual_value=response["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for GetRole API access"
                ))
        else:
            role_arn = response.get("Role", {}).get("Arn")
            self.findings.append(self.create_finding(
                status="PASS",
                region=region,
                resource_id=role_arn,
                actual_value=f"Service linked role {role_name} exists",
                remediation="No remediation needed"
            ))

        return self.findings
