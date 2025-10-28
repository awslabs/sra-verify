"""
Check if AWS Audit Manager is enabled.
"""
from typing import Dict, List, Any
from sraverify.services.auditmanager.base import AuditManagerCheck


class SRA_AUDITMANAGER_01(AuditManagerCheck):
    """Check if AWS Audit Manager is enabled."""

    def __init__(self):
        """Initialize Audit Manager enabled check."""
        super().__init__()
        self.check_id = "SRA-AUDITMANAGER-01"
        self.check_name = "AWS Audit Manager is enabled"
        self.description = "This check verifies that AWS Audit Manager is enabled in the AWS account. Audit Manager helps you continuously audit your AWS usage to simplify how you assess risk and compliance with regulations and industry standards."
        self.severity = "MEDIUM"
        self.check_logic = "Check account registration status using GetAccountStatus API. Check passes if status is ACTIVE."
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        for region in self.regions:
            status_response = self.get_account_status(region)
            
            if "Error" in status_response:
                self.findings.append(self.create_finding(
                    status="ERROR",
                    region=region,
                    resource_id=None,
                    actual_value=status_response["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for Audit Manager API access"
                ))
            else:
                account_status = status_response.get("status", "UNKNOWN")
                
                if account_status == "ACTIVE":
                    self.findings.append(self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=f"auditmanager:{self.account_id}",
                        actual_value=account_status,
                        remediation=""
                    ))
                else:
                    self.findings.append(self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=None,
                        actual_value=account_status,
                        remediation=f"Enable AWS Audit Manager in {region} by registering the account using the RegisterAccount API or AWS console"
                    ))
        
        return self.findings
