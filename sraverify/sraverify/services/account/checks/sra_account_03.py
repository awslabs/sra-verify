"""
SRA-ACCOUNT-03: Verify operations alternate contact is configured
"""
from typing import Dict, List, Any
from sraverify.services.account.base import AccountCheck


class SRA_ACCOUNT_03(AccountCheck):
    """Check if operations alternate contact is configured for the AWS account."""
    
    def __init__(self):
        super().__init__()
        self.check_id = "SRA-ACCOUNT-03"
        self.check_name = "Operations alternate contact configured"
        self.description = "Verifies that an operations alternate contact is configured for the AWS account"
        self.severity = "MEDIUM"
        self.check_logic = "Uses GetAlternateContact API to verify operations contact exists and has required fields"
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the operations alternate contact check."""
        account_id = self.account_id
        region = self.regions[0] if self.regions else "us-east-1"
        
        contact_info = self.get_alternate_contact(region, "OPERATIONS")
        
        if "Error" in contact_info:
            error_code = contact_info["Error"].get("Code", "")
            if error_code == "ResourceNotFoundException":
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id=f"account-{account_id}",
                    actual_value="No operations alternate contact configured",
                    remediation="Configure an operations alternate contact using AWS Console > Account Settings > Alternate contacts or AWS CLI: aws account put-alternate-contact --alternate-contact-type OPERATIONS --email-address <email> --name <name> --phone-number <phone> --title <title>"
                ))
            else:
                self.findings.append(self.create_finding(
                    status="ERROR",
                    region=region,
                    resource_id=f"account-{account_id}",
                    actual_value=contact_info["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for Account Management API access"
                ))
        else:
            contact = contact_info.get("AlternateContact", {})
            if contact and contact.get("EmailAddress") and contact.get("Name"):
                self.findings.append(self.create_finding(
                    status="PASS",
                    region=region,
                    resource_id=f"account-{account_id}",
                    actual_value=f"Operations contact configured: {contact.get('Name')} ({contact.get('EmailAddress')})",
                    remediation="No remediation needed"
                ))
            else:
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id=f"account-{account_id}",
                    actual_value="Operations alternate contact exists but missing required fields",
                    remediation="Update operations alternate contact to include name and email address using AWS Console > Account Settings > Alternate contacts"
                ))
        
        return self.findings
