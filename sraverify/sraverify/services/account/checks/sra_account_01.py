"""
SRA-ACCOUNT-01: Verify security alternate contact is configured
"""
from typing import Dict, List, Any
from sraverify.services.account.base import AccountCheck


class SRA_ACCOUNT_01(AccountCheck):
    """Check if security alternate contact is configured for the AWS account."""
    
    def __init__(self):
        super().__init__()
        self.check_id = "SRA-ACCOUNT-01"
        self.check_name = "Security alternate contact configured"
        self.description = "Verifies that a security alternate contact is configured for the AWS account"
        self.severity = "MEDIUM"
        self.check_logic = "Uses GetAlternateContact API to verify security contact exists and has required fields"
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the security alternate contact check."""
        account_id = self.account_id
        
        # Account-level check only needs to run once, use first region
        region = self.regions[0] if self.regions else "us-east-1"
        
        contact_info = self.get_alternate_contact(region, "SECURITY")
        
        if "Error" in contact_info:
            error_code = contact_info["Error"].get("Code", "")
            if error_code == "ResourceNotFoundException":
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id=f"account-{account_id}",
                    actual_value="No security alternate contact configured",
                    remediation="Configure a security alternate contact using AWS Console > Account Settings > Alternate contacts or AWS CLI: aws account put-alternate-contact --alternate-contact-type SECURITY --email-address <email> --name <name> --phone-number <phone> --title <title>"
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
                    actual_value=f"Security contact configured: {contact.get('Name')} ({contact.get('EmailAddress')})",
                    remediation="No remediation needed"
                ))
            else:
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id=f"account-{account_id}",
                    actual_value="Security alternate contact exists but missing required fields",
                    remediation="Update security alternate contact to include name and email address using AWS Console > Account Settings > Alternate contacts"
                ))
        
        return self.findings
