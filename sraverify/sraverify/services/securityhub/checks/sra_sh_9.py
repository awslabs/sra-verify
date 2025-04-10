"""
SRA-SH-9: Security Hub member accounts has enabled status.
"""
from typing import List, Dict, Any
from sraverify.services.securityhub.base import SecurityHubCheck
from sraverify.core.logging import logger


class SRA_SH_9(SecurityHubCheck):
    """Check if Security Hub member accounts have enabled status."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-SH-9"
        self.check_name = "Security Hub member accounts has enabled status"
        self.account_type = "audit"  # This check is for the audit account
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether each Security Hub member account member status enabled. "
            "Indicates that the member account is currently active. For manually invited member accounts "
            "indicates that the member account accepted the invitation."
        )
        self.check_logic = (
            "Check that the status of each Security Hub member for \"MemberStatus\": \"Enabled\". "
            "Check FAIL if any member accounts are not Enabled."
        )
        self.resource_type = "AWS::SecurityHub::Member"
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        # This is a global check, so we'll use a single region but report it as global
        region = self.regions[0] if self.regions else "us-east-1"
        
        # Get all Security Hub members
        sh_members = self.get_security_hub_members(region)
        
        # Check if all members are enabled
        non_enabled_members = [
            member for member in sh_members 
            if member.get('MemberStatus') != 'ENABLED'
        ]
        
        if non_enabled_members:
            # Create a list of non-enabled member account IDs
            non_enabled_account_ids = [member.get('AccountId') for member in non_enabled_members]
            non_enabled_account_ids_str = ', '.join(non_enabled_account_ids)
            
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",  # Report as global
                    account_id=account_id,
                    resource_id=f"securityhub:member/{account_id}",
                    checked_value="All Security Hub members are Enabled",
                    actual_value=f"Security Hub member(s) [{non_enabled_account_ids_str}] is not enabled",
                    remediation=(
                        f"Enable the Security Hub member account(s). If the status is 'INVITED', the account(s) need to accept the invitation. "
                        f"If using AWS Organizations integration, ensure the account(s) are properly configured. "
                        f"You can update the member status using the AWS CLI command: "
                        f"aws securityhub update-organization-configuration --auto-enable --region {region}"
                    )
                )
            )
        else:
            findings.append(
                self.create_finding(
                    status="PASS",
                    region="global",  # Report as global
                    account_id=account_id,
                    resource_id=f"securityhub:member/{account_id}",
                    checked_value="All Security Hub members are Enabled",
                    actual_value=f"All {len(sh_members)} Security Hub member accounts have ENABLED status",
                    remediation="No remediation needed"
                )
            )
        
        return findings
