"""
SRA-SECURITYHUB-09: Security Hub check.
"""
from typing import List, Dict, Any
from sraverify.services.securityhub.base import SecurityHubCheck
from sraverify.core.logging import logger


class SRA_SECURITYHUB_09(SecurityHubCheck):
    """Check if all Security Hub member accounts have Enabled status."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-SECURITYHUB-09"
        self.check_name = "All Security Hub member accounts have Enabled status"
        self.account_type = "audit"  # This check is for the audit account
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether each Security Hub member account has member status Enabled. "
            "Enabled status indicates that the member account is currently active. For manually invited "
            "member accounts, it indicates that the member account accepted the invitation."
        )
        self.check_logic = (
            "Check runs aws securityhub list-members in each region and verifies that all members have "
            "MemberStatus: Enabled. PASS if all members have Enabled status."
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        
        # Check each region separately
        for region in self.regions:
            # Get Security Hub members
            securityhub_members = self.get_security_hub_members(region)
            
            resource_id = f"securityhub:members/{self.account_id}/{region}"
            
            # Check if there are any members
            if not securityhub_members:
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=resource_id,
                        checked_value="All Security Hub member accounts have Enabled status",
                        actual_value=f"No Security Hub member accounts found in region {region}",
                        remediation="No remediation needed"
                    )
                )
                continue
            
            # Find members that don't have Enabled status
            non_enabled_members = []
            for member in securityhub_members:
                member_id = member.get('AccountId')
                member_status = member.get('MemberStatus')
                
                if member_status != 'Enabled':
                    non_enabled_members.append(f"{member_id} (Status: {member_status})")
            
            if non_enabled_members:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_id,
                        checked_value="All Security Hub member accounts have Enabled status",
                        actual_value=(
                            f"The following Security Hub member accounts do not have Enabled status in region {region}: "
                            f"{', '.join(non_enabled_members)}"
                        ),
                        remediation=(
                            f"Ensure all Security Hub member accounts have Enabled status in region {region}. "
                            f"For manually invited accounts, the member account needs to accept the invitation. "
                            f"For organization-based members, verify the account is properly configured. "
                            f"In the AWS Console, navigate to Security Hub in the audit account, go to Settings > Accounts, "
                            f"and check the status of each member account."
                        )
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=resource_id,
                        checked_value="All Security Hub member accounts have Enabled status",
                        actual_value=f"All {len(securityhub_members)} Security Hub member accounts have Enabled status in region {region}",
                        remediation="No remediation needed"
                    )
                )
        
        return findings
