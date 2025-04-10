"""
SRA-SH-11: Security Hub member account limit not reached.
"""
from typing import List, Dict, Any
from sraverify.services.securityhub.base import SecurityHubCheck
from sraverify.core.logging import logger
from botocore.exceptions import ClientError


class SRA_SH_11(SecurityHubCheck):
    """Check if Security Hub member account limit is not reached."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-SH-11"
        self.check_name = "Security Hub member account limit not reached"
        self.account_type = "audit"  # Changed from management to audit
        self.severity = "MEDIUM"
        self.description = (
            "This check verifies whether the maximum number of allowed member accounts are already "
            "associated with the delegated administrator account for the AWS Organization."
        )
        self.check_logic = (
            "Check evaluate if Security Hub describe-organization-configuration \"MemberAccountLimitReached\": false. "
            "If Limit = false check will PASS."
        )
    
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
        
        try:
            # Get organization configuration
            org_config = self.get_organization_configuration(region)
            
            # Check if member account limit is reached
            limit_reached = org_config.get('MemberAccountLimitReached', False)
            
            resource_id = f"securityhub:member-quota/{account_id}"
            
            if limit_reached:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region="global",  # Report as global
                        account_id=account_id,
                        resource_id=resource_id,
                        checked_value="Current member count is below quota limit",
                        actual_value=f"Security Hub has hit member account limit \"MemberAccountLimitReached\": true",
                        remediation=(
                            "You have reached the maximum number of member accounts allowed for a Security Hub administrator account. "
                            "Consider requesting a quota increase through the AWS Service Quotas console, or contact AWS Support "
                            "for assistance in increasing your Security Hub member account limit."
                        )
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region="global",  # Report as global
                        account_id=account_id,
                        resource_id=resource_id,
                        checked_value="Current member count is below quota limit",
                        actual_value=f"Security Hub has not hit member account limit \"MemberAccountLimitReached\": false",
                        remediation="No remediation needed"
                    )
                )
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = e.response.get('Error', {}).get('Message', '')
            
            if error_code == 'InvalidAccessException' and 'not an administrator' in error_message:
                findings.append(
                    self.create_finding(
                        status="ERROR",
                        region="global",
                        account_id=account_id,
                        resource_id=f"securityhub:member-quota/{account_id}",
                        checked_value="Current member count is below quota limit",
                        actual_value=f"Cannot check member account limit: This account is not the Security Hub delegated administrator",
                        remediation=(
                            "This check must be run from the Security Hub delegated administrator account (typically the audit account). "
                            "Please run this check from the correct account or ensure this account is properly configured as the "
                            "Security Hub delegated administrator."
                        )
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        status="ERROR",
                        region="global",
                        account_id=account_id,
                        resource_id=f"securityhub:member-quota/{account_id}",
                        checked_value="Current member count is below quota limit",
                        actual_value=f"Error checking member account limit: {error_code} - {error_message}",
                        remediation="Ensure the account has proper permissions to describe Security Hub organization configuration."
                    )
                )
        
        return findings
