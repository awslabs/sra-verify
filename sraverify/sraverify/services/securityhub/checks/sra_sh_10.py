"""
SRA-SH-10: Security Hub auto-enable is configured.
"""
from typing import List, Dict, Any
from sraverify.services.securityhub.base import SecurityHubCheck
from sraverify.core.logging import logger
from botocore.exceptions import ClientError


class SRA_SH_10(SecurityHubCheck):
    """Check if Security Hub auto-enable is configured for new member accounts."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-SH-10"
        self.check_name = "Security Hub auto-enable is configured"
        self.account_type = "audit"  # Changed from management to audit
        self.severity = "MEDIUM"
        self.description = (
            "This check verifies whether Security Hub is configured to be automatically enabled "
            "for new member accounts when they join the organization."
        )
        self.check_logic = (
            "Check evaluate if Security Hub describe-organization-configuration \"AutoEnable\": true"
        )
    
    def execute(self) -> List[Dict[str, Any]]:
            findings = []
            account_id = self.get_session_accountId(self.session)
            region = self.regions[0] if self.regions else "us-east-1"
            
            try:
                org_config = self.get_organization_configuration(region)
                auto_enable = org_config.get('AutoEnable', False)
                resource_id = f"securityhub:organization-configuration/{account_id}"
                
                if not auto_enable:
                    findings.append(
                        self.create_finding(
                            status="FAIL",
                            region="global",
                            account_id=account_id,
                            resource_id=resource_id,
                            checked_value="AutoEnable: true",
                            actual_value=f"AutoEnable is set to false",
                            remediation=(
                                "Enable auto-enable for new member accounts in Security Hub..."
                            )
                        )
                    )
                else:
                    findings.append(
                        self.create_finding(
                            status="PASS",
                            region="global",
                            account_id=account_id,
                            resource_id=resource_id,
                            checked_value="AutoEnable: true",
                            actual_value=f"AutoEnable is set to true",
                            remediation="No remediation needed"
                        )
                    )
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')
                error_message = e.response.get('Error', {}).get('Message', '')
                
                if error_code == 'InvalidAccessException' and 'not an administrator' in error_message:
                    # Don't log the error, just create a finding
                    findings.append(
                        self.create_finding(
                            status="ERROR",
                            region="global",
                            account_id=account_id,
                            resource_id=f"securityhub:organization-configuration/{account_id}",
                            checked_value="AutoEnable: true",
                            actual_value=f"Cannot check AutoEnable setting: This account is not the Security Hub delegated administrator",
                            remediation="This check must be run from the Security Hub delegated administrator account"
                        )
                    )
            
            return findings
        
        