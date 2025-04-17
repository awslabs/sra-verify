"""
SRA-INSPECTOR-08: Inspector EC2 Auto-Enable is Configured.
"""
from typing import List, Dict, Any
from sraverify.services.inspector.base import InspectorCheck
from sraverify.core.logging import logger


class SRA_INSPECTOR_08(InspectorCheck):
    """Check if Inspector EC2 auto-enable is configured."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-INSPECTOR-08"
        self.check_name = "Inspector EC2 auto-enable is configured"
        self.account_type = "audit"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Inspector is configured to automatically enable EC2 scanning for new accounts. "
            "Auto-enable ensures that EC2 instances in new accounts added to the organization are automatically scanned."
        )
        self.check_logic = (
            "Check runs inspector2 describe-organization-configuration. Check PASS if autoEnable.ec2=true"
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        account_id = self.get_session_accountId(self.session)
        
        # Check each region separately
        for region in self.regions:
            # Get organization configuration for this region
            org_config = self.get_organization_configuration(region)
            
            # Check if EC2 auto-enable is configured
            ec2_enabled = org_config.get('autoEnable', {}).get('ec2', False)
            
            if not ec2_enabled:
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"inspector2/{region}/organization-configuration/ec2",
                        checked_value="Inspector EC2 auto-enable is configured",
                        actual_value=f"EC2 auto-enable is not configured in {region}",
                        remediation=(
                            "Configure Inspector EC2 auto-enable using the AWS Console or CLI command: "
                            f"aws inspector2 update-organization-configuration --auto-enable ec2=true --region {region}"
                        )
                    )
                )
            else:
                self.findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        account_id=account_id,
                        resource_id=f"inspector2/{region}/organization-configuration/ec2",
                        checked_value="Inspector EC2 auto-enable is configured",
                        actual_value=f"EC2 auto-enable is configured in {region}",
                        remediation="No remediation needed"
                    )
                )
        
        return self.findings
