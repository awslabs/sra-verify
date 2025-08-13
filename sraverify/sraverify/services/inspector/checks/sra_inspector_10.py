"""
SRA-INSPECTOR-10: Inspector Lambda Auto-Enable is Configured.
"""
from typing import List, Dict, Any
from sraverify.services.inspector.base import InspectorCheck
from sraverify.core.logging import logger


class SRA_INSPECTOR_10(InspectorCheck):
    """Check if Inspector Lambda auto-enable is configured."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-INSPECTOR-10"
        self.check_name = "Inspector Lambda auto-enable is configured"
        self.account_type = "audit"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Inspector is configured to automatically enable Lambda scanning for new accounts. "
            "Auto-enable ensures that Lambda functions in new accounts added to the organization are automatically scanned."
        )
        self.check_logic = (
            "Check runs inspector2 describe-organization-configuration. Check PASS if autoEnable.lambda=true"
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        
        # Check each region separately
        for region in self.regions:
            # Get organization configuration for this region
            org_config = self.get_organization_configuration(region)
            
            # Check if Lambda auto-enable is configured
            lambda_enabled = org_config.get('autoEnable', {}).get('lambda', False)
            
            if not lambda_enabled:
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=f"inspector2/{region}/organization-configuration/lambda",
                        checked_value="Inspector Lambda auto-enable is configured",
                        actual_value="Lambda auto-enable is not configured",
                        remediation=(
                            "Configure Inspector Lambda auto-enable using the AWS Console or CLI command: "
                            f"aws inspector2 update-organization-configuration --auto-enable lambda=true --region {region}"
                        )
                    )
                )
            else:
                self.findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=f"inspector2/{region}/organization-configuration/lambda",
                        checked_value="Inspector Lambda auto-enable is configured",
                        actual_value="Lambda auto-enable is configured",
                        remediation="No remediation needed"
                    )
                )
        
        return self.findings
