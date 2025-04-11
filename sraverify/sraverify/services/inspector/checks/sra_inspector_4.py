"""
SRA-INSPECTOR-4: Inspector Lambda Function and Layers Vulnerability Scanning.
"""
from typing import List, Dict, Any
from sraverify.services.inspector.base import InspectorCheck
from sraverify.core.logging import logger


class SRA_INSPECTOR_4(InspectorCheck):
    """Check if Inspector Lambda function and layers vulnerability scanning is enabled for the account."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-INSPECTOR-4"
        self.check_name = "Inspector Lambda function and layers vulnerability scanning is enabled"
        self.account_type = "application"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Inspector Lambda function and layers for package and code vulnerability. "
            "Amazon Inspector monitors each Lambda function throughout its lifetime until it's either deleted or excluded from scanning."
        )
        self.check_logic = (
            "Check runs inspector2 batch-get-account-status. Check PASS if lambda status = ENABLED AND lambdaCode status = ENABLED"
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        account_id = self.get_session_accountId(self.session)
        
        for region in self.regions:
            # Get account status using the base class method with caching
            account_status = self.get_account_status(region)
            
            # Check if Lambda and LambdaCode scanning are enabled
            lambda_status = account_status.get('lambda', {}).get('status')
            lambda_code_status = account_status.get('lambdaCode', {}).get('status')
            
            if not account_status or lambda_status != 'ENABLED' or lambda_code_status != 'ENABLED':
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"inspector2/{account_id}/lambda",
                        checked_value="Inspector Lambda scanning: ENABLED, LambdaCode scanning: ENABLED",
                        actual_value=f"Inspector Lambda scanning: {lambda_status if lambda_status else 'NOT_ENABLED'}, "
                                    f"LambdaCode scanning: {lambda_code_status if lambda_code_status else 'NOT_ENABLED'}",
                        remediation=(
                            "Enable Amazon Inspector Lambda and LambdaCode scanning for your account using the AWS Console or CLI command: "
                            f"aws inspector2 enable --account-ids {account_id} --resource-types LAMBDA LAMBDA_CODE --region {region}"
                        )
                    )
                )
            else:
                self.findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        account_id=account_id,
                        resource_id=f"inspector2/{account_id}/lambda",
                        checked_value="Inspector Lambda scanning: ENABLED, LambdaCode scanning: ENABLED",
                        actual_value=f"Inspector Lambda scanning: {lambda_status}, LambdaCode scanning: {lambda_code_status}",
                        remediation="No remediation needed"
                    )
                )
        
        return self.findings
