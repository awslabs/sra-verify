"""
SRA-MACIE-10: Macie member account limit not reached.
"""
from typing import List, Dict, Any
from sraverify.services.macie.base import MacieCheck
from sraverify.core.logging import logger


class SRA_MACIE_10(MacieCheck):
    """Check if Macie member account limit not reached."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-MACIE-10"
        self.check_name = "Macie member account limit not reached"
        self.description = (
            "This check verifies whether the maximum number of allowed member accounts are already associated with the "
            "delegated administrator account for the AWS Organization."
        )
        self.severity = "MEDIUM"
        self.account_type = "audit"
        self.check_logic = "Check runs macie2 describe-organization-configuration. PASS if maxaccountlimitreached = False"
        self.resource_type = "AWS::Macie::Session"
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        for region in self.regions:
            # Get organization configuration using the base class method with caching
            org_config = self.get_organization_configuration(region)
            
            # Check if the API call was successful
            if not org_config:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"macie2/{account_id}/{region}",
                        checked_value="maxAccountLimitReached: false",
                        actual_value="Failed to retrieve Macie organization configuration",
                        remediation="Ensure Macie is enabled and you have the necessary permissions to call the Macie DescribeOrganizationConfiguration API"
                    )
                )
                continue
            
            # Check if max account limit is reached
            max_account_limit_reached = org_config.get('maxAccountLimitReached', False)
            
            if not max_account_limit_reached:
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        account_id=account_id,
                        resource_id=f"macie2/{account_id}/{region}",
                        checked_value="maxAccountLimitReached: false",
                        actual_value=f"Macie member account limit not reached in region {region}",
                        remediation="No remediation needed"
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"macie2/{account_id}/{region}",
                        checked_value="maxAccountLimitReached: false",
                        actual_value=f"Macie member account limit reached in region {region}",
                        remediation=(
                            "Contact AWS Support to request an increase in the Macie member account limit"
                        )
                    )
                )
        
        return findings
