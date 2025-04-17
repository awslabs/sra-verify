"""
SRA-MACIE-5: Macie administration for the AWS Organization has a delegated administrator.
"""
from typing import List, Dict, Any
from sraverify.services.macie.base import MacieCheck
from sraverify.core.logging import logger


class SRA_MACIE_5(MacieCheck):
    """Check if Macie administration for the AWS Organization has a delegated administrator."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-MACIE-5"
        self.check_name = "Macie administration for the AWS Organization has a delegated administrator"
        self.description = (
            "This check verifies whether Macie service administration for the AWS Organization is delegated out to AWS Organization management account."
        )
        self.severity = "HIGH"
        self.account_type = "management"
        self.check_logic = "Check validates that a delegated administrator exists for Macie. PASS if macie2 get-administrator-account returns a valid administrator account"
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
            # Get Macie administrator account using the base class method with caching
            admin_account = self.get_macie_administrator_account(region)
            
            # Check if the API call was successful and returned an administrator
            if not admin_account or 'administrator' not in admin_account:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"macie2/{account_id}/{region}",
                        checked_value="Administrator account for Macie",
                        actual_value=f"No administrator account found for Macie in region {region}",
                        remediation=(
                            f"Enable Macie and register a delegated administrator for Macie in region {region} using the AWS CLI command: "
                            f"aws macie2 enable-organization-admin-account --admin-account-id your-audit-account-id --region {region}"
                        )
                    )
                )
                continue
            
            # Check if administrator account exists and is enabled
            admin_account_id = admin_account.get('administrator', {}).get('accountId')
            relation_status = admin_account.get('administrator', {}).get('relationshipStatus')
            
            if admin_account_id and relation_status == 'Enabled':
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        account_id=account_id,
                        resource_id=f"macie2/{account_id}/administrator/{admin_account_id}/{region}",
                        checked_value="Administrator account for Macie",
                        actual_value=f"Macie has an administrator account: {admin_account_id} with status: {relation_status} in region {region}",
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
                        checked_value="Administrator account for Macie",
                        actual_value=f"Administrator account found for Macie in region {region} but status is not Enabled: {relation_status}",
                        remediation=(
                            f"Enable Macie and register a delegated administrator for Macie in region {region} using the AWS CLI command: "
                            f"aws macie2 enable-organization-admin-account --admin-account-id your-audit-account-id --region {region}"
                        )
                    )
                )
        
        return findings
