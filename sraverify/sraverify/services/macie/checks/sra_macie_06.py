"""
SRA-MACIE-06: Macie delegated admin account is the Security Tooling (Audit) account.
"""
from typing import List, Dict, Any
from sraverify.services.macie.base import MacieCheck
from sraverify.core.logging import logger


class SRA_MACIE_06(MacieCheck):
    """Check if Macie delegated admin account is the Security Tooling (Audit) account."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-MACIE-06"
        self.check_name = "Macie delegated admin account is the Security Tooling (Audit) account"
        self.description = (
            "This check verifies whether Macie delegated admin account is the audit account of your AWS organization. "
            "audit account is dedicated to operating security services, monitoring AWS accounts, and automating security "
            "alerting and response. Macie provides sensitive data discovery service."
        )
        self.severity = "HIGH"
        self.account_type = "management"
        self.check_logic = "Check validates that the administrator account for Macie is the --audit-account. Check PASS if macie2 get-administrator-account account ID == audit account passed via —audit-account flag"
        self.resource_type = "AWS::Macie::Session"
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        # Check if audit accounts are provided
        audit_accounts = []
        if hasattr(self, '_audit_accounts') and self._audit_accounts:
            audit_accounts = self._audit_accounts
        
        if not audit_accounts:
            for region in self.regions:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"macie2/{account_id}/{region}",
                        checked_value="Administrator account is Audit account",
                        actual_value="Audit Account ID not provided",
                        remediation="Provide the Audit account IDs using --audit-account flag"
                    )
                )
            return findings
        
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
                        checked_value="Administrator account is Audit account",
                        actual_value=f"No administrator account found for Macie in region {region}",
                        remediation=(
                            f"Enable Macie and register the Audit account ({', '.join(audit_accounts)}) as a delegated administrator for Macie in region {region} using the AWS CLI command: "
                            f"aws macie2 enable-organization-admin-account --admin-account-id {audit_accounts[0]} --region {region}"
                        )
                    )
                )
                continue
            
            # Check if administrator account exists and is enabled
            admin_account_id = admin_account.get('administrator', {}).get('accountId')
            relation_status = admin_account.get('administrator', {}).get('relationshipStatus')
            
            if not admin_account_id or relation_status != 'Enabled':
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"macie2/{account_id}/{region}",
                        checked_value="Administrator account is Audit account",
                        actual_value=f"Administrator account found for Macie in region {region} but status is not Enabled: {relation_status}",
                        remediation=(
                            f"Enable Macie and register the Audit account ({', '.join(audit_accounts)}) as a delegated administrator for Macie in region {region} using the AWS CLI command: "
                            f"aws macie2 enable-organization-admin-account --admin-account-id {audit_accounts[0]} --region {region}"
                        )
                    )
                )
                continue
            
            # Check if administrator account is the Audit account
            if admin_account_id in audit_accounts:
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        account_id=account_id,
                        resource_id=f"macie2/{account_id}/administrator/{admin_account_id}/{region}",
                        checked_value="Administrator account is Audit account",
                        actual_value=f"Macie administrator account {admin_account_id} is one of the specified Audit accounts in region {region}",
                        remediation="No remediation needed"
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"macie2/{account_id}/administrator/{admin_account_id}/{region}",
                        checked_value="Administrator account is Audit account",
                        actual_value=f"Macie administrator account {admin_account_id} is not one of the specified Audit accounts ({', '.join(audit_accounts)}) in region {region}",
                        remediation=(
                            f"Disable the current administrator and enable the Audit account ({', '.join(audit_accounts)}) as a delegated administrator for Macie in region {region} using the AWS CLI commands: "
                            f"aws macie2 disable-organization-admin-account --admin-account-id {admin_account_id} --region {region} && "
                            f"aws macie2 enable-organization-admin-account --admin-account-id {audit_accounts[0]} --region {region}"
                        )
                    )
                )
        
        return findings
