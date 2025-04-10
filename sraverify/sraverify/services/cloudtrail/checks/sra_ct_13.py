"""
SRA-CT-13: CloudTrail Delegated Administrator is the Audit Account.
"""
from typing import List, Dict, Any
from sraverify.services.cloudtrail.base import CloudTrailCheck
from sraverify.core.logging import logger


class SRA_CT_13(CloudTrailCheck):
    """Check if CloudTrail delegated administrator is the Audit account."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-CT-13"
        self.check_name = "The audit account is the Delegated Administrator set for CloudTrail"
        self.account_type = "management"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether CloudTrail delegated admin account is the audit account of your AWS organization. "
            "Audit account is dedicated to operating security services, monitoring AWS accounts, and "
            "automating security alerting and response. CloudTrail helps monitor API activities across "
            "all your AWS accounts and regions."
        )
        self.check_logic = (
            "Check if the delegated administrator account matches any of the specified Audit account IDs."
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        # Get delegated administrators for CloudTrail
        # This will use the cache if available or make API calls if needed
        delegated_admins = self.get_delegated_administrators()
        
        if not delegated_admins:
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    account_id=account_id,
                    resource_id=f"organization/{account_id}",
                    checked_value="CloudTrail delegated administrator is an Audit account",
                    actual_value="No delegated administrator configured for CloudTrail",
                    remediation=(
                        "Register an Audit account as delegated administrator for CloudTrail using the AWS CLI command: "
                        "aws organizations register-delegated-administrator "
                        "--account-id AUDIT_ACCOUNT_ID --service-principal cloudtrail.amazonaws.com"
                    )
                )
            )
            return findings
        
        # Check if audit_accounts is provided via _audit_accounts attribute
        audit_accounts = []
        if hasattr(self, '_audit_accounts') and self._audit_accounts:
            audit_accounts = self._audit_accounts
        
        if not audit_accounts:
            findings.append(
                self.create_finding(
                    status="ERROR",
                    region="global",
                    account_id=account_id,
                    resource_id=f"organization/{account_id}",
                    checked_value="CloudTrail delegated administrator is an Audit account",
                    actual_value="Audit Account ID not provided",
                    remediation="Provide the Audit account IDs using --audit-account flag"
                )
            )
            return findings
        
        # Check if any of the delegated administrators is an Audit account
        for admin in delegated_admins:
            admin_id = admin.get('Id', 'Unknown')
            admin_name = admin.get('Name', 'Unknown')
            
            # Create a resource ID that includes the delegated admin and audit account info
            resource_id = f"cloudtrail arn has delegated administrator set to {admin_id}, audit account is {audit_accounts[0]}, {admin_id in audit_accounts}"
            
            if admin_id in audit_accounts:
                # This delegated admin is in the audit accounts list
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region="global",
                        account_id=account_id,
                        resource_id=resource_id,
                        checked_value=f"CloudTrail delegated administrator is an Audit account ({', '.join(audit_accounts)})",
                        actual_value=f"CloudTrail delegated administrator {admin_id} ({admin_name}) is an Audit account",
                        remediation="No remediation needed"
                    )
                )
            else:
                # This delegated admin is not in the audit accounts list
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region="global",
                        account_id=account_id,
                        resource_id=resource_id,
                        checked_value=f"CloudTrail delegated administrator is an Audit account ({', '.join(audit_accounts)})",
                        actual_value=(
                            f"CloudTrail delegated administrator {admin_id} ({admin_name}) "
                            f"is not in the specified Audit accounts ({', '.join(audit_accounts)})"
                        ),
                        remediation=(
                            "Deregister the current delegated administrator and register an Audit account "
                            "as delegated administrator for CloudTrail using the AWS CLI commands: "
                            f"aws organizations deregister-delegated-administrator "
                            f"--account-id {admin_id} --service-principal cloudtrail.amazonaws.com && "
                            "aws organizations register-delegated-administrator "
                            f"--account-id {audit_accounts[0]} --service-principal cloudtrail.amazonaws.com"
                        )
                    )
                )
        
        return findings
