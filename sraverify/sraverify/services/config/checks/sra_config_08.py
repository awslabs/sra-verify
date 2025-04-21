"""
SRA-CONFIG-08: AWS Config Aggregator Authorization.
"""
from typing import List, Dict, Any
from sraverify.services.config.base import ConfigCheck
from sraverify.core.logging import logger


class SRA_CONFIG_08(ConfigCheck):
    """Check if Config delegated admin account is the Security Tooling (Audit) account."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-CONFIG-08"
        self.check_name = "Config delegated admin account is the Security Tooling (Audit) account"
        self.account_type = "management"  # This check applies to management account
        self.severity = "MEDIUM"
        self.description = (
            "This check verifies whether Config delegated admin account is the audit account of your "
            "AWS organization. The audit account is dedicated to operating security services, monitoring "
            "AWS accounts, and automating security alerting and response."
        )
        self.check_logic = (
            "Compares the delegated admin account ID with the provided audit account ID."
        )
        self.resource_type = "AWS::Organizations::Account"
        # Initialize audit account attribute
        self._audit_accounts = []
    
    def initialize(self, session, regions=None, **kwargs):
        """
        Initialize check with AWS session, regions, and parameters.
        
        Args:
            session: AWS session to use for the check
            regions: List of AWS regions to check
            **kwargs: Additional parameters for the check
        """
        super().initialize(session, regions)
        
        # Extract audit-account from kwargs
        if 'audit-account' in kwargs:
            # Handle both single value and list
            audit_account = kwargs['audit-account']
            if isinstance(audit_account, list):
                self._audit_accounts = audit_account
            else:
                self._audit_accounts = [audit_account]
            logger.debug(f"Audit account IDs set to: {self._audit_accounts}")
        else:
            logger.debug("No Audit account ID provided in parameters")
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        # Check if Audit account ID is provided
        if not self._audit_accounts:
            findings.append(
                self.create_finding(
                    status="ERROR",
                    region="global",
                    account_id=account_id,
                    resource_id="delegated-admin/none",
                    checked_value="Delegated administrator is audit account",
                    actual_value="No audit account ID provided",
                    remediation="Provide the audit account ID using the --audit-account parameter"
                )
            )
            return findings
        
        # Get delegated administrators for both Config service principals
        delegated_admins = self.get_delegated_administrators()
        
        if not delegated_admins:
            # No delegated administrator found for either service principal
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    account_id=account_id,
                    resource_id=f"delegated-admin/none",
                    checked_value=f"Delegated administrator is audit account {', '.join(self._audit_accounts)}",
                    actual_value=f"No delegated administrator found for Config service",
                    remediation=(
                        f"Register the audit account as a delegated administrator for Config using both service principals:\n"
                        f"1. aws organizations register-delegated-administrator "
                        f"--service-principal config.amazonaws.com "
                        f"--account-id {self._audit_accounts[0]}\n"
                        f"2. aws organizations register-delegated-administrator "
                        f"--service-principal config-multiaccountsetup.amazonaws.com "
                        f"--account-id {self._audit_accounts[0]}"
                    )
                )
            )
            return findings
        
        # Group delegated admins by account ID to check if the same account is used for both service principals
        admin_accounts = {}
        for admin in delegated_admins:
            admin_id = admin.get('Id', 'Unknown')
            admin_name = admin.get('Name', 'Unknown')
            
            if admin_id not in admin_accounts:
                admin_accounts[admin_id] = {
                    'name': admin_name,
                    'count': 1
                }
            else:
                admin_accounts[admin_id]['count'] += 1
        
        # Check if any of the audit accounts is a delegated administrator
        audit_account_found = False
        for audit_account_id in self._audit_accounts:
            if audit_account_id in admin_accounts:
                admin_info = admin_accounts[audit_account_id]
                admin_name = admin_info['name']
                service_count = admin_info['count']
                
                # Check if the audit account is delegated for both service principals
                if service_count == 2:
                    audit_account_found = True
                    findings.append(
                        self.create_finding(
                            status="PASS",
                            region="global",
                            account_id=account_id,
                            resource_id=f"delegated-admin/{audit_account_id}",
                            checked_value=f"Delegated administrator is audit account {audit_account_id}",
                            actual_value=f"Config delegated administrator is the audit account {audit_account_id} ({admin_name}) for both service principals",
                            remediation="No remediation needed"
                        )
                    )
                else:
                    audit_account_found = True
                    findings.append(
                        self.create_finding(
                            status="WARN",
                            region="global",
                            account_id=account_id,
                            resource_id=f"delegated-admin/{audit_account_id}",
                            checked_value=f"Delegated administrator is audit account {audit_account_id} for both service principals",
                            actual_value=f"Config delegated administrator is the audit account {audit_account_id} ({admin_name}) but not for all required service principals",
                            remediation=(
                                f"Ensure the audit account is registered as a delegated administrator for both Config service principals:\n"
                                f"1. aws organizations register-delegated-administrator "
                                f"--service-principal config.amazonaws.com "
                                f"--account-id {audit_account_id}\n"
                                f"2. aws organizations register-delegated-administrator "
                                f"--service-principal config-multiaccountsetup.amazonaws.com "
                                f"--account-id {audit_account_id}"
                            )
                        )
                    )
        
        # If no audit account is a delegated administrator
        if not audit_account_found:
            # List all accounts that are delegated administrators
            other_admins = []
            for admin_id, info in admin_accounts.items():
                other_admins.append(f"{admin_id} ({info['name']})")
            
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    account_id=account_id,
                    resource_id=f"delegated-admin/none",
                    checked_value=f"Delegated administrator is audit account {', '.join(self._audit_accounts)}",
                    actual_value=f"Config delegated administrator(s) {', '.join(other_admins)} are not the audit account {', '.join(self._audit_accounts)}",
                    remediation=(
                        f"1. Deregister the current delegated administrator(s).\n"
                        f"2. Register the audit account as a delegated administrator for both Config service principals:\n"
                        f"   aws organizations register-delegated-administrator "
                        f"--service-principal config.amazonaws.com "
                        f"--account-id {self._audit_accounts[0]}\n"
                        f"   aws organizations register-delegated-administrator "
                        f"--service-principal config-multiaccountsetup.amazonaws.com "
                        f"--account-id {self._audit_accounts[0]}"
                    )
                )
            )
        
        return findings
