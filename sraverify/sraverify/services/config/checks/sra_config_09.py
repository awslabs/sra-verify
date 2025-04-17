"""
SRA-CONFIG-09: AWS Config Aggregator.
"""
from typing import List, Dict, Any
from sraverify.services.config.base import ConfigCheck
from sraverify.core.logging import logger


class SRA_CONFIG_09(ConfigCheck):
    """Check if Config administration for the AWS Organization has a delegated administrator."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-CONFIG-09"
        self.check_name = "Config administration for the AWS Organization has a delegated administrator"
        self.account_type = "management"  # This check applies to management account
        self.severity = "MEDIUM"
        self.description = (
            "This check verifies whether Config service administration for your AWS Organization "
            "is delegated out of the AWS Organization management account."
        )
        self.check_logic = (
            "Checks if a delegated administrator exists for the Config service using the "
            "list-delegated-administrators API with service principals config.amazonaws.com "
            "and config-multiaccountsetup.amazonaws.com."
        )
        self.resource_type = "AWS::Organizations::Account"
        # Initialize parameters as an empty dict
        self.params = {}
    
    def initialize(self, session, regions=None, **kwargs):
        """
        Initialize check with AWS session, regions, and parameters.
        
        Args:
            session: AWS session to use for the check
            regions: List of AWS regions to check
            **kwargs: Additional parameters for the check
        """
        super().initialize(session, regions)
        # Store parameters
        self.params = kwargs
        logger.debug(f"Initialized {self.check_id} with parameters: {self.params}")
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        # Get delegated administrators for both Config service principals
        delegated_admins = self.get_delegated_administrators()
        
        if not delegated_admins:
            # No delegated administrator found for either service principal
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    account_id=account_id,
                    resource_id="delegated-admin/none",
                    checked_value="Delegated administrator exists for Config service",
                    actual_value="No delegated administrator found for Config service",
                    remediation=(
                        "Register a delegated administrator for Config using both service principals:\n"
                        "1. aws organizations register-delegated-administrator "
                        "--service-principal config.amazonaws.com "
                        "--account-id <AUDIT_ACCOUNT_ID>\n"
                        "2. aws organizations register-delegated-administrator "
                        "--service-principal config-multiaccountsetup.amazonaws.com "
                        "--account-id <AUDIT_ACCOUNT_ID>"
                    )
                )
            )
            return findings
        
        # Group delegated admins by service principal to check coverage
        service_principals_covered = set()
        admin_accounts = {}
        
        for admin in delegated_admins:
            admin_id = admin.get('Id', 'Unknown')
            admin_name = admin.get('Name', 'Unknown')
            
            # In a real implementation, we would know which service principal this admin is for
            # For now, we'll just track unique admin accounts
            if admin_id not in admin_accounts:
                admin_accounts[admin_id] = {
                    'name': admin_name,
                    'count': 1
                }
            else:
                admin_accounts[admin_id]['count'] += 1
        
        # Check if we have full coverage of service principals
        if len(delegated_admins) >= 2:
            # We have at least one delegated admin for each service principal
            for admin_id, info in admin_accounts.items():
                admin_name = info['name']
                service_count = info['count']
                
                if service_count == 2:
                    # This account is delegated for both service principals
                    findings.append(
                        self.create_finding(
                            status="PASS",
                            region="global",
                            account_id=account_id,
                            resource_id=f"delegated-admin/{admin_id}",
                            checked_value="Delegated administrator exists for Config service",
                            actual_value=f"Config service has delegated administrator set to account {admin_id} ({admin_name}) for both service principals",
                            remediation="No remediation needed"
                        )
                    )
                else:
                    # This account is delegated for only one service principal
                    findings.append(
                        self.create_finding(
                            status="WARN",
                            region="global",
                            account_id=account_id,
                            resource_id=f"delegated-admin/{admin_id}",
                            checked_value="Delegated administrator exists for all Config service principals",
                            actual_value=f"Config service has delegated administrator set to account {admin_id} ({admin_name}) but not for all required service principals",
                            remediation=(
                                f"Ensure the same account is registered as a delegated administrator for both Config service principals:\n"
                                f"1. aws organizations register-delegated-administrator "
                                f"--service-principal config.amazonaws.com "
                                f"--account-id {admin_id}\n"
                                f"2. aws organizations register-delegated-administrator "
                                f"--service-principal config-multiaccountsetup.amazonaws.com "
                                f"--account-id {admin_id}"
                            )
                        )
                    )
        else:
            # We don't have full coverage of service principals
            admin_list = []
            for admin_id, info in admin_accounts.items():
                admin_list.append(f"{admin_id} ({info['name']})")
            
            findings.append(
                self.create_finding(
                    status="WARN",
                    region="global",
                    account_id=account_id,
                    resource_id=f"delegated-admin/{','.join(admin_accounts.keys())}",
                    checked_value="Delegated administrator exists for all Config service principals",
                    actual_value=f"Config service has delegated administrators ({', '.join(admin_list)}) but not for all required service principals",
                    remediation=(
                        "Ensure a delegated administrator is registered for both Config service principals:\n"
                        "1. aws organizations register-delegated-administrator "
                        "--service-principal config.amazonaws.com "
                        "--account-id <AUDIT_ACCOUNT_ID>\n"
                        "2. aws organizations register-delegated-administrator "
                        "--service-principal config-multiaccountsetup.amazonaws.com "
                        "--account-id <AUDIT_ACCOUNT_ID>"
                    )
                )
            )
        
        return findings
