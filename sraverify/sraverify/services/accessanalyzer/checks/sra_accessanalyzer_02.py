"""
Check if IAM Access Analyzer has a delegated administrator for the organization.
"""
from typing import Dict, List, Any
from sraverify.services.accessanalyzer.base import AccessAnalyzerCheck
from sraverify.core.logging import logger


class SRA_ACCESSANALYZER_02(AccessAnalyzerCheck):
    """Check if IAM Access Analyzer has a delegated administrator for the organization."""
    
    def __init__(self):
        """Initialize IAM Access Analyzer check."""
        super().__init__()
        self.check_id = "SRA-ACCESSANALYZER-02"
        self.check_name = "IAM Access Analyzer Organization Delegated Administrator"
        self.description = ("This check verifies whether IAA service administration for your AWS "
                          "Organization is delegated out of your AWS Organization management account. "
                          "The delegated administrator has permissions to create and manage analyzers "
                          "with the AWS organization as the zone of trust.")
        self.severity = "HIGH"
        self.account_type = "management"  
        self.check_logic = ("Check if a delegated administrator is configured for IAM Access Analyzer in the organization")

    def execute(self) -> List[Dict[str, Any]]:
        """Execute the check."""
        findings = []        
        logger.debug(f"Executing {self.check_id} check for account {self.account_id}")

        # Check for delegated administrator
        try:
            logger.debug("Checking for IAM Access Analyzer delegated administrator")
            org_client = self.session.client('organizations')
            response = org_client.list_delegated_administrators(
                ServicePrincipal='access-analyzer.amazonaws.com'
            )
            
            # Store in class-level cache
            if response['DelegatedAdministrators']:
                delegated_admin = response['DelegatedAdministrators'][0]
                self.__class__._delegated_admin_cache[self.account_id] = delegated_admin
                logger.debug(f"Found delegated administrator: {delegated_admin['Id']}")
                
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region="global",
                        resource_id=delegated_admin['Id'],
                        actual_value=f"IAM Access Analyzer delegated administrator configured: "
                                   f"Account {delegated_admin['Id']}",
                        remediation="No remediation needed"
                    )
                )
            else:
                logger.debug("No delegated administrator found for IAM Access Analyzer")
                self.__class__._delegated_admin_cache[self.account_id] = {}
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region="global",                        
                        resource_id=f"organization/{self.account_id}",
                        actual_value="No delegated administrator configured for IAM Access Analyzer",
                        remediation="Configure a delegated administrator for IAM Access Analyzer using "
                                  "AWS Organizations"
                    )
                )
                
        except Exception as e:
            logger.error(f"Error checking delegated administrator: {e}")
            self.__class__._delegated_admin_cache[self.account_id] = {}
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",                    
                    resource_id=f"organization/{self.account_id}",
                    actual_value=f"Error checking delegated administrator: {str(e)}",
                    remediation="Ensure proper permissions to check delegated administrators "
                              "and that Organizations is enabled"
                )
            )

        return findings
