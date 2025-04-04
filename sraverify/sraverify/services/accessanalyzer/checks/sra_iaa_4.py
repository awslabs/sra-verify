"""
Check if IAM Access Analyzer external access analyzer is configured with Organization zone of trust in every region.
"""
from typing import Dict, List, Any
from sraverify.services.accessanalyzer.base import AccessAnalyzerCheck
from sraverify.core.logging import logger


class SRA_IAA_4(AccessAnalyzerCheck):
    """Check if IAM Access Analyzer has an analyzer with Organization zone of trust in every region."""
    
    def __init__(self):
        """Initialize IAM Access Analyzer check."""
        super().__init__()
        self.check_id = "SRA-IAA-4"
        self.check_name = "IAM Access Analyzer external access analyzer is configured with Organization zone of trust in every region"
        self.description = ("This check verifies whether IAA external access analyzer is configured with a zone of trust "
                          "of your AWS organization in every available region. IAM Access Analyzer generates a finding for each instance of a "
                          "resource-based policy that grants access to a resource within your zone of trust to a "
                          "principal that is not within your zone of trust. When you configure an organization as the "
                          "zone of trust for an analyzer- IAA generates findings or each instance of a resource-based "
                          "policy that grants access to a resource within your AWS organization to a principal that is "
                          "not within your AWS organization.")
        self.severity = "HIGH"
        self.account_type = "audit"
        self.check_logic = ("Check if an IAM Access Analyzer with Organization zone of trust exists in each region, created by the audit account")
        self._analyzer_details_cache = {}
        self._audit_accounts = []

    def execute(self) -> List[Dict[str, Any]]:
        """Execute the check for each region."""
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        # First, verify this check is running from an audit account - silently add to findings without logging warnings
        if hasattr(self, '_audit_accounts') and self._audit_accounts:
            if account_id not in self._audit_accounts:
                # Don't log a warning, just add to findings
                findings.append(
                    self.create_finding(
                        status="ERROR",
                        region="global",
                        account_id=account_id,
                        resource_id="accessanalyzer:account-validation",
                        actual_value=f"Invalid account for IAM Access Analyzer check: Account {account_id} is not an audit account",
                        remediation=f"This check must be run from an audit account ({', '.join(self._audit_accounts)}). Either run this check from one of the designated audit accounts or update your configuration to specify the correct audit account(s) using the --account-type parameter."
                    )
                )
                return findings
        
        # If no regions have Access Analyzer available, return a single error
        if not self._clients:
            findings.append(
                self.create_finding(
                    status="ERROR",
                    region="global",
                    account_id=account_id,
                    resource_id=f"accessanalyzer:global",
                    actual_value="IAM Access Analyzer not available in any specified region",
                    remediation="Ensure IAM Access Analyzer service is available in at least one region and you have proper permissions"
                )
            )
            return findings
        
        # Check if this account is the delegated admin for Access Analyzer
        is_delegated_admin = False
        
        try:
            # Try to list analyzers - if we can create organization analyzers, we're likely the delegated admin
            for region, client in self._clients.items():
                analyzers = self.get_analyzers(region)
                org_analyzers = [a for a in analyzers if a.get('type') == 'ORGANIZATION' and a.get('arn', '').split(':')[4] == account_id]
                if org_analyzers:
                    is_delegated_admin = True
                    break
        except Exception as e:
            # Don't log debug messages, just continue
            pass
        
        # Track if we found organization analyzers in any region
        found_org_analyzers = False
        all_regions_checked = True
        
        # Check each region where Access Analyzer is available
        for region, client in self._clients.items():
            try:
                # Get analyzers for this region using the base class method that handles caching
                analyzers = self.get_analyzers(region)
                
                # Look for analyzers with organization zone of trust in this specific region
                # that are created by this account
                org_analyzers = [
                    a for a in analyzers 
                    if a.get('type') == 'ORGANIZATION' 
                    and a.get('status') == 'ACTIVE'
                    and a.get('arn', '').split(':')[4] == account_id
                ]
                
                if org_analyzers:
                    # If we found organization analyzers in this region created by this account, report a PASS
                    found_org_analyzers = True
                    analyzer_names = [a.get('name', 'Unknown') for a in org_analyzers]
                    analyzer_arn = org_analyzers[0].get('arn', f"arn:aws:access-analyzer:{region}:{account_id}:analyzer/{region}")
                    
                    findings.append(
                        self.create_finding(
                            status="PASS",
                            region=region,
                            account_id=account_id,
                            resource_id=analyzer_arn,
                            actual_value=f"Found IAM Access Analyzer with Organization zone of trust in {region}: {', '.join(analyzer_names)}",
                            remediation=""
                        )
                    )
                else:
                    # If no organization analyzers in this region created by this account
                    findings.append(
                        self.create_finding(
                            status="FAIL",
                            region=region,
                            account_id=account_id,
                            resource_id="No Organization analyzer found in this region",
                            actual_value=f"No IAM Access Analyzer with Organization zone of trust found in {region}",
                            remediation=f"Create an IAM Access Analyzer with Organization zone of trust in {region} using the AWS CLI command: aws accessanalyzer create-analyzer --analyzer-name org-analyzer --type ORGANIZATION --region {region}"
                        )
                    )
            except Exception as e:
                all_regions_checked = False
                findings.append(
                    self.create_finding(
                        status="ERROR",
                        region=region,
                        account_id=account_id,
                        resource_id="error",
                        actual_value=f"Error checking IAM Access Analyzer in {region}: {str(e)}",
                        remediation="Ensure you have proper permissions to list IAM Access Analyzers and that the service is available in this region"
                    )
                )
        
        # If we didn't find any organization analyzers and we're not the delegated admin
        if not found_org_analyzers and not is_delegated_admin and all_regions_checked:
            findings.append(
                self.create_finding(
                    status="ERROR",
                    region="global",
                    account_id=account_id,
                    resource_id=f"accessanalyzer:delegatedadmin",
                    actual_value="This account does not appear to be the delegated administrator for IAM Access Analyzer",
                    remediation="Register this account as the delegated administrator for IAM Access Analyzer using the AWS CLI command: aws organizations register-delegated-administrator --service-principal access-analyzer.amazonaws.com --account-id " + account_id
                )
            )
        
        return findings
