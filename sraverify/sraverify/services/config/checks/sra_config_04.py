"""
SRA-CONFIG-04: AWS Config Recording Global Resources.
"""
from typing import List, Dict, Any
from sraverify.services.config.base import ConfigCheck
from sraverify.core.logging import logger


class SRA_CONFIG_04(ConfigCheck):
    """Check if AWS Config has an organization aggregator."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-CONFIG-04"
        self.check_name = "AWS Config has organization aggregator"
        self.account_type = "audit"  # This check applies to audit account
        self.severity = "HIGH"
        self.description = (
            "This check verifies that a AWS Config aggregator exists in the AWS Region that collects "
            "configuration and compliance data from all member accounts of the AWS Organization. "
            "It periodically retrieves configuration snapshots from the source accounts and stores "
            "them in the designated S3 bucket."
        )
        self.check_logic = (
            "Checks if AWS Config aggregator exists using describe-configuration-aggregators API."
        )
        self.resource_type = "AWS::Config::ConfigurationAggregator"
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        if not self.regions:
            findings.append(
                self.create_finding(
                    status="ERROR",
                    region="global",
                    account_id=account_id,
                    resource_id="config:global",
                    checked_value="Configuration aggregator exists",
                    actual_value="No regions specified for check",
                    remediation="Specify at least one region when running the check"
                )
            )
            return findings
        
        # Check if an organization aggregator exists in any region
        found_org_aggregator = False
        org_aggregator_region = None
        org_aggregator_name = None
        org_aggregator_arn = None
        
        for region in self.regions:
            # Get configuration aggregators for the region using the cache
            aggregators = self.get_configuration_aggregators(region)
            
            # Check if any of the aggregators is an organization aggregator
            for aggregator in aggregators:
                if 'OrganizationAggregationSource' in aggregator:
                    found_org_aggregator = True
                    org_aggregator_region = region
                    org_aggregator_name = aggregator.get('ConfigurationAggregatorName', 'Unknown')
                    org_aggregator_arn = aggregator.get('ConfigurationAggregatorArn', 
                                                      f"arn:aws:config:{region}:{account_id}:config-aggregator/{org_aggregator_name}")
                    break
            
            if found_org_aggregator:
                break
        
        # Return a single finding based on whether an organization aggregator was found
        if found_org_aggregator:
            findings.append(
                self.create_finding(
                    status="PASS",
                    region="global",
                    account_id=account_id,
                    resource_id=org_aggregator_arn,
                    checked_value="Configuration aggregator exists",
                    actual_value=f"Configuration aggregator '{org_aggregator_name}' exists in region {org_aggregator_region} with Source Type \"My Organization\"",
                    remediation="No remediation needed"
                )
            )
        else:
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    account_id=account_id,
                    resource_id=f"arn:aws:config:global:{account_id}:config-aggregator/none",
                    checked_value="Configuration aggregator exists",
                    actual_value="No organization aggregator found in any region",
                    remediation=(
                        "Create an organization configuration aggregator in at least one region using: aws configservice put-configuration-aggregator "
                        "--configuration-aggregator-name organization-aggregator --organization-aggregation-source "
                        f"\"EnableAllRegions=true,RoleArn=arn:aws:iam::{account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfigServiceRole\" "
                        "--region <region>"
                    )
                )
            )
        
        return findings
