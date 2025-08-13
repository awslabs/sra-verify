"""
SRA-CONFIG-05: AWS Config Recorder Status.
"""
from typing import List, Dict, Any
from sraverify.services.config.base import ConfigCheck
from sraverify.core.logging import logger


class SRA_CONFIG_05(ConfigCheck):
    """Check if AWS Config organization aggregator includes all regions."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-CONFIG-05"
        self.check_name = "AWS Config organization aggregator includes all regions"
        self.account_type = "audit"  # This check applies to audit account
        self.severity = "MEDIUM"
        self.description = (
            "This check verifies that the AWS Config organization aggregator is configured to aggregate "
            "config data from all existing and future AWS Regions. This provides you visibility into "
            "activities across all regions even if your business does not operate in the region."
        )
        self.check_logic = (
            "Checks if AWS Config organization aggregator has AllAwsRegions set to true."
        )
        self.resource_type = "AWS::Config::ConfigurationAggregator"
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        
        if not self.regions:
            findings.append(
                self.create_finding(
                    status="ERROR",
                    region="global",
                    resource_id="config:global",
                    checked_value="AllAwsRegions: true",
                    actual_value="No regions specified for check",
                    remediation="Specify at least one region when running the check"
                )
            )
            return findings
        
        # Check if an organization aggregator with AllAwsRegions=true exists in any region
        found_all_regions_aggregator = False
        all_regions_aggregator_region = None
        all_regions_aggregator_name = None
        all_regions_aggregator_arn = None
        
        for region in self.regions:
            # Get configuration aggregators for the region from cache
            aggregators = self.get_configuration_aggregators(region)
            
            # Check if any of the aggregators is an organization aggregator with all regions enabled
            for aggregator in aggregators:
                if ('OrganizationAggregationSource' in aggregator and 
                    aggregator.get('OrganizationAggregationSource', {}).get('AllAwsRegions', False)):
                    found_all_regions_aggregator = True
                    all_regions_aggregator_region = region
                    all_regions_aggregator_name = aggregator.get('ConfigurationAggregatorName', 'Unknown')
                    all_regions_aggregator_arn = aggregator.get('ConfigurationAggregatorArn', 
                                                              f"arn:aws:config:{region}:{self.account_id}:config-aggregator/{all_regions_aggregator_name}")
                    break
            
            if found_all_regions_aggregator:
                break
        
        # Return a single finding based on whether an organization aggregator with AllAwsRegions=true was found
        if found_all_regions_aggregator:
            findings.append(
                self.create_finding(
                    status="PASS",
                    region="global",
                    resource_id=all_regions_aggregator_arn,
                    checked_value="AllAwsRegions: true",
                    actual_value=f"Configuration aggregator '{all_regions_aggregator_name}' is configured to aggregate all regions, located in region {all_regions_aggregator_region} with Region selection \"All current and future AWS regions\"",
                    remediation="No remediation needed"
                )
            )
        else:
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    resource_id=f"arn:aws:config:global:{self.account_id}:config-aggregator/none",
                    checked_value="AllAwsRegions: true",
                    actual_value="No organization aggregator with AllAwsRegions=true found in any region",
                    remediation=(
                        "Create an organization configuration aggregator with AllAwsRegions=true in at least one region using: aws configservice put-configuration-aggregator "
                        "--configuration-aggregator-name organization-aggregator --organization-aggregation-source "
                        f"\"EnableAllRegions=true,RoleArn=arn:aws:iam::{self.account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfigServiceRole\" "
                        "--region <region>"
                    )
                )
            )
        
        return findings
