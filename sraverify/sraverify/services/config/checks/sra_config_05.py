"""
SRA-CONFIG-05: AWS Config Recorder Status.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.config.base import ConfigCheck


class SRA_CONFIG_05(ConfigCheck):
    """Check if AWS Config organization aggregator includes all regions."""

    # NOTE (requirement 11.14): this check loops ``self.regions`` while
    # emitting a single aggregated ``region="global"`` row. It is a candidate
    # for reclassification if a base-driven region loop is ever adopted.
    # Flagged only -- restructuring here would move row keys.
    meta = CheckMeta(
        check_id="SRA-CONFIG-05",
        title="AWS Config organization aggregator includes all regions",
        description=(
            "This check verifies that the AWS Config organization aggregator is configured to aggregate "
            "config data from all existing and future AWS Regions. This provides you visibility into "
            "activities across all regions even if your business does not operate in the region."
        ),
        check_logic=(
            "Checks if AWS Config organization aggregator has AllAwsRegions set to true."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.AUDIT,
        service="Config",
        resource_type="AWS::Config::ConfigurationAggregator",
        remediation=Remediation(
            text=(
                "Configure the AWS Config organization aggregator with AllAwsRegions set to "
                "true so it aggregates all current and future AWS Regions."
            ),
            cli=(
                "aws configservice put-configuration-aggregator "
                "--configuration-aggregator-name organization-aggregator "
                "--organization-aggregation-source "
                '"EnableAllRegions=true,RoleArn=<AWSServiceRoleForConfig-arn>" '
                "--region <region>"
            ),
            console=(
                "Config console in the audit account, Aggregators, select the aggregator, "
                "Edit, choose All current and future AWS regions."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One global Finding.
        """
        if not self.regions:
            yield self.error(
                region="global",
                resource_id="config:global",
                checked_value="AllAwsRegions: true",
                actual_value="No regions specified for check",
                remediation="Specify at least one region when running the check",
            )
            return

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

        # Yield a single finding based on whether an organization aggregator with AllAwsRegions=true was found
        if found_all_regions_aggregator:
            yield self.passed(
                region="global",
                resource_id=all_regions_aggregator_arn,
                checked_value="AllAwsRegions: true",
                actual_value=f"Configuration aggregator '{all_regions_aggregator_name}' is configured to aggregate all regions, located in region {all_regions_aggregator_region} with Region selection \"All current and future AWS regions\"",
            )
        else:
            yield self.failed(
                region="global",
                resource_id=f"arn:aws:config:global:{self.account_id}:config-aggregator/none",
                checked_value="AllAwsRegions: true",
                actual_value="No organization aggregator with AllAwsRegions=true found in any region",
                remediation=(
                    "Create an organization configuration aggregator with AllAwsRegions=true in at least one region using: aws configservice put-configuration-aggregator "
                    "--configuration-aggregator-name organization-aggregator --organization-aggregation-source "
                    f"\"EnableAllRegions=true,RoleArn=arn:aws:iam::{self.account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfigServiceRole\" "
                    "--region <region>"
                ),
            )
