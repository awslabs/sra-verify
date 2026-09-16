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

        # Set by the guard below when a Region's Config state could not be

        # read. A global 'not found in any region' FAIL must not fire on the

        # strength of Regions that never answered.

        undetermined = False

        for region in self.regions:
            # Get configuration aggregators for the region from cache
            aggregators_response = self.get_configuration_aggregators(region)

            if "Error" in aggregators_response:
                error = aggregators_response['Error']
                if self.is_not_configured(error):
                    # A declared semantic code: AWS answered and the control is
                    # absent. config declares AWSOrganizationsNotInUseException
                    # (DescribeOrganization) and NoSuchBucketPolicy
                    # (GetBucketPolicy); an empty recorder or channel list is a
                    # successful response, not an error, so nothing is declared for
                    # the describe_* operations themselves.
                    yield self.failed(
                        region=region,
                        resource_id=f"config:{self.account_id}:{region}",
                        actual_value=f"AWS Config is not configured in {region}",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"config:{self.account_id}:{region}",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                undetermined = True
                continue

            aggregators = aggregators_response.get(
                'ConfigurationAggregators', []
            )

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
        # A global 'not found in any region' verdict must not rest on Regions
        # that never answered. Each undetermined Region already yielded its own
        # ERROR row above, so returning here reports the gap without also
        # asserting the control is absent.
        if undetermined and not found_all_regions_aggregator:
            return

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
