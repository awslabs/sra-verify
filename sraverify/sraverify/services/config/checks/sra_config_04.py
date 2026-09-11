"""
SRA-CONFIG-04: AWS Config Recording Global Resources.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.config.base import ConfigCheck


class SRA_CONFIG_04(ConfigCheck):
    """Check if AWS Config has an organization aggregator."""

    # NOTE (requirement 11.14): this check loops ``self.regions`` while
    # emitting a single aggregated ``region="global"`` row. It is a candidate
    # for reclassification if a base-driven region loop is ever adopted.
    # Flagged only -- restructuring here would move row keys.
    meta = CheckMeta(
        check_id="SRA-CONFIG-04",
        title="AWS Config has organization aggregator",
        description=(
            "This check verifies that a AWS Config aggregator exists in the AWS Region that collects "
            "configuration and compliance data from all member accounts of the AWS Organization. "
            "It periodically retrieves configuration snapshots from the source accounts and stores "
            "them in the designated S3 bucket."
        ),
        check_logic=(
            "Checks if AWS Config aggregator exists using describe-configuration-aggregators API."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.AUDIT,
        service="Config",
        resource_type="AWS::Config::ConfigurationAggregator",
        remediation=Remediation(
            text=(
                "Create an AWS Config organization aggregator in the audit account so "
                "configuration and compliance data from every member account is collected "
                "centrally."
            ),
            cli=(
                "aws configservice put-configuration-aggregator "
                "--configuration-aggregator-name organization-aggregator "
                "--organization-aggregation-source "
                '"EnableAllRegions=true,RoleArn=<AWSServiceRoleForConfig-arn>" '
                "--region <region>"
            ),
            console=(
                "Config console in the audit account, Aggregators, Add aggregator, "
                "select Add my organization."
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
                checked_value="Configuration aggregator exists",
                actual_value="No regions specified for check",
                remediation="Specify at least one region when running the check",
            )
            return

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
                                                      f"arn:aws:config:{region}:{self.account_id}:config-aggregator/{org_aggregator_name}")
                    break

            if found_org_aggregator:
                break

        # Yield a single finding based on whether an organization aggregator was found
        if found_org_aggregator:
            yield self.passed(
                region="global",
                resource_id=org_aggregator_arn,
                checked_value="Configuration aggregator exists",
                actual_value=f"Configuration aggregator '{org_aggregator_name}' exists in region {org_aggregator_region} with Source Type \"My Organization\"",
            )
        else:
            yield self.failed(
                region="global",
                resource_id=f"arn:aws:config:global:{self.account_id}:config-aggregator/none",
                checked_value="Configuration aggregator exists",
                actual_value="No organization aggregator found in any region",
                remediation=(
                    "Create an organization configuration aggregator in at least one region using: aws configservice put-configuration-aggregator "
                    "--configuration-aggregator-name organization-aggregator --organization-aggregation-source "
                    f"\"EnableAllRegions=true,RoleArn=arn:aws:iam::{self.account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfigServiceRole\" "
                    "--region <region>"
                ),
            )
