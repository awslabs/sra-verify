"""
SRA-CONFIG-09: AWS Config Aggregator Status.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.config.base import ConfigCheck


class SRA_CONFIG_09(ConfigCheck):
    """Check if Config Organization aggregator is in a valid status."""

    meta = CheckMeta(
        check_id="SRA-CONFIG-09",
        title="Config Organization aggregator is in a valid status",
        description=(
            "This check verifies whether Config Organization aggregator has a valid status. "
            "A value of FAILED indicates errors while moving data and value OUTDATED indicates "
            "the data is not the most recent."
        ),
        check_logic=(
            "Checks if all aggregator sources have a status of SUCCEEDED using "
            "describe-configuration-aggregator-sources-status API."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.AUDIT,
        service="Config",
        resource_type="AWS::Config::ConfigurationAggregator",
        remediation=Remediation(
            text=(
                "Bring every AWS Config organization aggregator source to LastUpdateStatus "
                "SUCCEEDED by granting the aggregator role access to the source accounts and "
                "Regions."
            ),
            cli=(
                "aws configservice describe-configuration-aggregator-sources-status "
                "--configuration-aggregator-name <aggregator-name> --region <region>"
            ),
            console=(
                "Config console in the audit account, Aggregators, select the aggregator, "
                "review the source status table for FAILED or OUTDATED entries."
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
                checked_value="All source statuses are SUCCEEDED",
                actual_value="No regions specified for check",
                remediation="Specify at least one region when running the check",
            )
            return

        # First, find an organization aggregator in any region
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

        # If no organization aggregator found in any region, yield a global failure
        if not found_org_aggregator:
            yield self.failed(
                region="global",
                resource_id=f"arn:aws:config:global:{self.account_id}:config-aggregator/none",
                checked_value="All source statuses are SUCCEEDED",
                actual_value="No organization aggregator found in any region",
                remediation=(
                    "Create an organization configuration aggregator in at least one region using: aws configservice put-configuration-aggregator "
                    "--configuration-aggregator-name organization-aggregator --organization-aggregation-source "
                    f"\"EnableAllRegions=true,RoleArn=arn:aws:iam::{self.account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfigServiceRole\" "
                    "--region <region>"
                ),
            )
            return

        # Get client for the region where we found the organization aggregator
        client = self.get_client(org_aggregator_region)
        if not client:
            yield self.error(
                region="global",
                resource_id=org_aggregator_arn,
                checked_value="All source statuses are SUCCEEDED",
                actual_value=f"No Config client available for region {org_aggregator_region}",
                remediation="Ensure AWS Config service is available in the region and you have proper permissions",
            )
            return

        # Get aggregator sources status
        try:
            source_statuses = client.describe_configuration_aggregator_sources_status(org_aggregator_name)
        except Exception as e:
            yield self.error(
                region="global",
                resource_id=org_aggregator_arn,
                checked_value="All source statuses are SUCCEEDED",
                actual_value=f"Error getting source statuses for aggregator '{org_aggregator_name}' in region {org_aggregator_region}: {str(e)}",
                remediation="Ensure you have proper permissions to check aggregator status",
            )
            return

        if not source_statuses:
            # No source statuses found
            yield self.failed(
                region="global",
                resource_id=org_aggregator_arn,
                checked_value="All source statuses are SUCCEEDED",
                actual_value=f"No source statuses found for organization aggregator '{org_aggregator_name}' in region {org_aggregator_region}",
                remediation=f"Check the aggregator configuration in {org_aggregator_region} and ensure it has valid sources",
            )
            return

        # Check if all sources have SUCCEEDED status
        failed_sources = []
        for source in source_statuses:
            source_id = source.get('SourceId', 'Unknown')
            source_type = source.get('SourceType', 'Unknown')
            source_status = source.get('LastUpdateStatus', 'UNKNOWN')

            if source_status != "SUCCEEDED":
                failed_sources.append(f"{source_type}:{source_id} ({source_status})")

        if failed_sources:
            # Some sources have failed
            yield self.failed(
                region="global",
                resource_id=org_aggregator_arn,
                checked_value="All source statuses are SUCCEEDED",
                actual_value=f"Organization aggregator '{org_aggregator_name}' in region {org_aggregator_region} has sources with status: {', '.join(failed_sources)}",
                remediation=(
                    f"Check the AWS Config logs for errors related to the aggregator sources. "
                    f"Ensure the aggregator has the necessary permissions to access the source accounts."
                ),
            )
        else:
            # All sources have succeeded
            yield self.passed(
                region="global",
                resource_id=org_aggregator_arn,
                checked_value="All source statuses are SUCCEEDED",
                actual_value=f"Organization aggregator '{org_aggregator_name}' in region {org_aggregator_region} has all sources with status SUCCEEDED",
            )
