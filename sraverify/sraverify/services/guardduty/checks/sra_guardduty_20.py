"""
Check if GuardDuty S3 data events are configured for auto-enablement.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_20(GuardDutyCheck):
    """Check if GuardDuty S3 data events are configured for auto-enablement."""

    meta = CheckMeta(
        check_id="SRA-GUARDDUTY-20",
        title="GuardDuty S3 data events auto-enablement configured",
        description=(
            "This check verifies whether S3 data events are configured for auto-enablement "
            "in GuardDuty for all member accounts. S3 data events provide visibility into "
            "object-level API operations, enhancing threat detection for S3 buckets."
        ),
        check_logic=(
            "Check if S3_DATA_EVENTS feature is configured with AutoEnable set to ALL."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.AUDIT,
        service="GuardDuty",
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(
            text=(
                "Set AutoEnable to ALL for the GuardDuty S3_DATA_EVENTS feature in every "
                "enabled Region."
            ),
            cli=(
                "aws guardduty update-organization-configuration "
                "--detector-id <detector-id> "
                "--features Name=S3_DATA_EVENTS,AutoEnable=ALL --region <region>"
            ),
            console=(
                "GuardDuty console in the delegated administrator account, Settings, "
                "Accounts, S3 Protection, Enable for all accounts."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Region.
        """
        # Check all regions
        for region in self.regions:
            detector_id = self.get_detector_id(region)

            # Handle regions where we can't access GuardDuty
            if not detector_id:
                yield self.error(
                    region=region,
                    resource_id=f"guardduty:{region}",
                    actual_value="Unable to access GuardDuty in this region",
                    remediation="Check permissions or if GuardDuty is supported in this region",
                )
                continue

            # Get organization configuration for GuardDuty
            org_config = self.get_organization_configuration(region)

            # Check if there was an error in the response
            if "Error" in org_config:
                error_code = org_config["Error"].get("Code", "Unknown")
                error_message = org_config["Error"].get("Message", "Unknown error")

                # Handle BadRequestException specifically for non-management accounts
                if error_code == "BadRequestException":
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value=f"{error_code} {error_message}",
                        remediation="Verify that GuardDuty is the delegated admin in this Region and run the check again.",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value=f"Error accessing GuardDuty organization configuration: {error_code}",
                        remediation="Check permissions and AWS Organizations configuration",
                    )
                continue

            # Check if S3 data events are configured for auto-enablement
            # Look for S3_DATA_EVENTS in Features
            s3_data_events_found = False
            s3_data_events_auto_enable = "NOT_CONFIGURED"
            features = org_config.get('Features', [])

            for feature in features:
                if feature.get('Name') == 'S3_DATA_EVENTS':
                    s3_data_events_found = True
                    s3_data_events_auto_enable = feature.get('AutoEnable', 'NONE')
                    break

            if s3_data_events_found and s3_data_events_auto_enable == 'ALL':
                yield self.passed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value="GuardDuty S3 data events are configured for auto-enablement for all accounts (AutoEnable=ALL)",
                )
            elif s3_data_events_found:
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value=f"GuardDuty S3 data events are configured with AutoEnable={s3_data_events_auto_enable}, but should be ALL",
                    remediation=f"Configure S3 data events auto-enablement for all accounts in {region} by setting AutoEnable to ALL",
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value=f"GuardDuty S3 data events feature is not configured",
                    remediation=f"Enable S3 data events feature and configure auto-enablement for all accounts in {region}",
                )
