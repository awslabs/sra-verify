"""
Check if GuardDuty has CloudTrail event and management logs enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_08(GuardDutyCheck):
    """Check if GuardDuty has CloudTrail event and management logs enabled."""

    meta = CheckMeta(
        check_id="SRA-GUARDDUTY-08",
        title="GuardDuty CloudTrail logs enabled",
        description=(
            "This check verifies that GuardDuty has CloudTrail event and management logs as one of the feature, enabled. "
            "GuardDuty consumes CloudTrail management events directly from CloudTrail through an independent and "
            "duplicated stream of events and analyzes the CloudTrail event logs."
        ),
        check_logic=(
            "Get detector details in each Region. "
            "Check if CloudTrail logs are enabled in the Features array."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="GuardDuty",
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(
            text=(
                "Enable CloudTrail event and management logs for GuardDuty in every "
                "enabled Region."
            ),
            cli=(
                "aws guardduty update-detector --detector-id <detector-id> "
                "--features Name=CLOUD_TRAIL,Status=ENABLED --region <region>"
            ),
            console="GuardDuty console, Settings, Protection plans, CloudTrail logs, Enable.",
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

            # Get detector details
            detector_details = self.get_detector_details(region)

            if detector_details:
                # Check if CloudTrail logs are enabled in the Features array
                cloudtrail_enabled = False
                features = detector_details.get('Features', [])

                for feature in features:
                    if feature.get('Name') == 'CLOUD_TRAIL' and feature.get('Status') == 'ENABLED':
                        cloudtrail_enabled = True
                        break

                if cloudtrail_enabled:
                    yield self.passed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value="CloudTrail event and management logs are enabled",
                    )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value="CloudTrail event and management logs are not enabled",
                        remediation=f"Enable CloudTrail event and management logs for GuardDuty in {region} to monitor for suspicious API activity",
                    )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value="Unable to retrieve detector details",
                    remediation="Check GuardDuty permissions and configuration",
                )
