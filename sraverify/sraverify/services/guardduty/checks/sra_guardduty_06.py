"""
Check if GuardDuty has S3 protection enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_06(GuardDutyCheck):
    """Check if GuardDuty has S3 protection enabled."""

    meta = CheckMeta(
        check_id="SRA-GUARDDUTY-06",
        title="GuardDuty S3 protection enabled",
        description=(
            "This check verifies that GuardDuty has S3 protection enabled. "
            "GuardDuty provides enhanced visibility through S3 protection. "
            "GuardDuty monitors both AWS CloudTrail management events and AWS CloudTrail "
            "S3 data events to identify potential threats in your Amazon S3 resources."
        ),
        check_logic=(
            "Get detector details in each Region. "
            "Check if S3 protection is enabled in the Features array."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="GuardDuty",
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(
            text=(
                "Enable S3 protection for GuardDuty in every enabled Region so that "
                "CloudTrail management events and S3 data events are monitored."
            ),
            cli=(
                "aws guardduty update-detector --detector-id <detector-id> "
                "--features Name=S3_DATA_EVENTS,Status=ENABLED --region <region>"
            ),
            console="GuardDuty console, Settings, Protection plans, S3 Protection, Enable.",
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
                # Check if S3 protection is enabled in the Features array
                s3_protection_enabled = False
                features = detector_details.get('Features', [])

                for feature in features:
                    if feature.get('Name') == 'S3_DATA_EVENTS' and feature.get('Status') == 'ENABLED':
                        s3_protection_enabled = True
                        break

                if s3_protection_enabled:
                    yield self.passed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value="S3 protection is enabled",
                    )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value="S3 protection is not enabled",
                        remediation=f"Enable S3 protection for GuardDuty in {region} to monitor CloudTrail management and S3 data events",
                    )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value="Unable to retrieve detector details",
                    remediation="Check GuardDuty permissions and configuration",
                )
