"""
Check if GuardDuty detector is enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_03(GuardDutyCheck):
    """Check if GuardDuty detector is enabled."""

    meta = CheckMeta(
        check_id="SRA-GUARDDUTY-03",
        title="GuardDuty detector is enabled",
        description=(
            "This check verifies that the GuardDuty detector in the "
            "AWS account and AWS region is enabled. Detector represents "
            "GuardDuty service in the AWS account and specific region, "
            "if disabled will not provided threat intelligence service."
        ),
        check_logic=(
            "Get detector details in each Region. Check value of FindingPublishingFrequency."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="GuardDuty",
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(
            text="Enable the GuardDuty detector in every enabled Region.",
            cli=(
                "aws guardduty update-detector --detector-id <detector-id> "
                "--enable --region <region>"
            ),
            console="GuardDuty console, Settings, GuardDuty status, Enable.",
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

            # Use helper method from the base class
            detector_details = self.get_detector_details(region)

            if detector_details:
                detector_status = detector_details.get('Status', 'Not set')

                if detector_status == 'ENABLED':
                    yield self.passed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value=f"Detector status is {detector_status}",
                    )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value=f"Detector status is {detector_status}",
                        remediation="Enabled GuardDuty",
                    )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value="Unable to retrieve detector details",
                    remediation="Check GuardDuty permissions and configuration",
                )
