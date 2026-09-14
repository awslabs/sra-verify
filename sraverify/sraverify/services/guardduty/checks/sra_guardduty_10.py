"""
Check if GuardDuty has RDS protection enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_10(GuardDutyCheck):
    """Check if GuardDuty has RDS protection enabled."""

    meta = CheckMeta(
        check_id="SRA-GUARDDUTY-10",
        title="GuardDuty RDS protection enabled",
        description=(
            "This check verifies that GuardDuty RDS protection is enabled. "
            "RDS Protection in Amazon GuardDuty analyzes and profiles RDS login activity "
            "for potential access threats to Amazon Aurora databases and Amazon RDS for PostgreSQL."
        ),
        check_logic=(
            "Get detector details in each Region. "
            "Check if RDS protection is enabled in the Features array."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="GuardDuty",
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(
            text="Enable RDS Protection for GuardDuty in every enabled Region.",
            cli=(
                "aws guardduty update-detector --detector-id <detector-id> "
                "--features Name=RDS_LOGIN_EVENTS,Status=ENABLED --region <region>"
            ),
            console="GuardDuty console, Settings, Protection plans, RDS Protection, Enable.",
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
                # Check if RDS protection is enabled in the Features array
                rds_protection_enabled = False
                features = detector_details.get('Features', [])

                for feature in features:
                    if feature.get('Name') == 'RDS_LOGIN_EVENTS' and feature.get('Status') == 'ENABLED':
                        rds_protection_enabled = True
                        break

                if rds_protection_enabled:
                    yield self.passed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value="RDS protection is enabled",
                    )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value="RDS protection is not enabled",
                        remediation=f"Enable RDS protection for GuardDuty in {region} to monitor login activity for potential threats to Aurora and RDS for PostgreSQL databases",
                    )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value="Unable to retrieve detector details",
                    remediation="Check GuardDuty permissions and configuration",
                )
