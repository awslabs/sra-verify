"""
Check if GuardDuty has malware protection for EBS enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_09(GuardDutyCheck):
    """Check if GuardDuty has malware protection for EBS enabled."""

    meta = CheckMeta(
        check_id="SRA-GUARDDUTY-09",
        title="GuardDuty malware protection for EBS enabled",
        description=(
            "This check verifies that GuardDuty malware protection for EBS is enabled. "
            "Malware Protection for EC2 helps you detect the potential presence of malware "
            "by scanning the Amazon EBS volumes that are attached to the Amazon EC2 instances "
            "and container workloads."
        ),
        check_logic=(
            "Get detector details in each Region. "
            "Check if malware protection for EBS is enabled in the Features array."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="GuardDuty",
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(
            text=(
                "Enable Malware Protection for EBS in GuardDuty in every enabled Region."
            ),
            cli=(
                "aws guardduty update-detector --detector-id <detector-id> "
                "--features Name=EBS_MALWARE_PROTECTION,Status=ENABLED --region <region>"
            ),
            console=(
                "GuardDuty console, Settings, Protection plans, "
                "Malware Protection for EC2, Enable."
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

            # Get detector details
            detector_details = self.get_detector_details(region)

            if detector_details:
                # Check if malware protection for EBS is enabled in the Features array
                ebs_malware_protection_enabled = False
                features = detector_details.get('Features', [])

                for feature in features:
                    if feature.get('Name') == 'EBS_MALWARE_PROTECTION' and feature.get('Status') == 'ENABLED':
                        ebs_malware_protection_enabled = True
                        break

                if ebs_malware_protection_enabled:
                    yield self.passed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value="Malware protection for EBS is enabled",
                    )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value="Malware protection for EBS is not enabled",
                        remediation=f"Enable malware protection for EBS in GuardDuty in {region} to scan EC2 instances and container workloads for malware",
                    )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value="Unable to retrieve detector details",
                    remediation="Check GuardDuty permissions and configuration",
                )
