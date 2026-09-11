"""
Check if GuardDuty has DNS logs enabled as a log source.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_04(GuardDutyCheck):
    """Check if GuardDuty has DNS logs enabled as a log source."""

    meta = CheckMeta(
        check_id="SRA-GUARDDUTY-04",
        title="GuardDuty DNS logs enabled",
        description=(
            "This check verifies that GuardDuty has DNS logs as one of the log sources, enabled. "
            "If you use AWS DNS resolvers for your Amazon EC2 instances (the default setting), "
            "then GuardDuty can access and process your request and response DNS logs through the "
            "internal AWS DNS resolvers."
        ),
        check_logic=(
            "Get detector details in each Region. "
            "Check if DNS logs are enabled in the Features array."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service="GuardDuty",
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(
            text="Enable DNS logs as a GuardDuty data source in every enabled Region.",
            cli=(
                "aws guardduty update-detector --detector-id <detector-id> "
                "--features Name=DNS_LOGS,Status=ENABLED --region <region>"
            ),
            console="GuardDuty console, Settings, Protection plans, DNS logs, Enable.",
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
                # Check if DNS logs are enabled in the Features array
                dns_logs_enabled = False
                features = detector_details.get('Features', [])

                for feature in features:
                    if feature.get('Name') == 'DNS_LOGS' and feature.get('Status') == 'ENABLED':
                        dns_logs_enabled = True
                        break

                if dns_logs_enabled:
                    yield self.passed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value="DNS logs are enabled as a data source",
                    )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value="DNS logs are not enabled as a data source",
                        remediation=f"Enable DNS logs as a data source for GuardDuty in {region}",
                    )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value="Unable to retrieve detector details",
                    remediation="Check GuardDuty permissions and configuration",
                )
