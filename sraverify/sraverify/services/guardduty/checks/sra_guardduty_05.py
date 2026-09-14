"""
Check if GuardDuty has VPC flow logs enabled as a log source.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_05(GuardDutyCheck):
    """Check if GuardDuty has VPC flow logs enabled as a log source."""

    meta = CheckMeta(
        check_id="SRA-GUARDDUTY-05",
        title="GuardDuty VPC flow logs enabled",
        description=(
            "This check verifies that GuardDuty has VPC flow logs as one of the log sources, "
            "enabled.GuardDuty analyzes your VPC flow logs from Amazon EC2 instances within your account. "
            "It consumes VPC flow log events directly from the VPC Flow Logs feature through an independent "
            "and duplicated stream of flow logs."
        ),
        check_logic=(
            "Get detector details in each Region. "
            "Check if VPC Flow logs are enabled in the Features array."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service="GuardDuty",
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(
            text="Enable VPC flow logs as a GuardDuty data source in every enabled Region.",
            cli=(
                "aws guardduty update-detector --detector-id <detector-id> "
                "--features Name=FLOW_LOGS,Status=ENABLED --region <region>"
            ),
            console="GuardDuty console, Settings, Protection plans, VPC flow logs, Enable.",
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
                # Check if VPC flow logs are enabled in the Features array
                vpc_logs_enabled = False
                features = detector_details.get('Features', [])

                for feature in features:
                    if feature.get('Name') == 'FLOW_LOGS' and feature.get('Status') == 'ENABLED':
                        vpc_logs_enabled = True
                        break

                if vpc_logs_enabled:
                    yield self.passed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value="VPC flow logs are enabled as a data source",
                    )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value="VPC flow logs are not enabled as a data source",
                        remediation=f"Enable VPC flow logs as a data source for GuardDuty in {region}",
                    )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value="Unable to retrieve detector details",
                    remediation="Check GuardDuty permissions and configuration",
                )
