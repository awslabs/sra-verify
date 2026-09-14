"""
Check if GuardDuty has EC2 agent management enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_19(GuardDutyCheck):
    """Check if GuardDuty has EC2 agent management enabled."""

    meta = CheckMeta(
        check_id="SRA-GUARDDUTY-19",
        title="GuardDuty EC2 agent management enabled",
        description=(
            "This check verifies that GuardDuty has EC2 agent management enabled. "
            "EC2 agent management allows GuardDuty to automatically deploy and manage "
            "the security agent on your EC2 instances, simplifying the setup and maintenance "
            "of runtime monitoring for EC2 workloads."
        ),
        check_logic=(
            "Get detector details in each Region. Check if EC2_AGENT_MANAGEMENT is enabled "
            "in the RUNTIME_MONITORING feature's AdditionalConfiguration."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="GuardDuty",
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(
            text=(
                "Enable EC2 agent management in the GuardDuty Runtime Monitoring "
                "configuration in every enabled Region."
            ),
            cli=(
                "aws guardduty update-detector --detector-id <detector-id> "
                "--features "
                "'Name=RUNTIME_MONITORING,Status=ENABLED,"
                "AdditionalConfiguration=[{Name=EC2_AGENT_MANAGEMENT,Status=ENABLED}]' "
                "--region <region>"
            ),
            console=(
                "GuardDuty console, Settings, Protection plans, Runtime Monitoring, "
                "Automated agent configuration, Amazon EC2, Enable."
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
                # Check if EC2_AGENT_MANAGEMENT is enabled in any RUNTIME_MONITORING feature
                ec2_agent_management_enabled = False
                features = detector_details.get('Features', [])

                for feature in features:
                    if feature.get('Name') == 'RUNTIME_MONITORING':
                        # Check AdditionalConfiguration for EC2_AGENT_MANAGEMENT
                        additional_configs = feature.get('AdditionalConfiguration', [])
                        for config in additional_configs:
                            if config.get('Name') == 'EC2_AGENT_MANAGEMENT' and config.get('Status') == 'ENABLED':
                                ec2_agent_management_enabled = True
                                break

                        if ec2_agent_management_enabled:
                            break

                if ec2_agent_management_enabled:
                    yield self.passed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value="EC2 agent management is enabled",
                    )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value="EC2 agent management is not enabled",
                        remediation=f"Enable EC2 agent management in the Runtime Monitoring configuration for GuardDuty in {region}",
                    )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value="Unable to retrieve detector details",
                    remediation="Check GuardDuty permissions and configuration",
                )
