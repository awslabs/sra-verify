"""
Check if GuardDuty has ECS Fargate agent management enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_18(GuardDutyCheck):
    """Check if GuardDuty has ECS Fargate agent management enabled."""

    meta = CheckMeta(
        check_id="SRA-GUARDDUTY-18",
        title="GuardDuty ECS Fargate agent management enabled",
        description=(
            "This check verifies that GuardDuty has ECS Fargate agent management enabled. "
            "ECS Fargate agent management allows GuardDuty to automatically deploy and manage "
            "the security agent on your ECS Fargate tasks, simplifying the setup and maintenance "
            "of runtime monitoring for containerized workloads."
        ),
        check_logic=(
            "Get detector details in each Region. Check if ECS_FARGATE_AGENT_MANAGEMENT is "
            "enabled in the RUNTIME_MONITORING feature's AdditionalConfiguration."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="GuardDuty",
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(
            text=(
                "Enable ECS Fargate agent management in the GuardDuty Runtime Monitoring "
                "configuration in every enabled Region."
            ),
            cli=(
                "aws guardduty update-detector --detector-id <detector-id> "
                "--features "
                "'Name=RUNTIME_MONITORING,Status=ENABLED,"
                "AdditionalConfiguration=[{Name=ECS_FARGATE_AGENT_MANAGEMENT,Status=ENABLED}]' "
                "--region <region>"
            ),
            console=(
                "GuardDuty console, Settings, Protection plans, Runtime Monitoring, "
                "Automated agent configuration, AWS Fargate (ECS only), Enable."
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
            detectors = self.get_detector_id(region)

            # Test for the error result before reading any success-path key: this
            # is where "GuardDuty is not enabled here" and "the call failed" part
            # company.
            if "Error" in detectors:
                error = detectors["Error"]
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}",
                        actual_value=(
                            f"GuardDuty is not configured in this Region "
                            f"({error['Code']})"
                        ),
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"guardduty:{region}",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            detector_id = self.detector_id_of(detectors)

            if not detector_id:
                # Reached only after the error test above passed, so ListDetectors
                # succeeded and named no detector: GuardDuty is not enabled in this
                # Region. AWS answered, and the answer is that the control is absent,
                # which is a FAIL. Reporting it as ERROR asserted an inability to
                # determine something we had in fact determined.
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}",
                    actual_value="No GuardDuty detector in this Region",
                    remediation=f"Enable GuardDuty in {region}",
                )
                continue

            # Get detector details
            detector_details = self.get_detector_details(region)

            if "Error" in detector_details:
                error = detector_details["Error"]
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value=(
                            f"GuardDuty is not configured in this Region "
                            f"({error['Code']})"
                        ),
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            if detector_details:
                # Check if ECS_FARGATE_AGENT_MANAGEMENT is enabled in any RUNTIME_MONITORING feature
                ecs_fargate_agent_management_enabled = False
                features = detector_details.get('Features', [])

                for feature in features:
                    if feature.get('Name') == 'RUNTIME_MONITORING':
                        # Check AdditionalConfiguration for ECS_FARGATE_AGENT_MANAGEMENT
                        additional_configs = feature.get('AdditionalConfiguration', [])
                        for config in additional_configs:
                            if config.get('Name') == 'ECS_FARGATE_AGENT_MANAGEMENT' and config.get('Status') == 'ENABLED':
                                ecs_fargate_agent_management_enabled = True
                                break

                        if ecs_fargate_agent_management_enabled:
                            break

                if ecs_fargate_agent_management_enabled:
                    yield self.passed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value="ECS Fargate agent management is enabled",
                    )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value="ECS Fargate agent management is not enabled",
                        remediation=f"Enable ECS Fargate agent management in the Runtime Monitoring configuration for GuardDuty in {region}",
                    )
            else:
                # Not reachable in practice: the detector ID was resolved above,
                # so an empty GetDetector response would mean the detector
                # vanished between two calls. An ERROR rather than a FAIL,
                # because that is an undetermined state and not evidence the
                # control is absent.
                yield self.error(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value=(
                        "GetDetector returned no detector configuration for "
                        f"{detector_id}"
                    ),
                    remediation=(
                        "Re-run the scan; if it persists, confirm the detector "
                        f"still exists in {region}"
                    ),
                )
