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
