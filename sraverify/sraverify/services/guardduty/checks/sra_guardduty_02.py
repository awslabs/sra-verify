"""
Check if GuardDuty finding frequency is set.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_02(GuardDutyCheck):
    """Check if GuardDuty finding frequency is set."""

    meta = CheckMeta(
        check_id="SRA-GUARDDUTY-02",
        title="GuardDuty finding frequency is set",
        description=(
            "This check verifies that the GuardDuty finding frequency is set "
            "as per your organization requirement. This determines how often updates to active "
            "findings are exported to EventBridge, S3 (optional) and Detective (optional). "
            "By default, updated findings are exported every 6 hours but you can set to "
            "every 15 minutes or 1 hour."
        ),
        check_logic=(
            "Get detector details in each Region. Check value of FindingPublishingFrequency."
        ),
        severity=Severity.LOW,
        account_type=AccountType.APPLICATION,
        service="GuardDuty",
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(
            text=(
                "Set the GuardDuty finding publishing frequency to FIFTEEN_MINUTES, "
                "ONE_HOUR, or SIX_HOURS in every enabled Region."
            ),
            cli=(
                "aws guardduty update-detector --detector-id <detector-id> "
                "--finding-publishing-frequency FIFTEEN_MINUTES --region <region>"
            ),
            console=(
                "GuardDuty console, Settings, Finding export options, "
                "Update frequency for updated findings."
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
                yield self.error(
                    region=region,
                    resource_id=f"guardduty:{region}",
                    actual_value="Unable to access GuardDuty in this region",
                    remediation="Check permissions or if GuardDuty is supported in this region",
                )
                continue

            # Use helper method from the base class
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
                finding_frequency = detector_details.get('FindingPublishingFrequency', 'Not set')

                # Determine if the frequency is set to a valid value
                valid_frequencies = ['FIFTEEN_MINUTES', 'ONE_HOUR', 'SIX_HOURS']
                if finding_frequency in valid_frequencies:
                    yield self.passed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value=f"Finding frequency is set to {finding_frequency}",
                    )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value=f"Finding frequency is not properly set: {finding_frequency}",
                        remediation="Set GuardDuty finding frequency to FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS",
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
