"""
Check if GuardDuty has EKS runtime protection enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_11(GuardDutyCheck):
    """Check if GuardDuty has EKS runtime protection enabled."""

    meta = CheckMeta(
        check_id="SRA-GUARDDUTY-11",
        title="GuardDuty EKS runtime protection enabled",
        description=(
            "This check verifies that GuardDuty EKS runtime (original) or runtime protection is enabled. "
            "Runtime Monitoring observes and analyzes operating system-level, networking, "
            "and file events to help you detect potential threats in specific AWS workloads"
        ),
        check_logic=(
            "Get detector details in each Region. Check if EKS runtime monitoring or "
            "runtime monitoring is enabled in the Features array."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="GuardDuty",
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(
            text="Enable Runtime Monitoring for GuardDuty in every enabled Region.",
            cli=(
                "aws guardduty update-detector --detector-id <detector-id> "
                "--features Name=RUNTIME_MONITORING,Status=ENABLED --region <region>"
            ),
            console=(
                "GuardDuty console, Settings, Protection plans, Runtime Monitoring, Enable."
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
                # Check if EKS runtime protection is enabled in the Features array
                # We need to check both EKS_RUNTIME_MONITORING (original) and RUNTIME_MONITORING features
                eks_runtime_protection_enabled = False
                runtime_monitoring_enabled = False
                features = detector_details.get('Features', [])

                for feature in features:
                    if feature.get('Name') == 'EKS_RUNTIME_MONITORING' and feature.get('Status') == 'ENABLED':
                        eks_runtime_protection_enabled = True
                    if feature.get('Name') == 'RUNTIME_MONITORING' and feature.get('Status') == 'ENABLED':
                        runtime_monitoring_enabled = True

                # Consider the check passed if either of the runtime monitoring features is enabled
                if eks_runtime_protection_enabled or runtime_monitoring_enabled:
                    enabled_features = []
                    if eks_runtime_protection_enabled:
                        enabled_features.append("EKS_RUNTIME_MONITORING")
                    if runtime_monitoring_enabled:
                        enabled_features.append("RUNTIME_MONITORING")

                    yield self.passed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value=f"Runtime protection is enabled: {', '.join(enabled_features)}",
                    )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value="Runtime protection is not enabled",
                        remediation=f"Enable Runtime Monitoring for GuardDuty in {region} to monitor operating system-level, networking, and file events in workloads",
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
