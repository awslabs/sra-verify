"""
Check if GuardDuty detector exists.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_01(GuardDutyCheck):
    """Check if GuardDuty detector exists."""

    meta = CheckMeta(
        check_id="SRA-GUARDDUTY-01",
        title="GuardDuty detector exists",
        description=(
            "This check verifies that an GuardDuty detector exists in the AWS Region. "
            "A detector is a resource that represents the GuardDuty service and should "
            "be present in all AWS member account and AWS Region so that GuardDuty can "
            "generate findings about unauthorized or unusual activity even in those "
            "Regions that you may not be using actively."
        ),
        check_logic=(
            "Get detector_id in each Region. Check fails if there is no detector_id"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="GuardDuty",
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(
            text="Enable GuardDuty in every enabled Region.",
            cli="aws guardduty create-detector --enable --region <region>",
            console="GuardDuty console, Get started, Enable GuardDuty. Repeat per Region.",
        ),
        sra_sections=("Security Tooling account", "Amazon GuardDuty"),
        additional_urls=(
            "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Region.
        """
        for region in self.regions:
            detectors = self.get_detector_id(region)

            # Before the migration a failed ListDetectors call and a Region
            # with no detector both arrived here as None, and both produced
            # the FAIL below -- a masked FAIL, asserting the detector is
            # absent on the strength of a call that never answered.
            if "Error" in detectors:
                error = detectors["Error"]
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=None,
                        actual_value=(
                            f"GuardDuty is not configured in this Region "
                            f"({error['Code']})"
                        ),
                        remediation=f"Enable GuardDuty in {region}",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=None,
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            detector_id = self.detector_id_of(detectors)

            if not detector_id:
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value="No GuardDuty detector in this Region",
                    remediation=f"Enable GuardDuty in {region}",
                )
            else:
                yield self.passed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value=f"Detector {detector_id} present",
                )
