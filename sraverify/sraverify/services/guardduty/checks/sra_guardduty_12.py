"""
Check if GuardDuty has Lambda protection enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_12(GuardDutyCheck):
    """Check if GuardDuty has Lambda protection enabled."""

    meta = CheckMeta(
        check_id="SRA-GUARDDUTY-12",
        title="GuardDuty Lambda protection enabled",
        description=(
            "This check verifies that GuardDuty Lambda protection is enabled. "
            "Lambda Protection helps identify potential security threats when an AWS Lambda "
            "function gets invoked in the AWS environment."
        ),
        check_logic=(
            "Get detector details in each Region. "
            "Check if Lambda protection is enabled in the Features array."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="GuardDuty",
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(
            text="Enable Lambda Protection for GuardDuty in every enabled Region.",
            cli=(
                "aws guardduty update-detector --detector-id <detector-id> "
                "--features Name=LAMBDA_NETWORK_LOGS,Status=ENABLED --region <region>"
            ),
            console=(
                "GuardDuty console, Settings, Protection plans, Lambda Protection, Enable."
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
                # Check if Lambda protection is enabled in the Features array
                lambda_protection_enabled = False
                features = detector_details.get('Features', [])

                for feature in features:
                    if feature.get('Name') == 'LAMBDA_NETWORK_LOGS' and feature.get('Status') == 'ENABLED':
                        lambda_protection_enabled = True
                        break

                if lambda_protection_enabled:
                    yield self.passed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value="Lambda protection is enabled",
                    )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value="Lambda protection is not enabled",
                        remediation=f"Enable Lambda protection for GuardDuty in {region} to identify potential security threats in Lambda function invocations",
                    )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value="Unable to retrieve detector details",
                    remediation="Check GuardDuty permissions and configuration",
                )
