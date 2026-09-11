"""
Check if GuardDuty member account limit is reached.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_16(GuardDutyCheck):
    """Check if GuardDuty member account limit is reached."""

    meta = CheckMeta(
        check_id="SRA-GUARDDUTY-16",
        title="GuardDuty member account limit not reached",
        description=(
            "This check verifies whether the maximum number of allowed member accounts are already "
            "associated with the delegated administrator account for the AWS Organization. "
            "Reaching the limit prevents adding new accounts to GuardDuty monitoring."
        ),
        check_logic=(
            "Check if MemberAccountLimitReached is false using "
            "describe-organization-configuration API."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.AUDIT,
        service="GuardDuty",
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(
            text=(
                "Contact AWS Support to request an increase in the GuardDuty member "
                "account limit for the affected Region."
            ),
            console=(
                "AWS Support Center, Create case, Service limit increase, "
                "Limit type Amazon GuardDuty."
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

            # Get organization configuration for GuardDuty
            org_config = self.get_organization_configuration(region)

            # Check if there was an error in the response
            if "Error" in org_config:
                error_code = org_config["Error"].get("Code", "Unknown")
                error_message = org_config["Error"].get("Message", "Unknown error")

                # Handle BadRequestException specifically for non-management accounts
                if error_code == "BadRequestException":
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value=f"{error_code} {error_message}",
                        remediation="Verify that GuardDuty is the delegated admin in this Region and run the check again.",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value=f"Error accessing GuardDuty organization configuration: {error_code}",
                        remediation="Check permissions and AWS Organizations configuration",
                    )
                continue

            # Check if member account limit is reached
            member_account_limit_reached = org_config.get('MemberAccountLimitReached', False)

            if not member_account_limit_reached:
                yield self.passed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value="GuardDuty member account limit is not reached",
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value="GuardDuty member account limit is reached",
                    remediation=f"Contact AWS Support to request an increase in the GuardDuty member account limit for {region}",
                )
