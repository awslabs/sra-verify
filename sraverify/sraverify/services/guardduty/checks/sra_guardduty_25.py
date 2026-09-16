"""
Check if GuardDuty RDS Login Events are configured for auto-enablement.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_25(GuardDutyCheck):
    """Check if GuardDuty RDS Login Events are configured for auto-enablement."""

    meta = CheckMeta(
        check_id="SRA-GUARDDUTY-25",
        title="GuardDuty RDS Login Events auto-enablement configured",
        description=(
            "This check verifies whether RDS Login Events are configured for auto-enablement "
            "in GuardDuty for all member accounts. RDS Login Events monitoring analyzes database "
            "login activity to detect potentially suspicious login attempts to RDS databases."
        ),
        check_logic=(
            "Check if RDS_LOGIN_EVENTS feature is configured with AutoEnable set to ALL."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.AUDIT,
        service="GuardDuty",
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(
            text=(
                "Set AutoEnable to ALL for the GuardDuty RDS_LOGIN_EVENTS feature in every "
                "enabled Region."
            ),
            cli=(
                "aws guardduty update-organization-configuration "
                "--detector-id <detector-id> "
                "--features Name=RDS_LOGIN_EVENTS,AutoEnable=ALL --region <region>"
            ),
            console=(
                "GuardDuty console in the delegated administrator account, Settings, "
                "Accounts, RDS Protection, Enable for all accounts."
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

            # Get organization configuration for GuardDuty
            org_config = self.get_organization_configuration(region)

            # Check if there was an error in the response
            if "Error" in org_config:
                error = org_config["Error"]
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value=(
                            "No GuardDuty delegated administrator is enabled "
                            "for this Region"
                        ),
                        remediation="Verify that GuardDuty is the delegated admin in this Region and run the check again.",
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
            # Check if RDS Login Events are configured for auto-enablement
            # Look for RDS_LOGIN_EVENTS in Features
            rds_login_events_found = False
            rds_login_events_auto_enable = "NOT_CONFIGURED"
            features = org_config.get('Features', [])

            for feature in features:
                if feature.get('Name') == 'RDS_LOGIN_EVENTS':
                    rds_login_events_found = True
                    rds_login_events_auto_enable = feature.get('AutoEnable', 'NONE')
                    break

            if rds_login_events_found and rds_login_events_auto_enable == 'ALL':
                yield self.passed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value="GuardDuty RDS Login Events are configured for auto-enablement for all accounts (AutoEnable=ALL)",
                )
            elif rds_login_events_found:
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value=f"GuardDuty RDS Login Events are configured with AutoEnable={rds_login_events_auto_enable}, but should be ALL",
                    remediation=f"Configure RDS Login Events auto-enablement for all accounts in {region} by setting AutoEnable to ALL",
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value=f"GuardDuty RDS Login Events feature is not configured",
                    remediation=f"Enable RDS Login Events feature and configure auto-enablement for all accounts in {region}",
                )
