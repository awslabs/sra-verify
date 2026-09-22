"""
Check if GuardDuty AI Protection is configured for auto-enablement.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_26(GuardDutyCheck):
    """Check if GuardDuty AI Protection is configured for auto-enablement."""

    meta = CheckMeta(
        check_id="SRA-GUARDDUTY-26",
        title="GuardDuty AI Protection auto-enablement configured",
        description=(
            "This check verifies that GuardDuty AI Protection is configured to be automatically "
            "enabled for all accounts in the organization. AI Protection analyzes Amazon "
            "Bedrock, Bedrock AgentCore and SageMaker AI data events and management events to "
            "detect misuse of AI resources. When the delegated administrator sets AutoEnable to "
            "ALL, every existing member account and every account that joins later is covered "
            "without per-account action."
        ),
        check_logic=(
            "Check if AI_PROTECTION feature in the GuardDuty organization configuration has "
            "AutoEnable set to ALL."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.AUDIT,
        service="GuardDuty",
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(
            text=(
                "In the GuardDuty delegated administrator account, set AI Protection "
                "auto-enablement to ALL for the organization in every enabled Region."
            ),
            cli=(
                "aws guardduty update-organization-configuration "
                "--detector-id <detector-id> "
                "--features Name=AI_PROTECTION,AutoEnable=ALL --region <region>"
            ),
            console=(
                "GuardDuty console in the delegated administrator account, Settings, Accounts, "
                "Auto-enable, AI Protection, Enable for all accounts. Repeat per Region."
            ),
        ),
        sra_sections=("Security Tooling account", "Amazon GuardDuty"),
        additional_urls=(
            "https://docs.aws.amazon.com/guardduty/latest/ug/ai-protection.html",
            "https://docs.aws.amazon.com/guardduty/latest/APIReference/API_OrganizationFeatureConfiguration.html",
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
                # ListDetectors succeeded and named no detector: GuardDuty is not
                # enabled in this Region. AWS answered, and the answer is that the
                # control is absent, which is a FAIL.
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}",
                    actual_value="No GuardDuty detector in this Region",
                    remediation=f"Enable GuardDuty in {region}",
                )
                continue

            org_config = self.get_organization_configuration(region)

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
                        remediation=(
                            "Verify that GuardDuty is the delegated admin in this "
                            "Region and run the check again."
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

            # A feature the organization has never configured is absent from
            # Features[] rather than present with AutoEnable=NONE, so an absent
            # entry has to be a FAIL. A loop cannot find a missing record unless
            # it is told that finding nothing is non-compliant.
            ai_protection_found = False
            ai_protection_auto_enable = "NOT_CONFIGURED"
            features = org_config.get('Features', [])

            for feature in features:
                if feature.get('Name') == 'AI_PROTECTION':
                    ai_protection_found = True
                    ai_protection_auto_enable = feature.get('AutoEnable', 'NONE')
                    break

            if ai_protection_found and ai_protection_auto_enable == 'ALL':
                yield self.passed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value=(
                        "GuardDuty AI Protection is configured for auto-enablement "
                        "for all accounts (AutoEnable=ALL)"
                    ),
                )
            elif ai_protection_found:
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value=(
                        f"GuardDuty AI Protection is configured with "
                        f"AutoEnable={ai_protection_auto_enable}, but should be ALL"
                    ),
                    remediation=(
                        f"Configure AI Protection auto-enablement for all accounts in "
                        f"{region} by setting AutoEnable to ALL"
                    ),
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value="GuardDuty AI Protection feature is not configured",
                    remediation=(
                        f"Enable the AI Protection feature and configure "
                        f"auto-enablement for all accounts in {region}"
                    ),
                )
