"""
SRA-SECURITYHUB-13: Configuration policies enable the AI Security Best Practices standard.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityhub.base import SecurityHubCheck

#: The Region-independent tail of the AI Security Best Practices standard ARN.
#: ``EnabledStandardIdentifiers`` carries full Region-qualified ARNs (observed
#: 2026-09-16), so the comparison has to ignore the Region segment.
AI_STANDARD_SUFFIX = "standards/ai-security-best-practices/v/1.0.0"


class SRA_SECURITYHUB_13(SecurityHubCheck):
    """Check if configuration policies enable the AI Security Best Practices standard."""

    meta = CheckMeta(
        check_id="SRA-SECURITYHUB-13",
        title="Security Hub configuration policies enable the AI Security Best Practices standard",
        description=(
            "This check verifies that every Security Hub central configuration policy that "
            "enables Security Hub also enables the AI Security Best Practices standard, so "
            "member accounts inherit it rather than each opting in. Configuration policies "
            "exist only in the delegated administrator's home Region, so the home Region is "
            "resolved from the finding aggregator and the policy APIs are called there. One row "
            "is produced per configuration policy."
        ),
        check_logic=(
            "Resolve the home Region from securityhub:ListFindingAggregators, then call "
            "securityhub:ListConfigurationPolicies and securityhub:GetConfigurationPolicy for "
            "each policy. Passes if ConfigurationPolicy.SecurityHub.EnabledStandardIdentifiers "
            "contains the AI standard ARN. Fails per policy without it, and once if no "
            "aggregator or no policy exists."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.AUDIT,
        service="SecurityHub",
        resource_type="AWS::SecurityHub::ConfigurationPolicy",
        remediation=Remediation(
            text=(
                "In the delegated administrator's home Region, update each configuration policy "
                "to include the AI Security Best Practices standard in its enabled standards."
            ),
            cli=(
                "aws securityhub update-configuration-policy --identifier <policy-arn> "
                "--configuration-policy '{\"SecurityHub\":{\"ServiceEnabled\":true,"
                "\"EnabledStandardIdentifiers\":[\"arn:aws:securityhub:<region>::"
                "standards/ai-security-best-practices/v/1.0.0\"]}}' "
                "--region <home-region>"
            ),
            console=(
                "Security Hub CSPM console in the delegated administrator account and home "
                "Region, Settings, Configuration, Policies, select the policy, Edit, add AI "
                "Security Best Practices under Standards."
            ),
        ),
        sra_sections=("Security Tooling account", "AWS Security Hub"),
        additional_urls=(
            "https://docs.aws.amazon.com/securityhub/latest/userguide/view-policy.html",
            "https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetConfigurationPolicy.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per configuration policy.
        """
        checked_value = (
            "Configuration policy EnabledStandardIdentifiers includes the AI "
            "Security Best Practices standard"
        )

        if not self._clients:
            yield self.failed(
                region="global",
                resource_id="securityhub:global",
                checked_value=checked_value,
                actual_value="Security Hub not available in any region",
                remediation="Enable Security Hub in at least one region",
            )
            return

        # The configuration-policy operations are delegated-administrator and
        # home-Region only: from any other Region the delegated administrator
        # itself is refused with 'Central Configuration APIs can only be called
        # from the aggregation region'. ListFindingAggregators answers from any
        # subscribed Region and its ARN carries the home Region, so it is asked
        # first rather than sweeping every Region and misreading the refusals.
        probe_region = self.regions[0]
        aggregators_response = self.get_finding_aggregators(probe_region)

        if "Error" in aggregators_response:
            error = aggregators_response["Error"]
            if self.is_not_configured(error):
                yield self.failed(
                    region="global",
                    resource_id=f"securityhub:configuration-policy/{self.account_id}",
                    checked_value=checked_value,
                    actual_value=(
                        f"Security Hub is not enabled in region {probe_region}, so no "
                        f"configuration policy enables the AI Security Best Practices "
                        f"standard"
                    ),
                    remediation=(
                        "Enable Security Hub in the delegated administrator account, "
                        "then enable central configuration"
                    ),
                )
            else:
                yield self.error(
                    region="global",
                    resource_id=f"securityhub:configuration-policy/{self.account_id}",
                    checked_value=checked_value,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
            return

        home_region = self.home_region_of(aggregators_response)

        if home_region and home_region not in self.regions:
            # The home Region is resolved from the aggregator ARN, so it can name
            # a Region the scan was never asked to cover -- and clients are only
            # built for self.regions. Asking an accessor for one anyway returns a
            # NoClient error result whose row ("Request failed: NoClient") says
            # nothing about why. Decide it here instead: no AWS call can change
            # the fact that the answer lives outside the scanned Regions, so this
            # guard belongs ahead of the calls.
            yield self.error(
                region="global",
                resource_id=f"securityhub:configuration-policy/{self.account_id}",
                checked_value=checked_value,
                actual_value=(
                    f"Security Hub central configuration is managed from home Region "
                    f"{home_region}, which is not among the scanned Regions "
                    f"({', '.join(self.regions)})"
                ),
                remediation=(
                    f"Re-run the check with {home_region} included in --regions so the "
                    f"configuration policies can be read from the home Region"
                ),
            )
            return

        if not home_region:
            # ListFindingAggregators succeeded and named no aggregator. AWS
            # answered: there is no aggregation Region, so central configuration
            # cannot be in use and no policy propagates the standard.
            yield self.failed(
                region="global",
                resource_id=f"securityhub:configuration-policy/{self.account_id}",
                checked_value=checked_value,
                actual_value=(
                    "No Security Hub finding aggregator exists, so there is no home "
                    "Region and central configuration is not in use"
                ),
                remediation=(
                    "Designate a home Region by creating a finding aggregator, enable "
                    "central configuration, then create a configuration policy that "
                    "enables the AI Security Best Practices standard"
                ),
            )
            return

        policies_response = self.get_configuration_policies(home_region)

        if "Error" in policies_response:
            error = policies_response["Error"]
            if self.is_not_configured(error):
                # The declared needle is 'with central configuration enabled',
                # which states central configuration is not in use. The other
                # AccessDeniedException message -- wrong Region -- is deliberately
                # undeclared and lands in the ERROR arm below.
                yield self.failed(
                    region=home_region,
                    resource_id=f"securityhub:configuration-policy/{self.account_id}",
                    checked_value=checked_value,
                    actual_value=(
                        "Security Hub central configuration is not enabled for this "
                        "account, so no configuration policy exists"
                    ),
                    remediation=(
                        "Enable Security Hub central configuration from the delegated "
                        "administrator account, then create a configuration policy that "
                        "enables the AI Security Best Practices standard"
                    ),
                )
            else:
                yield self.error(
                    region=home_region,
                    resource_id=f"securityhub:configuration-policy/{self.account_id}",
                    checked_value=checked_value,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
            return

        summaries = policies_response.get('ConfigurationPolicySummaries', [])

        if not summaries:
            yield self.failed(
                region=home_region,
                resource_id=f"securityhub:configuration-policy/{self.account_id}",
                checked_value=checked_value,
                actual_value=(
                    f"No Security Hub configuration policies exist in home Region "
                    f"{home_region}"
                ),
                remediation=(
                    f"Create a configuration policy in {home_region} that enables the "
                    f"AI Security Best Practices standard and associate it with the root"
                ),
            )
            return

        # One row per policy. A policy that leaves Security Hub disabled enables
        # no standards by definition, so it is reported as its own FAIL rather
        # than silently skipped.
        for summary in sorted(summaries, key=lambda s: s.get("Arn", "")):
            policy_arn = summary.get("Arn", "Unknown")
            policy_name = summary.get("Name", "Unknown")

            policy_response = self.get_configuration_policy(home_region, policy_arn)

            # Inside the per-policy loop, so one undetermined policy costs one row
            # rather than the whole check's output.
            if "Error" in policy_response:
                error = policy_response["Error"]
                if self.is_not_configured(error):
                    yield self.failed(
                        region=home_region,
                        resource_id=policy_arn,
                        checked_value=checked_value,
                        actual_value=(
                            f"Configuration policy {policy_name} is no longer present"
                        ),
                    )
                else:
                    yield self.error(
                        region=home_region,
                        resource_id=policy_arn,
                        checked_value=checked_value,
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            security_hub_policy = (
                policy_response.get('ConfigurationPolicy') or {}
            ).get('SecurityHub') or {}

            if not security_hub_policy.get('ServiceEnabled'):
                yield self.failed(
                    region=home_region,
                    resource_id=policy_arn,
                    checked_value=checked_value,
                    actual_value=(
                        f"Configuration policy {policy_name} leaves Security Hub "
                        f"disabled, so it enables no standards"
                    ),
                    remediation=(
                        f"Set ServiceEnabled to true on configuration policy "
                        f"{policy_name} and add the AI Security Best Practices standard"
                    ),
                )
                continue

            identifiers = security_hub_policy.get('EnabledStandardIdentifiers') or []
            ai_standard_enabled = any(
                identifier.endswith(AI_STANDARD_SUFFIX) for identifier in identifiers
            )

            standard_names = sorted(
                self.standard_name_of(identifier) for identifier in identifiers
            )
            standards_list = ', '.join(standard_names) if standard_names else "None"

            if ai_standard_enabled:
                yield self.passed(
                    region=home_region,
                    resource_id=policy_arn,
                    checked_value=checked_value,
                    actual_value=(
                        f"Configuration policy {policy_name} enables the AI Security "
                        f"Best Practices standard. Enabled standards: {standards_list}"
                    ),
                )
            else:
                yield self.failed(
                    region=home_region,
                    resource_id=policy_arn,
                    checked_value=checked_value,
                    actual_value=(
                        f"Configuration policy {policy_name} does not enable the AI "
                        f"Security Best Practices standard. Enabled standards: "
                        f"{standards_list}"
                    ),
                    remediation=(
                        f"Add the AI Security Best Practices standard to configuration "
                        f"policy {policy_name} in {home_region}"
                    ),
                )
