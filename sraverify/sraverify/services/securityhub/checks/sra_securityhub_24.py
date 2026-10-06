"""
SRA-SECURITYHUB-24: Security Hub CSPM CIS AWS Foundations Benchmark standard is enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityhub.base import SecurityHubCheck

#: Present in every CIS AWS Foundations Benchmark ARN. Matched with ``in``
#: rather than ``endswith`` because the version varies (v5.0.0, v3.0.0, v1.4.0
#: under ``standards/``) and the legacy v1.2.0 ARN uses ``ruleset/``.
CIS_STANDARD_MARKER = "cis-aws-foundations-benchmark/v/"

#: The only ``StandardsStatus`` in which a standard is actually evaluating.
CIS_STANDARD_READY = "READY"

#: Statuses a subscription passes *through* rather than settles in.
TRANSIENT_STANDARD_STATUSES = frozenset({"PENDING", "DELETING"})

#: The version the remediation recommends.
CIS_RECOMMENDED_SUFFIX = "standards/cis-aws-foundations-benchmark/v/5.0.0"


class SRA_SECURITYHUB_24(SecurityHubCheck):
    """Check if a CIS AWS Foundations Benchmark version is enabled and READY."""

    meta = CheckMeta(
        check_id="SRA-SECURITYHUB-24",
        title="Security Hub CSPM CIS AWS Foundations Benchmark standard is enabled",
        description=(
            "This check verifies that a version of the CIS AWS Foundations Benchmark is among "
            "the enabled Security Hub CSPM standards in each Region and that at least one such "
            "subscription is READY. Any supported version counts: v5.0.0, v3.0.0 and v1.4.0 "
            "use standards ARNs, and the legacy v1.2.0 uses a ruleset ARN. A subscription in "
            "FAILED or INCOMPLETE carries the ARN while evaluating nothing, or only part of "
            "the benchmark."
        ),
        check_logic=(
            "Call securityhub:GetEnabledStandards in each Region and read "
            "StandardsSubscriptions[]. Passes if a subscription's StandardsArn contains "
            "cis-aws-foundations-benchmark/v/ and its StandardsStatus is READY. Fails if no "
            "such subscription exists, if none is READY, or if Security Hub CSPM is not "
            "enabled in the Region, naming every CIS version found and its status."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service="Security Hub CSPM",
        resource_type="AWS::SecurityHub::Standard",
        remediation=Remediation(
            text=(
                "Enable a CIS AWS Foundations Benchmark version in every Region where Security "
                "Hub CSPM is enabled, or add it to the central configuration policy so members "
                "inherit it."
            ),
            cli=(
                "aws securityhub batch-enable-standards --standards-subscription-requests "
                "'StandardsArn=arn:aws:securityhub:<region>::standards/"
                "cis-aws-foundations-benchmark/v/5.0.0' --region <region>"
            ),
            console=(
                "Security Hub CSPM console, Security standards, CIS AWS Foundations Benchmark "
                "v5.0.0, Enable. Repeat per Region, or edit the configuration policy in the "
                "delegated administrator's home Region."
            ),
        ),
        sra_sections=("Security Tooling account", "AWS Security Hub CSPM"),
        additional_urls=(
            "https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html",
            "https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetEnabledStandards.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Region.
        """
        checked_value = "A CIS AWS Foundations Benchmark standard is enabled and READY"

        if not self._clients:
            yield self.failed(
                region="global",
                resource_id="securityhub:global",
                checked_value=checked_value,
                actual_value="Security Hub CSPM not available in any region",
                remediation="Enable Security Hub CSPM in at least one region",
            )
            return

        for region in self.regions:
            standards_response = self.get_enabled_standards(region)

            if "Error" in standards_response:
                error = standards_response["Error"]
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"securityhub:standards/{self.account_id}",
                        checked_value=checked_value,
                        actual_value=(
                            f"Security Hub CSPM is not enabled in region {region}, so no CIS "
                            f"AWS Foundations Benchmark standard is enabled"
                        ),
                        remediation=(
                            f"Enable Security Hub CSPM in {region}, then enable a CIS AWS "
                            f"Foundations Benchmark standard"
                        ),
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"securityhub:standards/{self.account_id}",
                        checked_value=checked_value,
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            enabled_standards = standards_response.get('StandardsSubscriptions', [])

            standard_names = sorted(
                self.standard_name_of(standard.get('StandardsArn', ''))
                for standard in enabled_standards
            )
            standards_list = ', '.join(standard_names) if standard_names else "None"

            cis_subscriptions = sorted(
                (
                    standard
                    for standard in enabled_standards
                    if CIS_STANDARD_MARKER in standard.get('StandardsArn', '')
                ),
                key=lambda standard: standard.get('StandardsArn', ''),
            )
            cis_list = ', '.join(
                f"{self.standard_name_of(standard.get('StandardsArn', ''))} "
                f"{standard.get('StandardsStatus') or 'UNKNOWN'}"
                for standard in cis_subscriptions
            ) or "none"
            listing = f"Enabled standards: {standards_list}; CIS: {cis_list}"

            enable_cli = (
                f"aws securityhub batch-enable-standards --standards-subscription-requests "
                f"'StandardsArn=arn:aws:securityhub:{region}::{CIS_RECOMMENDED_SUFFIX}' "
                f"--region {region}"
            )

            if not cis_subscriptions:
                yield self.failed(
                    region=region,
                    resource_id=f"securityhub:standards/{self.account_id}",
                    checked_value=checked_value,
                    actual_value=(
                        f"Account {self.account_id} region {region} has no CIS AWS "
                        f"Foundations Benchmark version enabled. {listing}"
                    ),
                    remediation=(
                        f"Enable a CIS AWS Foundations Benchmark standard in {region}: "
                        f"{enable_cli}"
                    ),
                )
                continue

            if any(
                standard.get('StandardsStatus') == CIS_STANDARD_READY
                for standard in cis_subscriptions
            ):
                yield self.passed(
                    region=region,
                    resource_id=f"securityhub:standards/{self.account_id}",
                    checked_value=checked_value,
                    actual_value=(
                        f"Account {self.account_id} region {region} has a CIS AWS "
                        f"Foundations Benchmark standard enabled and READY. {listing}"
                    ),
                )
                continue

            # Every CIS subscription is subscribed but not evaluating. AWS
            # answered, so this is a FAIL rather than an inability to determine.
            if all(
                (standard.get('StandardsStatus') or 'UNKNOWN') in TRANSIENT_STANDARD_STATUSES
                for standard in cis_subscriptions
            ):
                remediation = (
                    f"Every CIS AWS Foundations Benchmark subscription in {region} is "
                    f"PENDING or DELETING; re-run the check once it settles, and if none "
                    f"reaches READY, re-enable the standard"
                )
                reason = ""
            else:
                first = cis_subscriptions[0]
                reason_code = (
                    first.get('StandardsStatusReason') or {}
                ).get('StatusReasonCode')
                reason = f", reason {reason_code}" if reason_code else ""
                remediation = (
                    f"Investigate the CIS AWS Foundations Benchmark subscriptions in "
                    f"{region} ({cis_list}{reason}), then re-enable the standard: "
                    f"{enable_cli}"
                )

            yield self.failed(
                region=region,
                resource_id=f"securityhub:standards/{self.account_id}",
                checked_value=checked_value,
                actual_value=(
                    f"Account {self.account_id} region {region} has a CIS AWS Foundations "
                    f"Benchmark standard subscribed but none is READY{reason}, so the "
                    f"benchmark is not evaluating. {listing}"
                ),
                remediation=remediation,
            )
