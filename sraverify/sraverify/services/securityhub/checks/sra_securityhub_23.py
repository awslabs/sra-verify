"""
SRA-SECURITYHUB-23: Security Hub CSPM AWS Foundational Security Best Practices standard is enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityhub.base import SecurityHubCheck

#: The Region-independent tail of the FSBP standard ARN. The full ARN embeds the
#: Region (``arn:aws:securityhub:us-east-1::standards/
#: aws-foundational-security-best-practices/v/1.0.0``), so a whole-ARN comparison
#: would only ever match one Region.
FSBP_STANDARD_SUFFIX = "standards/aws-foundational-security-best-practices/v/1.0.0"

#: The only ``StandardsStatus`` in which the standard is actually evaluating.
FSBP_STANDARD_READY = "READY"

#: Statuses a subscription passes *through* rather than settles in; they earn
#: re-run-later wording rather than re-enable wording.
TRANSIENT_STANDARD_STATUSES = frozenset({"PENDING", "DELETING"})


class SRA_SECURITYHUB_23(SecurityHubCheck):
    """Check if the Security Hub CSPM FSBP standard is enabled and READY."""

    meta = CheckMeta(
        check_id="SRA-SECURITYHUB-23",
        title="Security Hub CSPM AWS Foundational Security Best Practices standard is enabled",
        description=(
            "This check verifies that the AWS Foundational Security Best Practices standard "
            "(aws-foundational-security-best-practices/v/1.0.0) is among the enabled Security "
            "Hub CSPM standards in each Region and that its subscription is READY. "
            "SRA-SECURITYHUB-01 passes on any standard, so an account subscribed only to a "
            "vendor or industry standard passes it while the AWS baseline is unevaluated. A "
            "FAILED or INCOMPLETE subscription carries the standard's ARN while evaluating "
            "nothing, or only part of the standard."
        ),
        check_logic=(
            "Call securityhub:GetEnabledStandards in each Region and read "
            "StandardsSubscriptions[]. Passes if a subscription's StandardsArn ends with "
            "standards/aws-foundational-security-best-practices/v/1.0.0 and its "
            "StandardsStatus is READY. Fails if that subscription is absent, if its status is "
            "anything else, or if Security Hub CSPM is not enabled in the Region."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="Security Hub CSPM",
        resource_type="AWS::SecurityHub::Standard",
        remediation=Remediation(
            text=(
                "Enable the AWS Foundational Security Best Practices standard in every Region "
                "where Security Hub CSPM is enabled, or add it to the central configuration "
                "policy so members inherit it."
            ),
            cli=(
                "aws securityhub batch-enable-standards --standards-subscription-requests "
                "'StandardsArn=arn:aws:securityhub:<region>::standards/"
                "aws-foundational-security-best-practices/v/1.0.0' --region <region>"
            ),
            console=(
                "Security Hub CSPM console, Security standards, AWS Foundational Security Best "
                "Practices, Enable. Repeat per Region, or edit the configuration policy in the "
                "delegated administrator's home Region."
            ),
        ),
        sra_sections=("Security Tooling account", "AWS Security Hub CSPM"),
        additional_urls=(
            "https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html",
            "https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetEnabledStandards.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Region.
        """
        checked_value = "AWS Foundational Security Best Practices standard is enabled and READY"

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

            # "Security Hub is not subscribed here" is an InvalidAccessException
            # the discriminator recognizes; every other failure is an ERROR.
            if "Error" in standards_response:
                error = standards_response["Error"]
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"securityhub:standards/{self.account_id}",
                        checked_value=checked_value,
                        actual_value=(
                            f"Security Hub CSPM is not enabled in region {region}, so the "
                            f"AWS Foundational Security Best Practices standard is not enabled"
                        ),
                        remediation=(
                            f"Enable Security Hub CSPM in {region}, then enable the AWS "
                            f"Foundational Security Best Practices standard"
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

            fsbp_subscription = None
            standard_names = []
            for standard in enabled_standards:
                standard_arn = standard.get('StandardsArn', '')
                if standard_arn.endswith(FSBP_STANDARD_SUFFIX):
                    fsbp_subscription = standard
                standard_names.append(self.standard_name_of(standard_arn))

            standards_list = ', '.join(sorted(standard_names)) if standard_names else "None"

            if fsbp_subscription is None:
                yield self.failed(
                    region=region,
                    resource_id=f"securityhub:standards/{self.account_id}",
                    checked_value=checked_value,
                    actual_value=(
                        f"Account {self.account_id} region {region} does not have the AWS "
                        f"Foundational Security Best Practices standard enabled. Enabled "
                        f"standards: {standards_list}"
                    ),
                    remediation=(
                        f"Enable the AWS Foundational Security Best Practices standard in "
                        f"{region}: aws securityhub batch-enable-standards "
                        f"--standards-subscription-requests "
                        f"'StandardsArn=arn:aws:securityhub:{region}::"
                        f"standards/aws-foundational-security-best-practices/v/1.0.0' "
                        f"--region {region}"
                    ),
                )
                continue

            status = fsbp_subscription.get('StandardsStatus') or 'UNKNOWN'

            if status == FSBP_STANDARD_READY:
                yield self.passed(
                    region=region,
                    resource_id=f"securityhub:standards/{self.account_id}",
                    checked_value=checked_value,
                    actual_value=(
                        f"Account {self.account_id} region {region} has the AWS "
                        f"Foundational Security Best Practices standard enabled and READY. "
                        f"Enabled standards: {standards_list}"
                    ),
                )
                continue

            reason_code = (
                fsbp_subscription.get('StandardsStatusReason') or {}
            ).get('StatusReasonCode')
            reason = f", reason {reason_code}" if reason_code else ""

            if status in TRANSIENT_STANDARD_STATUSES:
                remediation = (
                    f"The AWS Foundational Security Best Practices subscription in {region} "
                    f"is {status}; re-run the check once it settles, and if it does not "
                    f"reach READY, re-enable the standard"
                )
            else:
                remediation = (
                    f"Investigate the AWS Foundational Security Best Practices subscription "
                    f"in {region} (status {status}{reason}), then re-enable the standard: "
                    f"aws securityhub batch-enable-standards "
                    f"--standards-subscription-requests "
                    f"'StandardsArn=arn:aws:securityhub:{region}::"
                    f"standards/aws-foundational-security-best-practices/v/1.0.0' "
                    f"--region {region}"
                )

            yield self.failed(
                region=region,
                resource_id=f"securityhub:standards/{self.account_id}",
                checked_value=checked_value,
                actual_value=(
                    f"Account {self.account_id} region {region} has the AWS Foundational "
                    f"Security Best Practices standard subscribed but its status is "
                    f"{status}, not READY{reason}, so the standard is not evaluating"
                ),
                remediation=remediation,
            )
