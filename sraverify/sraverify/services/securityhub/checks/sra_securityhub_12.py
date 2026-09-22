"""
SRA-SECURITYHUB-12: AI Security Best Practices standard is enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityhub.base import SecurityHubCheck

#: The Region-independent tail of the AI Security Best Practices standard ARN.
#: The full ARN embeds the Region (``arn:aws:securityhub:us-east-1::standards/
#: ai-security-best-practices/v/1.0.0``), so a whole-ARN comparison would only
#: ever match one Region. The ``standards/`` prefix is part of the literal so
#: that a standard whose name merely ends in ``ai-security-best-practices``
#: cannot match.
AI_STANDARD_SUFFIX = "standards/ai-security-best-practices/v/1.0.0"

#: The only ``StandardsStatus`` in which the standard is actually evaluating.
#: The full enum is ``PENDING``, ``READY``, ``FAILED``, ``DELETING`` and
#: ``INCOMPLETE``, and every one of the other four carries the standard's ARN in
#: ``StandardsSubscriptions`` while the standard is not running -- ``FAILED`` can
#: sit there indefinitely, and ``INCOMPLETE`` means only some of the standard's
#: controls came up. Testing the ARN alone therefore reported a control that
#: evaluates nothing as PASS.
AI_STANDARD_READY = "READY"

#: Statuses a subscription passes *through* rather than settles in. They earn
#: different remediation wording: telling someone to re-enable a standard that is
#: mid-propagation is wrong advice, and a live run showed a policy-driven
#: subscription sitting at ``PENDING`` for well under two minutes before reaching
#: ``READY``.
TRANSIENT_STANDARD_STATUSES = frozenset({"PENDING", "DELETING"})


class SRA_SECURITYHUB_12(SecurityHubCheck):
    """Check if the Security Hub AI Security Best Practices standard is enabled."""

    meta = CheckMeta(
        check_id="SRA-SECURITYHUB-12",
        title="Security Hub AI Security Best Practices standard is enabled",
        description=(
            "This check verifies that the AI Security Best Practices standard "
            "(ai-security-best-practices/v/1.0.0) is among the enabled Security Hub CSPM "
            "standards in each Region. The standard evaluates Amazon Bedrock, Bedrock "
            "AgentCore and SageMaker AI resources for encryption, network isolation and "
            "access configuration. It is never enabled automatically, so an account passes "
            "SRA-SECURITYHUB-01 with any standard while leaving AI resources unevaluated. "
            "The subscription must also be READY: a subscription in FAILED or INCOMPLETE "
            "carries the standard's ARN while evaluating nothing, or only part of the "
            "standard."
        ),
        check_logic=(
            "Call securityhub:GetEnabledStandards in each Region and read "
            "StandardsSubscriptions[]. Check passes if a subscription's StandardsArn ends "
            "with standards/ai-security-best-practices/v/1.0.0 and its StandardsStatus is "
            "READY. Fails if that subscription is absent, if its status is anything else, "
            "or if Security Hub is not enabled in the Region."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="SecurityHub",
        resource_type="AWS::SecurityHub::Standard",
        remediation=Remediation(
            text=(
                "Enable the AI Security Best Practices standard in every Region where Security "
                "Hub is enabled, or add it to the central configuration policy so members "
                "inherit it."
            ),
            cli=(
                "aws securityhub batch-enable-standards --standards-subscription-requests "
                "'StandardsArn=arn:aws:securityhub:<region>::standards/"
                "ai-security-best-practices/v/1.0.0' --region <region>"
            ),
            console=(
                "Security Hub CSPM console, Security standards, AI Security Best Practices, "
                "Enable. Repeat per Region."
            ),
        ),
        sra_sections=("Security Tooling account", "AWS Security Hub"),
        additional_urls=(
            "https://docs.aws.amazon.com/securityhub/latest/userguide/standards-ai-security.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Region.
        """
        checked_value = "AI Security Best Practices standard is enabled and READY"

        if not self._clients:
            yield self.failed(
                region="global",
                resource_id="securityhub:global",
                checked_value=checked_value,
                actual_value="Security Hub not available in any region",
                remediation="Enable Security Hub in at least one region",
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
                            f"Security Hub is not enabled in region {region}, so the "
                            f"AI Security Best Practices standard is not enabled"
                        ),
                        remediation=(
                            f"Enable Security Hub in {region}, then enable the AI "
                            f"Security Best Practices standard"
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

            # Keep the whole subscription, not just a boolean: its StandardsStatus
            # decides the verdict as much as its presence does.
            ai_subscription = None
            standard_names = []
            for standard in enabled_standards:
                standard_arn = standard.get('StandardsArn', '')
                if standard_arn.endswith(AI_STANDARD_SUFFIX):
                    ai_subscription = standard
                standard_names.append(self.standard_name_of(standard_arn))

            standards_list = ', '.join(sorted(standard_names)) if standard_names else "None"

            if ai_subscription is None:
                yield self.failed(
                    region=region,
                    resource_id=f"securityhub:standards/{self.account_id}",
                    checked_value=checked_value,
                    actual_value=(
                        f"Account {self.account_id} region {region} does not have the AI "
                        f"Security Best Practices standard enabled. Enabled standards: "
                        f"{standards_list}"
                    ),
                    remediation=(
                        f"Enable the AI Security Best Practices standard in {region}: "
                        f"aws securityhub batch-enable-standards "
                        f"--standards-subscription-requests "
                        f"'StandardsArn=arn:aws:securityhub:{region}::"
                        f"standards/ai-security-best-practices/v/1.0.0' --region {region}"
                    ),
                )
                continue

            status = ai_subscription.get('StandardsStatus') or 'UNKNOWN'

            if status == AI_STANDARD_READY:
                yield self.passed(
                    region=region,
                    resource_id=f"securityhub:standards/{self.account_id}",
                    checked_value=checked_value,
                    actual_value=(
                        f"Account {self.account_id} region {region} has the AI Security "
                        f"Best Practices standard enabled and READY. Enabled standards: "
                        f"{standards_list}"
                    ),
                )
                continue

            # AWS answered, and the answer is that the standard is subscribed but
            # not evaluating, which is a FAIL rather than an inability to
            # determine. The reason code is what makes it triageable -- an
            # absent configuration recorder and an exceeded Config rule quota are
            # different problems that both surface as FAILED.
            reason_code = (
                ai_subscription.get('StandardsStatusReason') or {}
            ).get('StatusReasonCode')
            reason = f", reason {reason_code}" if reason_code else ""

            if status in TRANSIENT_STANDARD_STATUSES:
                remediation = (
                    f"The AI Security Best Practices subscription in {region} is "
                    f"{status}; re-run the check once it settles, and if it does not "
                    f"reach READY, re-enable the standard"
                )
            else:
                remediation = (
                    f"Investigate the AI Security Best Practices subscription in "
                    f"{region} (status {status}{reason}), then re-enable the standard: "
                    f"aws securityhub batch-enable-standards "
                    f"--standards-subscription-requests "
                    f"'StandardsArn=arn:aws:securityhub:{region}::"
                    f"standards/ai-security-best-practices/v/1.0.0' --region {region}"
                )

            yield self.failed(
                region=region,
                resource_id=f"securityhub:standards/{self.account_id}",
                checked_value=checked_value,
                actual_value=(
                    f"Account {self.account_id} region {region} has the AI Security "
                    f"Best Practices standard subscribed but its status is {status}, "
                    f"not READY{reason}, so the standard is not evaluating"
                ),
                remediation=remediation,
            )
