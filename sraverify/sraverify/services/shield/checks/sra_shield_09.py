"""
Check if Shield Advanced proactive engagement is enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_09(ShieldCheck):
    """Check if Shield Advanced proactive engagement is enabled."""

    meta = CheckMeta(
        check_id="SRA-SHIELD-09",
        title="Shield Advanced proactive engagement is enabled",
        description=(
            "This check verifies that AWS Shield Advanced proactive engagement "
            "is enabled, allowing the Shield Response Team to contact you directly during attacks."
        ),
        check_logic=(
            "Get Shield subscription details and check ProactiveEngagementStatus. "
            "Check fails if proactive engagement is disabled."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service="Shield",
        resource_type="AWS::Shield::Subscription",
        remediation=Remediation(
            text=(
                "Enable proactive engagement using the EnableProactiveEngagement API "
                "and configure emergency contacts."
            ),
            cli=(
                "aws shield associate-proactive-engagement-details "
                "--emergency-contact-list "
                "EmailAddress=<email>,PhoneNumber=<phone>,ContactNotes=<notes> "
                "--region us-east-1 && aws shield enable-proactive-engagement "
                "--region us-east-1"
            ),
            console=(
                "AWS WAF & Shield console, AWS Shield, Overview, "
                "Proactive engagement, Edit, Enable, add emergency contacts."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding for the proactive engagement configuration.
        """
        # Shield is a global service, check only in us-east-1
        region = "us-east-1"
        subscription = self.get_subscription_state(region)

        if "Error" in subscription:
            error = subscription["Error"]
            if self.is_not_configured(error):
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value="Shield Advanced not subscribed",
                    remediation="Enable Shield Advanced subscription in the AWS Shield console"
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
        elif "Subscription" in subscription:
            proactive_status = subscription["Subscription"].get("ProactiveEngagementStatus", "")
            if proactive_status == "ENABLED":
                yield self.passed(
                    region=region,
                    resource_id="shield:proactive-engagement",
                    actual_value="Proactive engagement is enabled"
                )
            elif proactive_status == "PENDING":
                yield self.failed(
                    region=region,
                    resource_id="shield:proactive-engagement",
                    actual_value="Proactive engagement is pending",
                    remediation="Complete proactive engagement setup by providing emergency contacts"
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id="shield:proactive-engagement",
                    actual_value=f"Proactive engagement is {proactive_status or 'disabled'}",
                    remediation="Enable proactive engagement using EnableProactiveEngagement API and configure emergency contacts"
                )
        else:
            yield self.failed(
                region=region,
                resource_id=None,
                actual_value="Shield Advanced subscription not found",
                remediation="Enable Shield Advanced subscription in the AWS Shield console"
            )
