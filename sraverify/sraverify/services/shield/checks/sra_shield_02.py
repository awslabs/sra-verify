"""
Check if Shield Advanced auto-renew is enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_02(ShieldCheck):
    """Check if Shield Advanced auto-renew is enabled."""

    meta = CheckMeta(
        check_id="SRA-SHIELD-02",
        title="Shield Advanced auto-renew is enabled",
        description=(
            "This check verifies that AWS Shield Advanced subscription "
            "has auto-renew enabled to ensure continuous protection."
        ),
        check_logic=(
            "Get Shield subscription details. Check fails if auto-renew is disabled."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service="Shield",
        resource_type="AWS::Shield::Subscription",
        remediation=Remediation(
            text=(
                "Enable auto-renew for the Shield Advanced subscription using the "
                "UpdateSubscription API."
            ),
            cli=(
                "aws shield update-subscription --auto-renew ENABLED "
                "--region us-east-1"
            ),
            console=(
                "AWS WAF & Shield console, AWS Shield, Overview, Subscription, "
                "Edit, set Auto-renew to Enabled."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding for the Shield Advanced subscription.
        """
        # Shield is a global service, check only in us-east-1
        region = "us-east-1"
        subscription = self.get_subscription_state(region)

        if "Error" in subscription:
            error_code = subscription["Error"].get("Code", "")
            if error_code == "ResourceNotFoundException":
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
                    actual_value=subscription["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for Shield API access"
                )
        elif "Subscription" in subscription:
            auto_renew = subscription["Subscription"].get("AutoRenew", "")
            if auto_renew == "ENABLED":
                yield self.passed(
                    region=region,
                    resource_id="shield:subscription",
                    actual_value="Auto-renew is enabled"
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id="shield:subscription",
                    actual_value=f"Auto-renew is {auto_renew}",
                    remediation="Enable auto-renew for Shield Advanced subscription using UpdateSubscription API"
                )
        else:
            yield self.failed(
                region=region,
                resource_id=None,
                actual_value="Shield Advanced subscription not found",
                remediation="Enable Shield Advanced subscription in the AWS Shield console"
            )
