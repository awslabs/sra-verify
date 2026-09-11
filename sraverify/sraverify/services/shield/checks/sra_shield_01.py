"""
Check if Shield Advanced is enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_01(ShieldCheck):
    """Check if Shield Advanced is enabled."""

    meta = CheckMeta(
        check_id="SRA-SHIELD-01",
        title="Shield Advanced is enabled",
        description=(
            "This check verifies that AWS Shield Advanced is enabled. "
            "Shield Advanced provides enhanced DDoS protection for your AWS resources "
            "and includes 24/7 access to the AWS DDoS Response Team (DRT)."
        ),
        check_logic=(
            "Get Shield subscription state. Check fails if subscription is not active."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="Shield",
        resource_type="AWS::Shield::Subscription",
        remediation=Remediation(
            text="Enable Shield Advanced subscription in the AWS Shield console.",
            cli="aws shield create-subscription --region us-east-1",
            console=(
                "AWS WAF & Shield console, AWS Shield, Overview, "
                "Subscribe to Shield Advanced."
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
        status = self.get_subscription_status(region)

        if "Error" in status:
            error_code = status["Error"].get("Code", "")
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
                    actual_value=status["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for Shield API access"
                )
        elif status.get("SubscriptionState") == "ACTIVE":
            yield self.passed(
                region=region,
                resource_id="shield:subscription",
                actual_value="Shield Advanced is active"
            )
        else:
            yield self.failed(
                region=region,
                resource_id=None,
                actual_value=f"Subscription state: {status.get('SubscriptionState', 'Unknown')}",
                remediation="Enable Shield Advanced subscription in the AWS Shield console"
            )
