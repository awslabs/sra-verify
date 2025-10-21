"""
Check if Shield Advanced auto-renew is enabled.
"""
from typing import Dict, List, Any
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_02(ShieldCheck):
    """Check if Shield Advanced auto-renew is enabled."""

    def __init__(self):
        """Initialize Shield Advanced auto-renew check."""
        super().__init__()
        self.check_id = "SRA-SHIELD-02"
        self.check_name = "Shield Advanced auto-renew is enabled"
        self.description = ("This check verifies that AWS Shield Advanced subscription "
                           "has auto-renew enabled to ensure continuous protection.")
        self.severity = "MEDIUM"
        self.check_logic = "Get Shield subscription details. Check fails if auto-renew is disabled."

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """
        # Shield is a global service, check only in us-east-1
        region = "us-east-1"
        subscription = self.get_subscription_state(region)

        if "Error" in subscription:
            error_code = subscription["Error"].get("Code", "")
            if error_code == "ResourceNotFoundException":
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id=None,
                    actual_value="Shield Advanced not subscribed",
                    remediation="Enable Shield Advanced subscription in the AWS Shield console"
                ))
            else:
                self.findings.append(self.create_finding(
                    status="ERROR",
                    region=region,
                    resource_id=None,
                    actual_value=subscription["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for Shield API access"
                ))
        elif "Subscription" in subscription:
            auto_renew = subscription["Subscription"].get("AutoRenew", "")
            if auto_renew == "ENABLED":
                self.findings.append(self.create_finding(
                    status="PASS",
                    region=region,
                    resource_id="shield:subscription",
                    actual_value="Auto-renew is enabled",
                    remediation=""
                ))
            else:
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id="shield:subscription",
                    actual_value=f"Auto-renew is {auto_renew}",
                    remediation="Enable auto-renew for Shield Advanced subscription using UpdateSubscription API"
                ))
        else:
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=None,
                actual_value="Shield Advanced subscription not found",
                remediation="Enable Shield Advanced subscription in the AWS Shield console"
            ))

        return self.findings
