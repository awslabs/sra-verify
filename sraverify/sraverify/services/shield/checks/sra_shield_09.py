"""
Check if Shield Advanced proactive engagement is enabled.
"""
from typing import Dict, List, Any
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_09(ShieldCheck):
    """Check if Shield Advanced proactive engagement is enabled."""

    def __init__(self):
        """Initialize Shield Advanced proactive engagement check."""
        super().__init__()
        self.check_id = "SRA-SHIELD-09"
        self.check_name = "Shield Advanced proactive engagement is enabled"
        self.description = ("This check verifies that AWS Shield Advanced proactive engagement "
                            "is enabled, allowing the Shield Response Team to contact you directly during attacks.")
        self.severity = "MEDIUM"
        self.check_logic = ("Get Shield subscription details and check ProactiveEngagementStatus. "
                            "Check fails if proactive engagement is disabled.")

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
            proactive_status = subscription["Subscription"].get("ProactiveEngagementStatus", "")
            if proactive_status == "ENABLED":
                self.findings.append(self.create_finding(
                    status="PASS",
                    region=region,
                    resource_id="shield:proactive-engagement",
                    actual_value="Proactive engagement is enabled",
                    remediation=""
                ))
            elif proactive_status == "PENDING":
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id="shield:proactive-engagement",
                    actual_value="Proactive engagement is pending",
                    remediation="Complete proactive engagement setup by providing emergency contacts"
                ))
            else:
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id="shield:proactive-engagement",
                    actual_value=f"Proactive engagement is {proactive_status or 'disabled'}",
                    remediation="Enable proactive engagement using EnableProactiveEngagement API and configure emergency contacts"
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
