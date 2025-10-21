"""
Check if Shield Advanced is enabled.
"""
from typing import Dict, List, Any
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_01(ShieldCheck):
    """Check if Shield Advanced is enabled."""

    def __init__(self):
        """Initialize Shield Advanced enabled check."""
        super().__init__()
        self.check_id = "SRA-SHIELD-01"
        self.check_name = "Shield Advanced is enabled"
        self.description = ("This check verifies that AWS Shield Advanced is enabled. "
                           "Shield Advanced provides enhanced DDoS protection for your AWS resources "
                           "and includes 24/7 access to the AWS DDoS Response Team (DRT).")
        self.severity = "HIGH"
        self.check_logic = "Get Shield subscription state. Check fails if subscription is not active."

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """
        # Shield is a global service, check only in us-east-1
        region = "us-east-1"
        status = self.get_subscription_status(region)

        if "Error" in status:
            error_code = status["Error"].get("Code", "")
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
                    actual_value=status["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for Shield API access"
                ))
        elif status.get("SubscriptionState") == "ACTIVE":
            self.findings.append(self.create_finding(
                status="PASS",
                region=region,
                resource_id="shield:subscription",
                actual_value="Shield Advanced is active",
                remediation=""
            ))
        else:
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=None,
                actual_value=f"Subscription state: {status.get('SubscriptionState', 'Unknown')}",
                remediation="Enable Shield Advanced subscription in the AWS Shield console"
            ))

        return self.findings
