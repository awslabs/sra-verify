"""Check if Security Tooling account has data access."""

from typing import List, Dict, Any
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.core.logging import logger


class SRA_SECURITYLAKE_17(SecurityLakeCheck):
    """Check if Security Tooling account has data access."""

    def __init__(self):
        """Initialize check."""
        super().__init__()
        self.check_id = "SRA-SECURITYLAKE-17"
        self.check_name = "Security Lake audit account has data access"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether the AWS Organization Security tooling"
            "(Audit) account is set up as data access subscriber. These "
            "subscribers can directly access the S3 objects and receive "
            "notifications of new objects through a subscription endpoint or "
            "by polling an Amazon SQS queue."
        )
        self.check_logic = (
            "Checks if the Security Tooling (Audit) account is set up as a data access subscriber. "
            "The check passes if there is at least one subscriber with type DATA_ACCESS and "
            "the account ID matches the current account ID. "
            "The check fails if no data access subscriber is found for the Security Tooling account."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """Run check."""
        findings = []

        # This is a global check, so we only need to run it once
        # Use the first region just to make the API call
        region = self.regions[0] if self.regions else "us-east-1"
        resource_id = f"arn:aws:securitylake::global:subscriber/data-access"

        # Get subscribers using the base class method
        subscribers = self.get_subscribers(region)

        # Check if any subscriber is the security tooling account with data access
        security_tooling_subscriber = next(
            (sub for sub in subscribers
             if sub.get("subscriberType") == "DATA_ACCESS" and
             sub.get("accountId") == self.session.client("sts").get_caller_identity()["Account"]),
            None
        )

        if not security_tooling_subscriber:
            logger.debug("Security tooling account is not set up as data access subscriber")
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    resource_id=resource_id,
                    checked_value="Security tooling account has data access",
                    actual_value="Security tooling account is not set up as data access subscriber",
                    remediation=(
                        "Set up the Security Tooling account as a data access subscriber in Security Lake. "
                        "In the Security Lake console, navigate to Subscribers > Create subscriber and select "
                        "the Security Tooling account with Data access type."
                    )
                )
            )
        else:
            # Get subscriber ID for resource ID
            subscriber_id = security_tooling_subscriber.get("subscriberId", "default")
            resource_id = f"arn:aws:securitylake::global:subscriber/{subscriber_id}"

            logger.debug("Security tooling account is set up as data access subscriber")
            findings.append(
                self.create_finding(
                    status="PASS",
                    region="global",
                    resource_id=resource_id,
                    checked_value="Security tooling account has data access",
                    actual_value="Security tooling account is set up as data access subscriber",
                    remediation="No remediation needed"
                )
            )

        return findings
