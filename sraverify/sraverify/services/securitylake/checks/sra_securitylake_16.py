"""Check if Security Tooling account has query access."""


from typing import List, Dict, Any
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.core.logging import logger


class SRA_SECURITYLAKE_16(SecurityLakeCheck):
    """Check if Security Tooling account has query access."""

    def __init__(self):
        """Initialize check."""
        super().__init__()
        self.check_id = "SRA-SECURITYLAKE-16"
        self.check_name = "Security Lake audit account has query access"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether the AWS Organization Security tooling"
            "(Audit) account is set up as query access subscriber. These "
            "subscribers directly query AWS Lake Formation tables in your S3 "
            "bucket with services like Amazon Athena. Separation of log storage "
            "(Log Archive account) and log access (Security Tooling account) "
            "helps is separation of duties and helps in least privilege access."
        )
        self.check_logic = (
            "Checks if the Security Tooling (Audit) account is set up as a query access subscriber. "
            "The check passes if there is at least one subscriber with type QUERY_ACCESS and "
            "the account ID matches the current account ID. "
            "The check fails if no query access subscriber is found for the Security Tooling account."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """Run check."""
        findings = []

        # This is a global check, so we only need to run it once
        # Use the first region just to make the API call
        region = self.regions[0] if self.regions else "us-east-1"
        resource_id = f"arn:aws:securitylake::global:subscriber/query-access"

        # Get subscribers using the base class method
        subscribers = self.get_subscribers(region)

        # Check if any subscriber is the security tooling account with query access
        security_tooling_subscriber = next(
            (sub for sub in subscribers
             if sub.get("subscriberType") == "QUERY_ACCESS" and
             sub.get("accountId") == self.session.client("sts").get_caller_identity()["Account"]),
            None
        )

        if not security_tooling_subscriber:
            logger.debug("Security tooling account is not set up as query access subscriber")
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    resource_id=resource_id,
                    checked_value="Security tooling account has query access",
                    actual_value="Security tooling account is not set up as query access subscriber",
                    remediation=(
                        "Set up the Security Tooling account as a query access subscriber in Security Lake. "
                        "In the Security Lake console, navigate to Subscribers > Create subscriber and select "
                        "the Security Tooling account with Query access type."
                    )
                )
            )
        else:
            # Get subscriber ID for resource ID
            subscriber_id = security_tooling_subscriber.get("subscriberId", "default")
            resource_id = f"arn:aws:securitylake::global:subscriber/{subscriber_id}"

            logger.debug("Security tooling account is set up as query access subscriber")
            findings.append(
                self.create_finding(
                    status="PASS",
                    region="global",
                    resource_id=resource_id,
                    checked_value="Security tooling account has query access",
                    actual_value="Security tooling account is set up as query access subscriber",
                    remediation="No remediation needed"
                )
            )

        return findings
