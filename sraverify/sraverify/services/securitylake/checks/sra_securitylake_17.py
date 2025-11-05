"""Check if Audit account has data access."""

from typing import List, Dict, Any
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.core.logging import logger


class SRA_SECURITYLAKE_17(SecurityLakeCheck):
    """Check if Audit account has data access."""

    def __init__(self):
        """Initialize check."""
        super().__init__()
        self.check_id = "SRA-SECURITYLAKE-17"
        self.check_name = "Security Lake audit account has data access"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether the AWS Organization "
            "Audit account is set up as data access subscriber. These "
            "subscribers can directly access the S3 objects and receive "
            "notifications of new objects through a subscription endpoint or "
            "by polling an Amazon SQS queue."
        )
        self.check_logic = (
            "Checks if the audit account is set up as a data access subscriber. "
            "The check passes if there is at least one subscriber with type DATA_ACCESS and "
            "the account ID matches the audit account ID. "
            "The check fails if no data access subscriber is found for the audit account."
        )
        self._audit_accounts = []

    def execute(self) -> List[Dict[str, Any]]:
        """Run check."""
        findings = []

        # Check if audit account ID is provided
        if not self._audit_accounts:
            logger.warning("Audit account ID not provided. Check cannot be completed.")
            findings.append(
                self.create_finding(
                    status="ERROR",
                    region="global",
                    resource_id=f"arn:aws:securitylake::global:subscriber/data-access",
                    checked_value="Security tooling account has data access",
                    actual_value="Audit account ID not provided",
                    remediation="Run sraverify with --audit-account parameter"
                )
            )
            return findings

        # Use the first audit account in the list
        audit_account_id = self._audit_accounts[0]
        logger.debug(f"Using audit account ID: {audit_account_id}")

        # This is a global check, so we only need to run it once
        # Use the first region just to make the API call
        region = self.regions[0] if self.regions else "us-east-1"
        resource_id = f"arn:aws:securitylake::global:subscriber/data-access"

        # Get subscribers using the base class method
        subscribers = self.get_subscribers(region)

        # Check if any subscriber is the audit account with data access
        audit_subscriber = next(
            (sub for sub in subscribers
             if sub.get("subscriberType") == "DATA_ACCESS" and
             sub.get("accountId") == audit_account_id),
            None
        )

        if not audit_subscriber:
            logger.debug("Audit account is not set up as data access subscriber")
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    resource_id=resource_id,
                    checked_value=f"Audit account {audit_account_id} has data access",
                    actual_value=f"Audit account {audit_account_id} is not set up as data access subscriber",
                    remediation=(
                        f"Set up the audit account {audit_account_id} as a data access subscriber in Security Lake. "
                        "In the Security Lake console, navigate to Subscribers > Create subscriber and select "
                        f"the audit account {audit_account_id} with Data access type."
                    )
                )
            )
        else:
            # Get subscriber ID for resource ID
            subscriber_id = audit_subscriber.get("subscriberId", "default")
            resource_id = f"arn:aws:securitylake::global:subscriber/{subscriber_id}"

            logger.debug("Audit account is set up as data access subscriber")
            findings.append(
                self.create_finding(
                    status="PASS",
                    region="global",
                    resource_id=resource_id,
                    checked_value=f"Audit account {audit_account_id} has data access",
                    actual_value=f"Audit account {audit_account_id} is set up as data access subscriber",
                    remediation="No remediation needed"
                )
            )

        return findings
