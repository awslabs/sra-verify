"""Check if Audit account has data access."""

from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.logging import logger
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securitylake.base import SecurityLakeCheck


class SRA_SECURITYLAKE_17(SecurityLakeCheck):
    """Check if Audit account has data access."""

    meta = CheckMeta(
        check_id="SRA-SECURITYLAKE-17",
        title="Security Lake audit account has data access",
        description=(
            "This check verifies whether the AWS Organization "
            "Audit account is set up as data access subscriber. These "
            "subscribers can directly access the S3 objects and receive "
            "notifications of new objects through a subscription endpoint or "
            "by polling an Amazon SQS queue."
        ),
        check_logic=(
            "Checks if the audit account is set up as a data access subscriber. "
            "The check passes if there is at least one subscriber with type DATA_ACCESS and "
            "the account ID matches the audit account ID. "
            "The check fails if no data access subscriber is found for the audit account."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.LOG_ARCHIVE,
        service="SecurityLake",
        resource_type="AWS::SecurityLake::SecurityLake",
        remediation=Remediation(
            text=(
                "Create a Security Lake subscriber for the audit account with S3 data "
                "access."
            ),
            cli=(
                "aws securitylake create-subscriber --subscriber-name audit-data "
                "--access-types S3 "
                "--subscriber-identity principal=<audit-account-id>,externalId=<external-id> "
                "--sources '[{\"awsLogSource\":{\"sourceName\":\"CLOUD_TRAIL_MGMT\","
                "\"sourceVersion\":\"2.0\"}}]' --region <region>"
            ),
            console=(
                "Security Lake console, Subscribers, Create subscriber, select the "
                "audit account and Data access type."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """Run check.

        Yields:
            One Finding per Region, or a single global ERROR Finding.
        """
        # Check if audit account ID is provided
        if not self.audit_accounts:
            logger.warning("Audit account ID not provided. Check cannot be completed.")
            yield self.error(
                region="global",
                resource_id=f"arn:aws:securitylake::global:subscriber/data-access",
                checked_value="Security tooling account has data access",
                actual_value="Audit account ID not provided",
                remediation="Run sraverify with --audit-account parameter",
            )
            return

        # Use the first audit account in the list
        audit_account_id = self.audit_accounts[0]
        logger.debug(f"Using audit account ID: {audit_account_id}")

        # Check each region
        for region in self.regions:
            resource_id = f"arn:aws:securitylake:{region}:{self.account_id}:subscriber/data-access"

            # Get subscribers using the base class method
            subscribers_response = self.get_subscribers(region)

            if "Error" in subscribers_response:
                error = subscribers_response['Error']
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=resource_id,
                        checked_value=f"Audit account {audit_account_id} has data access",
                        actual_value=f"No Security Lake data lake exists in {region}, so the control is not configured",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=resource_id,
                        checked_value=f"Audit account {audit_account_id} has data access",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            # The guard above is load-bearing for this check in particular:
            # AccessDeniedException is deliberately not in the discriminator
            # table, so a denied ListSubscribers yields ERROR rather than
            # "is not set up as a subscriber".
            subscribers = subscribers_response.get('subscribers', [])

            # Check if any subscriber is the audit account with data access
            audit_subscriber = next(
                (sub for sub in subscribers
                 if "S3" in sub.get("accessTypes", []) and
                 sub.get("subscriberIdentity", {}).get("principal") == audit_account_id),
                None
            )

            if not audit_subscriber:
                logger.debug(f"Audit account is not set up as data access subscriber in {region}")
                yield self.failed(
                    region=region,
                    resource_id=resource_id,
                    checked_value=f"Audit account {audit_account_id} has data access",
                    actual_value=f"Audit account {audit_account_id} is not set up as data access subscriber",
                    remediation=(
                        f"Set up the audit account {audit_account_id} as a data access subscriber in Security Lake. "
                        "In the Security Lake console, navigate to Subscribers > Create subscriber and select "
                        f"the audit account {audit_account_id} with Data access type."
                    ),
                )
            else:
                # Get subscriber ID for resource ID
                subscriber_id = audit_subscriber.get("subscriberId", "default")
                resource_id = f"arn:aws:securitylake:{region}:{self.account_id}:subscriber/{subscriber_id}"

                logger.debug(f"Audit account is set up as data access subscriber in {region}")
                yield self.passed(
                    region=region,
                    resource_id=resource_id,
                    checked_value=f"Audit account {audit_account_id} has data access",
                    actual_value=f"Audit account {audit_account_id} is set up as data access subscriber",
                )
