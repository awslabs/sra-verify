"""Check if Audit account has query access."""

from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.logging import logger
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securitylake.base import SecurityLakeCheck


class SRA_SECURITYLAKE_16(SecurityLakeCheck):
    """Check if Audit account has query access."""

    meta = CheckMeta(
        check_id="SRA-SECURITYLAKE-16",
        title="Security Lake audit account has query access",
        description=(
            "This check verifies whether the AWS Organization audit "
            "account is set up as query access subscriber. These "
            "subscribers directly query AWS Lake Formation tables in your S3 "
            "bucket with services like Amazon Athena. Separation of log storage "
            "(Log Archive account) and log access (audit account) "
            "helps is separation of duties and helps in least privilege access."
        ),
        check_logic=(
            "Checks if the audit account is set up as a query access subscriber. "
            "The check passes if there is at least one subscriber with type QUERY_ACCESS and "
            "the account ID matches the audit account ID. "
            "The check fails if no query access subscriber is found for the audit account."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.LOG_ARCHIVE,
        service="SecurityLake",
        resource_type="AWS::SecurityLake::SecurityLake",
        remediation=Remediation(
            text=(
                "Create a Security Lake subscriber for the audit account with Lake "
                "Formation query access."
            ),
            cli=(
                "aws securitylake create-subscriber --subscriber-name audit-query "
                "--access-types LAKEFORMATION "
                "--subscriber-identity principal=<audit-account-id>,externalId=<external-id> "
                "--sources '[{\"awsLogSource\":{\"sourceName\":\"CLOUD_TRAIL_MGMT\","
                "\"sourceVersion\":\"2.0\"}}]' --region <region>"
            ),
            console=(
                "Security Lake console, Subscribers, Create subscriber, select the "
                "audit account and Lake Formation query access."
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
                resource_id=f"arn:aws:securitylake::global:subscriber/query-access",
                checked_value="Security tooling account has query access",
                actual_value="Audit account ID not provided",
                remediation="Run sraverify with --audit-account parameter",
            )
            return

        # Use the first audit account in the list
        audit_account_id = self.audit_accounts[0]
        logger.debug(f"Using audit account ID: {audit_account_id}")

        # Check each region
        for region in self.regions:
            resource_id = f"arn:aws:securitylake:{region}:{self.account_id}:subscriber/query-access"

            # Get subscribers using the base class method
            subscribers = self.get_subscribers(region)

            # Check if any subscriber is the audit account with query access
            audit_subscriber = next(
                (sub for sub in subscribers
                 if "LAKEFORMATION" in sub.get("accessTypes", []) and
                 sub.get("subscriberIdentity", {}).get("principal") == audit_account_id),
                None
            )

            if not audit_subscriber:
                logger.debug(f"Audit account is not set up as query access subscriber in {region}")
                yield self.failed(
                    region=region,
                    resource_id=resource_id,
                    checked_value=f"Audit account {audit_account_id} has query access",
                    actual_value=f"Audit account {audit_account_id} is not set up as query access subscriber",
                    remediation=(
                        f"Set up the audit account {audit_account_id} as a query access subscriber in Security Lake. "
                        "In the Security Lake console, navigate to Subscribers > Create subscriber and select "
                        f"the audit account {audit_account_id} with Query access type."
                    ),
                )
            else:
                # Get subscriber ID for resource ID
                subscriber_id = audit_subscriber.get("subscriberId", "default")
                resource_id = f"arn:aws:securitylake:{region}:{self.account_id}:subscriber/{subscriber_id}"

                logger.debug(f"Audit account is set up as query access subscriber in {region}")
                yield self.passed(
                    region=region,
                    resource_id=resource_id,
                    checked_value=f"Audit account {audit_account_id} has query access",
                    actual_value=f"Audit account {audit_account_id} is set up as query access subscriber",
                )
