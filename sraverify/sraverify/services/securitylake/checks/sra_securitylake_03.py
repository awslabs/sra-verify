"""Check if Security Lake SQS DLQ is encrypted with CMK."""

from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.logging import logger
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securitylake.base import SecurityLakeCheck


class SRA_SECURITYLAKE_03(SecurityLakeCheck):
    """Check if Security Lake SQS DLQ is encrypted with CMK."""

    meta = CheckMeta(
        check_id="SRA-SECURITYLAKE-03",
        title="Security Lake DLQ encrypted with CMK",
        description=(
            "This check verifies whether Security Lake SQS DLQ is encrypted in this "
            "region with a customer managed key from AWS KMS. You must use a customer "
            "managed KMS key for the encryption as you have greater control on the key "
            "usage and permission."
        ),
        check_logic=(
            "Gets all subscribers for Security Lake in the region. "
            "For each subscriber with a DLQ endpoint, checks if the queue is encrypted with a customer managed KMS key. "
            "The check passes if all DLQ queues are encrypted with customer managed keys (not AWS managed keys). "
            "The check fails if any DLQ queue is not encrypted or uses an AWS managed key (alias/aws/*)."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.LOG_ARCHIVE,
        service="SecurityLake",
        resource_type="AWS::SecurityLake::SecurityLake",
        remediation=Remediation(
            text=(
                "Encrypt every Security Lake dead-letter queue with a customer "
                "managed KMS key rather than an AWS managed key."
            ),
            cli=(
                "aws sqs set-queue-attributes --queue-url <dlq-url> "
                "--attributes KmsMasterKeyId=<customer-managed-key-id>"
            ),
            console=(
                "SQS console, select the dead-letter queue, Edit, Encryption, "
                "Server-side encryption enabled, choose a customer managed KMS key."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Region.
        """

        for region in self.regions:
            logger.debug(f"Checking if Security Lake SQS DLQ is encrypted with CMK in {region}")

            # Get subscribers for the region using the base class method
            subscribers_response = self.get_subscribers(region)

            if "Error" in subscribers_response:
                error = subscribers_response['Error']
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"arn:aws:securitylake:{region}:{self.account_id}:datalake/default",
                        checked_value="All DLQ queues encrypted with CMK",
                        actual_value=f"No Security Lake data lake exists in {region}, so the control is not configured",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"arn:aws:securitylake:{region}:{self.account_id}:datalake/default",
                        checked_value="All DLQ queues encrypted with CMK",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            subscribers = subscribers_response.get('subscribers', [])

            # Find DLQ queues
            dlq_queues = []
            for subscriber in subscribers:
                endpoint = subscriber.get("subscriberEndpoint", "")
                if endpoint and "sqs" in endpoint.lower() and "dlq" in endpoint.lower():
                    queue_url = endpoint
                    queue_name = queue_url.split("/")[-1]
                    dlq_queues.append((queue_name, queue_url))

            if not subscribers or not dlq_queues:
                resource_id = f"arn:aws:securitylake:{region}:{self.account_id}:dlq/none"
                yield self.failed(
                    region=region,
                    resource_id=resource_id,
                    checked_value="DLQ queues present and encrypted with CMK",
                    actual_value=f"No DLQ queues found - Security Lake may not be enabled in {region}",
                    remediation=(
                        "Enable Security Lake and configure subscribers with DLQ queues. In the Security Lake console, "
                        "navigate to Subscribers and add subscribers with DLQ queue endpoints."
                    ),
                )
                continue

            # Check encryption for each queue
            unencrypted_dlqs = []
            # Queues whose encryption could not be read. Kept separate
            # from the unencrypted list because 'we could not look' is
            # not 'it is not encrypted'.
            undetermined_queues = []
            for queue_name, queue_url in dlq_queues:
                # Check encryption using base class method
                encryption_response = self.get_sqs_queue_encryption(
                    region, queue_url
                )
                if "Error" in encryption_response:
                    # A queue whose encryption could not be read is not evidence
                    # that it is unencrypted, so it is not added to the
                    # unencrypted list. The ERROR row below reports it.
                    undetermined_queues.append(
                        (queue_name, encryption_response["Error"])
                    )
                    continue

                kms_key = encryption_response.get("Attributes", {}).get(
                    "KmsMasterKeyId"
                )

                if not kms_key or kms_key.startswith("alias/aws/"):
                    unencrypted_dlqs.append((queue_name, queue_url))

            if undetermined_queues:
                first_error = undetermined_queues[0][1]
                yield self.error(
                    region=region,
                    resource_id=(
                        f"arn:aws:sqs:{region}:{self.account_id}:"
                        f"{undetermined_queues[0][0]}"
                    ),
                    checked_value="All DLQ queues encrypted with CMK",
                    actual_value=(
                        f"{first_error['Operation']} failed: "
                        f"{first_error['Code']}: {first_error['Message']}"
                    ),
                    remediation=self._remediation_for(first_error),
                )

            if unencrypted_dlqs:
                # Use the first unencrypted queue for the resource ID
                queue_name = unencrypted_dlqs[0][0]
                resource_id = f"arn:aws:sqs:{region}:{self.account_id}:{queue_name}"

                logger.debug(f"Found {len(unencrypted_dlqs)} unencrypted DLQ queues in {region}")
                yield self.failed(
                    region=region,
                    resource_id=resource_id,
                    checked_value="All DLQ queues encrypted with CMK",
                    actual_value=f"The following DLQ queues are not encrypted with CMK: {', '.join([name for name, _ in unencrypted_dlqs])}",
                    remediation=(
                        "Configure DLQ queue encryption with a customer managed KMS key. In the SQS console, "
                        "select each DLQ queue and under Server-side encryption, choose 'Enable server-side encryption' "
                        "and select a customer managed KMS key."
                    ),
                )
            else:
                # Use the first queue for the resource ID in the PASS case
                queue_name = dlq_queues[0][0]
                resource_id = f"arn:aws:sqs:{region}:{self.account_id}:{queue_name}"

                logger.debug(f"All Security Lake DLQ queues are encrypted with CMK in {region}")
                yield self.passed(
                    region=region,
                    resource_id=resource_id,
                    checked_value="All DLQ queues encrypted with CMK",
                    actual_value=f"All Security Lake DLQ queues are encrypted with CMK in {region}",
                )
