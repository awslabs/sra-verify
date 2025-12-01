"""Check if Security Lake SQS DLQ is encrypted with CMK."""

from typing import List, Dict, Any
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.core.logging import logger


class SRA_SECURITYLAKE_03(SecurityLakeCheck):
    """Check if Security Lake SQS DLQ is encrypted with CMK."""

    def __init__(self):
        """Initialize check."""
        super().__init__()
        self.check_id = "SRA-SECURITYLAKE-03"
        self.check_name = "Security Lake DLQ encrypted with CMK"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Security Lake SQS DLQ is encrypted in this "
            "region with a customer managed key from AWS KMS. You must use a customer "
            "managed KMS key for the encryption as you have greater control on the key "
            "usage and permission."
        )
        self.check_logic = (
            "Gets all subscribers for Security Lake in the region. "
            "For each subscriber with a DLQ endpoint, checks if the queue is encrypted with a customer managed KMS key. "
            "The check passes if all DLQ queues are encrypted with customer managed keys (not AWS managed keys). "
            "The check fails if any DLQ queue is not encrypted or uses an AWS managed key (alias/aws/*)."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """

        for region in self.regions:
            logger.debug(f"Checking if Security Lake SQS DLQ is encrypted with CMK in {region}")

            # Get subscribers for the region using the base class method
            subscribers = self.get_subscribers(region)

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
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_id,
                        checked_value="DLQ queues present and encrypted with CMK",
                        actual_value=f"No DLQ queues found - Security Lake may not be enabled in {region}",
                        remediation=(
                            "Enable Security Lake and configure subscribers with DLQ queues. In the Security Lake console, "
                            "navigate to Subscribers and add subscribers with DLQ queue endpoints."
                        )
                    )
                )
                continue

            # Check encryption for each queue
            unencrypted_dlqs = []
            for queue_name, queue_url in dlq_queues:
                # Check encryption using base class method
                kms_key = self.get_sqs_queue_encryption(region, queue_url)

                if not kms_key or kms_key.startswith("alias/aws/"):
                    unencrypted_dlqs.append((queue_name, queue_url))

            if unencrypted_dlqs:
                # Use the first unencrypted queue for the resource ID
                queue_name = unencrypted_dlqs[0][0]
                resource_id = f"arn:aws:sqs:{region}:{self.account_id}:{queue_name}"

                logger.debug(f"Found {len(unencrypted_dlqs)} unencrypted DLQ queues in {region}")
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_id,
                        checked_value="All DLQ queues encrypted with CMK",
                        actual_value=f"The following DLQ queues are not encrypted with CMK: {', '.join([name for name, _ in unencrypted_dlqs])}",
                        remediation=(
                            "Configure DLQ queue encryption with a customer managed KMS key. In the SQS console, "
                            "select each DLQ queue and under Server-side encryption, choose 'Enable server-side encryption' "
                            "and select a customer managed KMS key."
                        )
                    )
                )
            else:
                # Use the first queue for the resource ID in the PASS case
                queue_name = dlq_queues[0][0]
                resource_id = f"arn:aws:sqs:{region}:{self.account_id}:{queue_name}"

                logger.debug(f"All Security Lake DLQ queues are encrypted with CMK in {region}")
                self.findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=resource_id,
                        checked_value="All DLQ queues encrypted with CMK",
                        actual_value=f"All Security Lake DLQ queues are encrypted with CMK in {region}",
                        remediation="No remediation needed"
                    )
                )

        return self.findings
