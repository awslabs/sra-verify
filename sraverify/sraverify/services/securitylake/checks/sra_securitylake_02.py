"""Check if Security Lake SQS queues are encrypted with CMK."""

from typing import List, Dict, Any
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.core.logging import logger


class SRA_SECURITYLAKE_02(SecurityLakeCheck):
    """Check if Security Lake SQS queues are encrypted with CMK."""

    def __init__(self):
        """Initialize check."""
        super().__init__()
        self.check_id = "SRA-SECURITYLAKE-02"
        self.check_name = "Security Lake SQS queues encrypted with CMK"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Security Lake manager SQS Queues within "
            "delegated admin account is encrypted with a customer managed key from "
            "AWS KMS. These SQS queues are used by AWS Lambda function for ETL job "
            "and also by subscribers looking for new logs deposited into the data lake. "
            "You must use a customer managed KMS key for the encryption as you have "
            "greater control on the key usage and permission."
        )
        self.check_logic = (
            "Gets all subscribers for Security Lake in the region. "
            "For each subscriber with an SQS endpoint, checks if the queue is encrypted with a customer managed KMS key. "
            "The check passes if all SQS queues are encrypted with customer managed keys (not AWS managed keys). "
            "The check fails if any SQS queue is not encrypted or uses an AWS managed key (alias/aws/*)."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """

        for region in self.regions:
            logger.debug(f"Checking if Security Lake SQS queues are encrypted with CMK in {region}")

            # Get subscribers for the region using the base class method
            subscribers = self.get_subscribers(region)

            # Find SQS queues
            sqs_queues = []
            for subscriber in subscribers:
                endpoint = subscriber.get("subscriberEndpoint", "")
                if endpoint and "sqs" in endpoint.lower():
                    # Convert ARN to queue URL if needed
                    if endpoint.startswith("arn:aws:sqs:"):
                        # Extract components from ARN: arn:aws:sqs:region:account:queue-name
                        arn_parts = endpoint.split(":")
                        if len(arn_parts) >= 6:
                            queue_region = arn_parts[3]
                            account_id = arn_parts[4]
                            queue_name = arn_parts[5]
                            queue_url = f"https://sqs.{queue_region}.amazonaws.com/{account_id}/{queue_name}"
                        else:
                            continue
                    else:
                        queue_url = endpoint
                        queue_name = queue_url.split("/")[-1]
                    
                    sqs_queues.append((queue_name, queue_url))

            if not subscribers or not sqs_queues:
                resource_id = f"arn:aws:securitylake:{region}:{self.account_id}:subscriber/none"
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_id,
                        checked_value="SQS queues present and encrypted with CMK",
                        actual_value=f"No SQS queues found - Security Lake may not be enabled in {region}",
                        remediation=(
                            "Enable Security Lake and configure subscribers with SQS queues. In the Security Lake console, "
                            "navigate to Subscribers and add subscribers with SQS queue endpoints."
                        )
                    )
                )
                continue

            # Check encryption for each queue
            unencrypted_queues = []
            for queue_name, queue_url in sqs_queues:
                resource_id = f"arn:aws:sqs:{region}:{self.account_id}:{queue_name}"

                # Check encryption using base class method
                kms_key = self.get_sqs_queue_encryption(region, queue_url)

                if not kms_key or kms_key.startswith("alias/aws/"):
                    unencrypted_queues.append((queue_name, queue_url))

            if unencrypted_queues:
                # Use the first unencrypted queue for the resource ID
                queue_name = unencrypted_queues[0][0]
                resource_id = f"arn:aws:sqs:{region}:{self.account_id}:{queue_name}"

                logger.debug(f"Found {len(unencrypted_queues)} unencrypted SQS queues in {region}")
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_id,
                        checked_value="All SQS queues encrypted with CMK",
                        actual_value=f"The following SQS queues are not encrypted with CMK: {', '.join([name for name, _ in unencrypted_queues])}",
                        remediation=(
                            "Configure SQS queue encryption with a customer managed KMS key. In the SQS console, "
                            "select each queue and under Server-side encryption, choose 'Enable server-side encryption' "
                            "and select a customer managed KMS key."
                        )
                    )
                )
            else:
                # Use the first queue for the resource ID in the PASS case
                queue_name = sqs_queues[0][0]
                resource_id = f"arn:aws:sqs:{region}:{self.account_id}:{queue_name}"

                logger.debug(f"All Security Lake SQS queues are encrypted with CMK in {region}")
                self.findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=resource_id,
                        checked_value="All SQS queues encrypted with CMK",
                        actual_value=f"All Security Lake SQS queues are encrypted with CMK in {region}",
                        remediation="No remediation needed"
                    )
                )

        return self.findings
