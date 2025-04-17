"""
SRA-CONFIG-03: AWS Config Recording All Resource Types.
"""
from typing import List, Dict, Any
from sraverify.services.config.base import ConfigCheck
from sraverify.core.logging import logger


class SRA_CONFIG_03(ConfigCheck):
    """Check if AWS Config latest recording event is processed successfully."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-CONFIG-03"
        self.check_name = "AWS Config latest recording event is processed successfully"
        self.account_type = "application"  # This check applies to all account types
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether the last delivery attempt to the delivery channel was successful "
            "to ensure you receive configuration change notifications. As AWS Config continually records "
            "the changes that occur to your AWS resources, it sends notifications and updated configuration "
            "states through the delivery channel."
        )
        self.check_logic = (
            "Checks if the lastStatus of the delivery channel is SUCCESS."
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        if not self.regions:
            findings.append(
                self.create_finding(
                    status="ERROR",
                    region="global",
                    account_id=account_id,
                    resource_id="config:global",
                    actual_value="No regions specified for check",
                    remediation="Specify at least one region when running the check"
                )
            )
            return findings
        
        # Check each region for delivery channel status
        for region in self.regions:
            # Get delivery channels for the region
            channels = self.get_delivery_channels(region)
            
            # Get delivery channel status for the region
            channel_statuses = self.get_delivery_channel_status(region)
            
            if not channels:
                # No delivery channel found in this region
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"arn:aws:config:{region}:{account_id}:deliveryChannel/default",
                        actual_value="No delivery channel found in this region",
                        remediation=(
                            f"Create a delivery channel in {region} using: aws configservice put-delivery-channel --delivery-channel name=default,s3BucketName=config-bucket-{account_id},snsTopicARN=arn:aws:sns:{region}:{account_id}:config-notifications --region {region}. "
                            f"Note: You must first create an S3 bucket and SNS topic with appropriate permissions for AWS Config."
                        )
                    )
                )
                continue
            
            if not channel_statuses:
                # No delivery channel status found in this region
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"arn:aws:config:{region}:{account_id}:deliveryChannel/default",
                        actual_value="No delivery channel status found in this region",
                        remediation=(
                            f"Check the delivery channel configuration in {region} and ensure it's properly configured. "
                            f"Verify S3 bucket permissions and SNS topic permissions are correctly set up for AWS Config."
                        )
                    )
                )
                continue
            
            # Check each delivery channel status
            for status in channel_statuses:
                channel_name = status.get('name', 'default')
                resource_id = f"config:deliveryChannel:{channel_name}"
                
                # Check configHistoryDeliveryInfo - this is the most important one
                history_info = status.get('configHistoryDeliveryInfo', {})
                history_status = history_info.get('lastStatus', 'UNKNOWN')
                history_attempt_time = history_info.get('lastAttemptTime', 'UNKNOWN')
                history_success_time = history_info.get('lastSuccessfulTime', 'UNKNOWN')
                
                # Check configSnapshotDeliveryInfo - may be UNKNOWN if no snapshot has been taken yet
                snapshot_info = status.get('configSnapshotDeliveryInfo', {})
                snapshot_status = snapshot_info.get('lastStatus', 'UNKNOWN')
                
                # Check configStreamDeliveryInfo - may be NOT_APPLICABLE if streaming is not configured
                stream_info = status.get('configStreamDeliveryInfo', {})
                stream_status = stream_info.get('lastStatus', 'UNKNOWN')
                
                # Determine overall status - focus on history delivery as the primary indicator
                # Stream may be NOT_APPLICABLE and snapshot may be UNKNOWN if not configured/used
                if history_status == "SUCCESS":
                    # History delivery is successful, which is the most important
                    findings.append(
                        self.create_finding(
                            status="PASS",
                            region=region,
                            account_id=account_id,
                            resource_id=resource_id,
                            actual_value=(
                                f"Delivery channel '{channel_name}' is processing events successfully: "
                                f"Config History: {history_status} (Last success: {history_success_time}), "
                                f"Config Snapshot: {snapshot_status}, "
                                f"Config Stream: {stream_status}"
                            ),
                            remediation="No remediation needed"
                        )
                    )
                else:
                    # History delivery is not successful
                    findings.append(
                        self.create_finding(
                            status="FAIL",
                            region=region,
                            account_id=account_id,
                            resource_id=resource_id,
                            actual_value=(
                                f"Delivery channel '{channel_name}' has issues processing events: "
                                f"Config History: {history_status} (Last attempt: {history_attempt_time}), "
                                f"Config Snapshot: {snapshot_status}, "
                                f"Config Stream: {stream_status}"
                            ),
                            remediation=(
                                "Check the following: 1. S3 bucket permissions - ensure Config has write access. "
                                "2. SNS topic permissions - ensure Config can publish to the topic. "
                                "3. IAM role permissions - ensure Config service role has necessary permissions. "
                                "4. Check CloudWatch Logs for Config service errors."
                            )
                        )
                    )
        
        return findings
