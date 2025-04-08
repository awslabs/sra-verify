"""
SRA-CONFIG-7: AWS Config last config history delivery is successful.
"""
from typing import List, Dict, Any
from datetime import datetime, timezone, timedelta
from sraverify.services.config.base import ConfigCheck
from sraverify.core.logging import logger


class SRA_CONFIG_7(ConfigCheck):
    """Check if AWS Config last config history delivery is successful."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-CONFIG-7"
        self.check_name = "AWS Config last config history delivery is successful"
        self.account_type = "application"  # This check applies to application accounts
        self.severity = "HIGH"
        self.description = (
            "This check verifies that the last delivery of resource config history by AWS config "
            "into the delivery channel was successful."
        )
        self.check_logic = (
            "Checks if the last delivery of config history was successful and within the last 24 hours."
        )
        self.resource_type = "AWS::Config::DeliveryChannel"
    
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
                    checked_value="configHistoryDeliveryInfo.lastStatus: SUCCESS, lastSuccessfulTime within 24 hours",
                    actual_value="No regions specified for check",
                    remediation="Specify at least one region when running the check"
                )
            )
            return findings
        
        # Check each region for delivery channel status
        for region in self.regions:
            # Get delivery channel status for the region
            channel_statuses = self.get_delivery_channel_status(region)
            
            if not channel_statuses:
                # No delivery channel status found in this region
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"arn:aws:config:{region}:{account_id}:deliveryChannel/default",
                        checked_value="configHistoryDeliveryInfo.lastStatus: SUCCESS, lastSuccessfulTime within 24 hours",
                        actual_value="No delivery channel status found in this region",
                        remediation=(
                            f"Ensure a delivery channel is configured in {region} and check its status using: "
                            f"aws configservice describe-delivery-channel-status --region {region}"
                        )
                    )
                )
                continue
            
            # Check each delivery channel status
            for status in channel_statuses:
                channel_name = status.get('name', 'default')
                resource_id = f"arn:aws:config:{region}:{account_id}:deliveryChannel/{channel_name}"
                
                # Check configHistoryDeliveryInfo
                history_info = status.get('configHistoryDeliveryInfo', {})
                history_status = history_info.get('lastStatus', 'UNKNOWN')
                history_success_time_str = history_info.get('lastSuccessfulTime')
                
                if not history_success_time_str:
                    # No successful delivery time found
                    findings.append(
                        self.create_finding(
                            status="FAIL",
                            region=region,
                            account_id=account_id,
                            resource_id=resource_id,
                            checked_value="configHistoryDeliveryInfo.lastStatus: SUCCESS, lastSuccessfulTime within 24 hours",
                            actual_value=f"No successful delivery time found for channel '{channel_name}'",
                            remediation=(
                                f"Check the AWS Config logs and permissions in {region}. "
                                f"Ensure the Config service role has the necessary permissions to deliver to the S3 bucket."
                            )
                        )
                    )
                    continue
                
                # Convert the timestamp to datetime
                try:
                    history_success_time = datetime.fromisoformat(history_success_time_str.replace('Z', '+00:00'))
                except (ValueError, TypeError):
                    # Invalid timestamp format
                    findings.append(
                        self.create_finding(
                            status="FAIL",
                            region=region,
                            account_id=account_id,
                            resource_id=resource_id,
                            checked_value="configHistoryDeliveryInfo.lastStatus: SUCCESS, lastSuccessfulTime within 24 hours",
                            actual_value=f"Invalid timestamp format: {history_success_time_str}",
                            remediation=(
                                f"Check the AWS Config logs and permissions in {region}. "
                                f"Ensure the Config service role has the necessary permissions to deliver to the S3 bucket."
                            )
                        )
                    )
                    continue
                
                # Check if the last successful delivery was within the last 24 hours
                now = datetime.now(timezone.utc)
                time_diff = now - history_success_time
                
                if history_status == "SUCCESS" and time_diff < timedelta(hours=24):
                    # Last delivery was successful and within the last 24 hours
                    findings.append(
                        self.create_finding(
                            status="PASS",
                            region=region,
                            account_id=account_id,
                            resource_id=resource_id,
                            checked_value="configHistoryDeliveryInfo.lastStatus: SUCCESS, lastSuccessfulTime within 24 hours",
                            actual_value=f"Last config history delivery was successful at {history_success_time_str}",
                            remediation=""
                        )
                    )
                else:
                    # Last delivery was not successful or not within the last 24 hours
                    if history_status != "SUCCESS":
                        actual_value = f"Last config history delivery status: {history_status}, time: {history_success_time_str}"
                    else:
                        actual_value = f"Last config history delivery was successful but outdated: {history_success_time_str} ({time_diff.total_seconds() / 3600:.1f} hours ago)"
                    
                    findings.append(
                        self.create_finding(
                            status="FAIL",
                            region=region,
                            account_id=account_id,
                            resource_id=resource_id,
                            checked_value="configHistoryDeliveryInfo.lastStatus: SUCCESS, lastSuccessfulTime within 24 hours",
                            actual_value=actual_value,
                            remediation=(
                                f"Check the AWS Config logs and permissions in {region}. "
                                f"Ensure the Config service role has the necessary permissions to deliver to the S3 bucket. "
                                f"If the delivery is outdated, check if there are any configuration changes to record."
                            )
                        )
                    )
        
        return findings
