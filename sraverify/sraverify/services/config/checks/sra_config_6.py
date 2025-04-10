"""
SRA-CONFIG-6: AWS Config delivery channel S3 bucket is centralized in Log Archive account.
"""
from typing import List, Dict, Any
import json
from sraverify.services.config.base import ConfigCheck
from sraverify.core.logging import logger


class SRA_CONFIG_6(ConfigCheck):
    """Check if AWS Config delivery channel S3 bucket is centralized in Log Archive account."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-CONFIG-6"
        self.check_name = "AWS Config delivery channel S3 bucket is centralized in Log Archive account"
        self.account_type = "application"  # This check applies to management account
        self.severity = "MEDIUM"
        self.description = (
            "This check verifies that the AWS Config delivery channel S3 bucket is centralized in "
            "Log Archive account. Security Tooling provides central visibility and monitoring of AWS "
            "Organization wide resource configuration."
        )
        self.check_logic = (
            "Checks if AWS Config delivery channel S3 bucket is owned by the Log Archive account."
        )
        self.resource_type = "AWS::Config::DeliveryChannel"
        # Initialize log archive account attribute
        self._log_archive_accounts = None
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        # Check if Log Archive account ID is provided
        if not hasattr(self, '_log_archive_accounts') or not self._log_archive_accounts:
            findings.append(
                self.create_finding(
                    status="ERROR",
                    region="global",
                    account_id=account_id,
                    resource_id="config:global",
                    checked_value="S3 bucket owned by Log Archive account",
                    actual_value="Log Archive Account ID not provided",
                    remediation="Provide the Log Archive account ID using the --log-archive-account parameter"
                )
            )
            return findings
        
        # Use the first log archive account if multiple are provided
        log_archive_account = self._log_archive_accounts[0]
        logger.debug(f"Using Log Archive account: {log_archive_account}")
        
        if not self.regions:
            findings.append(
                self.create_finding(
                    status="ERROR",
                    region="global",
                    account_id=account_id,
                    resource_id="config:global",
                    checked_value=f"S3 bucket owned by Log Archive account {log_archive_account}",
                    actual_value="No regions specified for check",
                    remediation="Specify at least one region when running the check"
                )
            )
            return findings
        
        # Check each region for delivery channels
        for region in self.regions:
            # Get delivery channels for the region
            channels = self.get_delivery_channels(region)
            
            if not channels:
                # No delivery channel found in this region
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"arn:aws:config:{region}:{account_id}:deliveryChannel/default",
                        checked_value=f"S3 bucket owned by Log Archive account {log_archive_account}",
                        actual_value="No delivery channel found in this region",
                        remediation=(
                            f"Create a delivery channel in {region} using: aws configservice put-delivery-channel "
                            f"--delivery-channel name=default,s3BucketName=aws-controltower-logs-{log_archive_account}-{region} "
                            f"--region {region}"
                        )
                    )
                )
                continue
            
            # Check each delivery channel
            for channel in channels:
                channel_name = channel.get('name', 'default')
                bucket_name = channel.get('s3BucketName', '')
                
                if not bucket_name:
                    # No S3 bucket configured
                    findings.append(
                        self.create_finding(
                            status="FAIL",
                            region=region,
                            account_id=account_id,
                            resource_id=f"arn:aws:config:{region}:{account_id}:deliveryChannel/{channel_name}",
                            checked_value=f"S3 bucket owned by Log Archive account {log_archive_account}",
                            actual_value="No S3 bucket configured for delivery channel",
                            remediation=(
                                f"Update the delivery channel in {region} to use an S3 bucket in the Log Archive account: "
                                f"aws configservice put-delivery-channel --delivery-channel name={channel_name},"
                                f"s3BucketName=aws-controltower-logs-{log_archive_account}-{region} --region {region}"
                            )
                        )
                    )
                    continue
                
                # Check if the bucket name contains the Log Archive account ID
                # This is a common pattern for AWS Control Tower and other AWS managed solutions
                bucket_owner_found = False
                
                # Check for common bucket naming patterns
                patterns_to_check = [
                    f"aws-controltower-logs-{log_archive_account}",  # AWS Control Tower pattern
                    f"config-bucket-{log_archive_account}",          # Common custom pattern
                    f"aws-config-{log_archive_account}",             # Another common pattern
                    f"config-{log_archive_account}",                 # Simple pattern
                    f"-{log_archive_account}-"                       # Generic pattern (account ID in the middle)
                ]
                
                for pattern in patterns_to_check:
                    if pattern in bucket_name:
                        bucket_owner_found = True
                        break
                
                if bucket_owner_found:
                    # Bucket name contains the Log Archive account ID, assume it's owned by the Log Archive account
                    findings.append(
                        self.create_finding(
                            status="PASS",
                            region=region,
                            account_id=account_id,
                            resource_id=f"arn:aws:config:{region}:{account_id}:deliveryChannel/{channel_name}",
                            checked_value=f"S3 bucket owned by Log Archive account {log_archive_account}",
                            actual_value=f"Delivery channel S3 bucket '{bucket_name}' is owned by the Log Archive account {log_archive_account}",
                            remediation="No remediation needed"
                        )
                    )
                else:
                    # Try to check if the bucket is in another region but still owned by Log Archive
                    # For example, a bucket in us-east-1 might be used by a delivery channel in us-east-2
                    cross_region_match = False
                    
                    for other_region in self.regions:
                        if other_region != region and f"-{other_region}" in bucket_name:
                            # The bucket name contains another region, check if it also contains the Log Archive account ID
                            for pattern in patterns_to_check:
                                if pattern in bucket_name:
                                    cross_region_match = True
                                    break
                            
                            if cross_region_match:
                                break
                    
                    if cross_region_match:
                        # Bucket is in another region but still owned by Log Archive
                        findings.append(
                            self.create_finding(
                                status="PASS",
                                region=region,
                                account_id=account_id,
                                resource_id=f"arn:aws:config:{region}:{account_id}:deliveryChannel/{channel_name}",
                                checked_value=f"S3 bucket owned by Log Archive account {log_archive_account}",
                                actual_value=f"Delivery channel S3 bucket '{bucket_name}' is owned by the Log Archive account {log_archive_account} (cross-region bucket)",
                                remediation="No remediation needed"
                            )
                        )
                    else:
                        # Bucket name doesn't contain the Log Archive account ID
                        findings.append(
                            self.create_finding(
                                status="FAIL",
                                region=region,
                                account_id=account_id,
                                resource_id=f"arn:aws:config:{region}:{account_id}:deliveryChannel/{channel_name}",
                                checked_value=f"S3 bucket owned by Log Archive account {log_archive_account}",
                                actual_value=f"Delivery channel S3 bucket '{bucket_name}' does not appear to be owned by the Log Archive account {log_archive_account} based on the bucket name",
                                remediation=(
                                    f"1. Create an S3 bucket in the Log Archive account {log_archive_account}. "
                                    f"2. Update the delivery channel in {region} to use the new S3 bucket: "
                                    f"aws configservice put-delivery-channel --delivery-channel name={channel_name},"
                                    f"s3BucketName=aws-controltower-logs-{log_archive_account}-{region} --region {region}"
                                )
                            )
                        )
        
        return findings
