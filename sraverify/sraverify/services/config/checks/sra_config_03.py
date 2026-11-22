"""
SRA-CONFIG-03: AWS Config Recording All Resource Types.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.config.base import ConfigCheck


class SRA_CONFIG_03(ConfigCheck):
    """Check if AWS Config latest recording event is processed successfully."""

    # NOTE (requirement 11.14): this check loops ``self.regions`` and also
    # emits a ``region="global"`` row from its no-regions guard. It is a
    # candidate for reclassification if a base-driven region loop is ever
    # adopted. Flagged only -- restructuring here would move row keys.
    meta = CheckMeta(
        check_id="SRA-CONFIG-03",
        title="AWS Config latest recording event is processed successfully",
        description=(
            "Checks AWS Config history delivery and applicable snapshot and SNS stream delivery."
        ),
        check_logic=(
            "Requires successful history delivery and evaluates snapshot and stream delivery when applicable."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="Config",
        resource_type="AWS::Config::ConfigurationRecorder",
        remediation=Remediation(
            text=(
                "Repair Config delivery using the S3 bucket and KMS key policies, and the SNS "
                "topic policy when a topic is configured."
            ),
            cli=(
                "aws configservice describe-delivery-channel-status --region <region>"
            ),
            console=(
                "Config console in each Region, Settings, review the delivery channel S3 "
                "bucket policy and, if configured, the SNS topic policy."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per delivery channel per Region.
        """
        if not self.regions:
            yield self.error(
                region="global",
                resource_id="config:global",
                actual_value="No regions specified for check",
                remediation="Specify at least one region when running the check",
            )
            return

        # Check each region for delivery channel status
        # Set by the guard below when a Region's Config state could not be
        # read. A global 'not found in any region' FAIL must not fire on the
        # strength of Regions that never answered.
        undetermined = False
        for region in self.regions:
            # Get delivery channels for the region
            channels_response = self.get_delivery_channels(region)

            if "Error" in channels_response:
                error = channels_response['Error']
                if self.is_not_configured(error):
                    # A declared semantic code: AWS answered and the control is
                    # absent. config declares AWSOrganizationsNotInUseException
                    # (DescribeOrganization) and NoSuchBucketPolicy
                    # (GetBucketPolicy); an empty recorder or channel list is a
                    # successful response, not an error, so nothing is declared for
                    # the describe_* operations themselves.
                    yield self.failed(
                        region=region,
                        resource_id=f"config:{self.account_id}:{region}",
                        actual_value=f"AWS Config is not configured in {region}",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"config:{self.account_id}:{region}",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                undetermined = True
                continue

            status_response = self.get_delivery_channel_status(region)

            if "Error" in status_response:
                error = status_response['Error']
                if self.is_not_configured(error):
                    # A declared semantic code: AWS answered and the control is
                    # absent. config declares AWSOrganizationsNotInUseException
                    # (DescribeOrganization) and NoSuchBucketPolicy
                    # (GetBucketPolicy); an empty recorder or channel list is a
                    # successful response, not an error, so nothing is declared for
                    # the describe_* operations themselves.
                    yield self.failed(
                        region=region,
                        resource_id=f"config:{self.account_id}:{region}",
                        actual_value=f"AWS Config is not configured in {region}",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"config:{self.account_id}:{region}",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                undetermined = True
                continue

            channels = channels_response.get('DeliveryChannels', [])
            channel_statuses = status_response.get('DeliveryChannelsStatus', [])

            if not channels:
                # No delivery channel found in this region
                yield self.failed(
                    region=region,
                    resource_id=f"arn:aws:config:{region}:{self.account_id}:deliveryChannel/default",
                    actual_value="No delivery channel found in this region",
                    remediation=(
                        f"Create a delivery channel in {region} using: aws configservice put-delivery-channel --delivery-channel name=default,s3BucketName=config-bucket-{self.account_id} --region {region}. "
                        f"Note: You must first create an S3 bucket with appropriate permissions for AWS Config."
                    ),
                )
                continue

            if not channel_statuses:
                # No delivery channel status found in this region
                yield self.failed(
                    region=region,
                    resource_id=f"arn:aws:config:{region}:{self.account_id}:deliveryChannel/default",
                    actual_value="No delivery channel status found in this region",
                    remediation=(
                        f"Check the delivery channel configuration in {region} and ensure it's properly configured. "
                        f"Verify S3 bucket permissions and, if configured, SNS topic permissions for AWS Config."
                    ),
                )
                continue

            for status in channel_statuses:
                channel_name = status.get('name', 'default')
                resource_id = f"config:deliveryChannel:{channel_name}"
                matches = [channel for channel in channels if channel.get('name') == status.get('name') and status.get('name') is not None]
                channel = matches[0] if matches else (channels[0] if len(channels) == 1 and (not status.get('name') or not channels[0].get('name')) else None)
                snapshot_configured = None if channel is None else bool(channel.get('configSnapshotDeliveryProperties', {}).get('deliveryFrequency'))
                stream_configured = None if channel is None else bool(channel.get('snsTopicARN'))
                history = status.get('configHistoryDeliveryInfo') or {}
                snapshot = status.get('configSnapshotDeliveryInfo') or {}
                stream = status.get('configStreamDeliveryInfo') or {}
                failures = []
                errors = []
                if history.get('lastStatus') not in ("Success", "SUCCESS"):
                    failures.append('History')
                for name, info, configured in (("Snapshot", snapshot, snapshot_configured), ("Stream", stream, stream_configured)):
                    value = info.get('lastStatus')
                    if value in ("Success", "SUCCESS"):
                        continue
                    normalized = value.lower() if isinstance(value, str) and value.isascii() else None
                    if normalized == "failure":
                        if name == "Stream" and configured is False:
                            errors.append(name)
                        else:
                            failures.append(name)
                        continue
                    missing = 'lastStatus' not in info
                    has_error = bool(info.get('lastErrorCode') or info.get('lastErrorMessage'))
                    attempted = name == "Snapshot" and bool(info.get('lastAttemptTime') or info.get('lastSuccessfulTime') or info.get('nextDeliveryTime'))
                    if configured is False and (normalized == "not_applicable" or (missing and not has_error and not attempted)):
                        continue
                    errors.append(name)
                actual = (
                    f"Delivery channel '{channel_name}': Config History: {history.get('lastStatus', 'UNKNOWN')} "
                    f"(Last attempt: {history.get('lastAttemptTime', 'UNKNOWN')}, Last success: {history.get('lastSuccessfulTime', 'UNKNOWN')}), "
                    f"Config Snapshot: {snapshot.get('lastStatus', 'UNKNOWN')}, Config Stream: {stream.get('lastStatus', 'UNKNOWN')}; "
                    f"Failed: {', '.join(failures) or 'none'}; indeterminate: {', '.join(errors) or 'none'}"
                )
                if failures:
                    yield self.failed(region=region, resource_id=resource_id, actual_value=actual,
                        remediation="Check S3 bucket and KMS key policies for history or snapshot failures, and SNS topic policy for stream failures.")
                elif errors:
                    yield self.error(region=region, resource_id=resource_id, actual_value=actual,
                        remediation="Verify delivery status and configuration, and retry after a delivery attempt.")
                else:
                    yield self.passed(region=region, resource_id=resource_id, actual_value=actual)
