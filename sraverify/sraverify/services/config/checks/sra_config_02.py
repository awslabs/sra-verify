"""
SRA-CONFIG-02: AWS Config Delivery Channel Configured.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.config.base import ConfigCheck


class SRA_CONFIG_02(ConfigCheck):
    """Check if AWS Config recorder is running."""

    # NOTE (requirement 11.14): this check loops ``self.regions`` and also
    # emits a ``region="global"`` row from its no-regions guard. It is a
    # candidate for reclassification if a base-driven region loop is ever
    # adopted. Flagged only -- restructuring here would move row keys.
    meta = CheckMeta(
        check_id="SRA-CONFIG-02",
        title="AWS Config recorder is running",
        description=(
            "This check verifies that configuration recorder is running. AWS Config configuration "
            "recorder must be started and running to record resource configurations. If you set up "
            "AWS Config by using the console or the AWS CLI, AWS Config automatically creates and "
            "then starts the configuration recorder for you. Users with right permission have the "
            "ability to stop configuration recorder."
        ),
        check_logic=(
            "Checks if AWS Config recorder is running by verifying the lastStatus is SUCCESS."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="Config",
        resource_type="AWS::Config::ConfigurationRecorder",
        remediation=Remediation(
            text=(
                "Start the AWS Config configuration recorder in every enabled Region and "
                "confirm its last status is SUCCESS."
            ),
            cli=(
                "aws configservice start-configuration-recorder "
                "--configuration-recorder-name default --region <region>"
            ),
            console=(
                "Config console in each Region, Settings, confirm Recording is on and the "
                "recorder reports no delivery errors."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Region.
        """
        if not self.regions:
            yield self.error(
                region="global",
                resource_id="config:global",
                actual_value="No regions specified for check",
                remediation="Specify at least one region when running the check",
            )
            return

        # Check each region for configuration recorder status
        # Set by the guard below when a Region's Config state could not be
        # read. A global 'not found in any region' FAIL must not fire on the
        # strength of Regions that never answered.
        undetermined = False
        for region in self.regions:
            # Get configuration recorders for the region
            recorders_response = self.get_configuration_recorders(region)

            if "Error" in recorders_response:
                error = recorders_response['Error']
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

            status_response = self.get_configuration_recorder_status(region)

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

            recorders = recorders_response.get('ConfigurationRecorders', [])
            recorder_statuses = status_response.get(
                'ConfigurationRecordersStatus', []
            )

            if not recorders:
                # No configuration recorder found in this region
                yield self.failed(
                    region=region,
                    resource_id=f"arn:aws:config:{region}:{self.account_id}:configurationRecorder/default",
                    actual_value="No configuration recorder found in this region",
                    remediation=(
                        f"First create a configuration recorder in {region} using: aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=arn:aws:iam::{self.account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig --recording-group allSupported=true,includeGlobalResourceTypes=true --region {region}. "
                        f"Then start the recorder with: aws configservice start-configuration-recorder --configuration-recorder-name default --region {region}"
                    ),
                )
                continue

            # Configuration recorder exists, check if it's running
            recorder_name = recorders[0].get('name', 'default')

            # Find the status for this recorder
            recorder_status = next((status for status in recorder_statuses if status.get('name') == recorder_name), None)

            # Get the full ARN from the status if available
            recorder_arn = None
            if recorder_status and 'arn' in recorder_status:
                recorder_arn = recorder_status.get('arn')
            else:
                # Construct the Config Recorder ARN if not available in status
                recorder_arn = f"arn:aws:config:{region}:{self.account_id}:configurationRecorder/{recorder_name}"

            if not recorder_status:
                # The recorder exists, but DescribeConfigurationRecorderStatus
                # returned no entry for it. AWS answered and its answer is silent
                # about this recorder, so whether it is recording is undetermined --
                # an ERROR, not a FAIL asserting the control is absent.
                yield self.error(
                    region=region,
                    resource_id=recorder_arn,
                    actual_value=(
                        f"DescribeConfigurationRecorderStatus returned no status "
                        f"entry for recorder '{recorder_name}'"
                    ),
                    remediation=(
                        f"Re-run the scan; if it persists, confirm the recorder in "
                        f"{region} is fully provisioned and that the member role may "
                        f"call config:DescribeConfigurationRecorderStatus"
                    ),
                )
                continue

            # Check if the recorder is recording
            is_recording = recorder_status.get('recording', False)
            last_status = recorder_status.get('lastStatus', 'UNKNOWN')
            last_error_code = recorder_status.get('lastErrorCode', '')
            last_error_message = recorder_status.get('lastErrorMessage', '')

            if is_recording and last_status == "SUCCESS":
                # Configuration recorder is running successfully
                yield self.passed(
                    region=region,
                    resource_id=recorder_arn,
                    actual_value=f"Configuration recorder '{recorder_name}' is running with lastStatus: SUCCESS",
                )
            elif is_recording:
                # Configuration recorder is recording but not in SUCCESS state
                error_info = f"lastStatus: {last_status}"
                if last_error_code:
                    error_info += f", errorCode: {last_error_code}"
                if last_error_message:
                    error_info += f", errorMessage: {last_error_message}"

                yield self.failed(
                    region=region,
                    resource_id=recorder_arn,
                    actual_value=f"Configuration recorder '{recorder_name}' is recording but has issues: {error_info}",
                    remediation=(
                        f"Check the AWS Config logs and permissions in {region}. "
                        f"Ensure the Config service role has the necessary permissions to record resources."
                    ),
                )
            else:
                # Configuration recorder is not recording
                yield self.failed(
                    region=region,
                    resource_id=recorder_arn,
                    actual_value=f"Configuration recorder '{recorder_name}' is not recording",
                    remediation=(
                        f"Start the configuration recorder in {region} using the AWS CLI command: "
                        f"aws configservice start-configuration-recorder --configuration-recorder-name {recorder_name} --region {region}"
                    ),
                )
