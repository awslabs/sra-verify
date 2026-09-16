"""
SRA-CONFIG-01: AWS Config Recorder Configured.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.config.base import ConfigCheck


class SRA_CONFIG_01(ConfigCheck):
    """Check if AWS Config recorder is configured in each region."""

    # NOTE (requirement 11.14): this check loops ``self.regions`` and also
    # emits a ``region="global"`` row from its no-regions guard. It is a
    # candidate for reclassification if a base-driven region loop is ever
    # adopted. Flagged only -- restructuring here would move row keys.
    meta = CheckMeta(
        check_id="SRA-CONFIG-01",
        title="AWS Config recorder is configured in this region",
        description=(
            "This check verifies that a configuration recorder exists in the AWS Region. "
            "AWS Config uses the configuration recorder to detect changes in your resource configurations "
            "and capture these changes as configuration items. You must create a configuration recorder "
            "in every AWS Region for AWS Config can track your resource configurations in the region."
        ),
        check_logic=(
            "Checks if AWS Config recorder exists in each region using describe-configuration-recorder-status API."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="Config",
        resource_type="AWS::Config::ConfigurationRecorder",
        remediation=Remediation(
            text=(
                "Create a configuration recorder in every enabled Region and start it, "
                "so AWS Config records resource configuration changes there."
            ),
            cli=(
                "aws configservice put-configuration-recorder "
                "--configuration-recorder name=default,roleARN=<AWSServiceRoleForConfig-arn> "
                "--recording-group allSupported=true,includeGlobalResourceTypes=true "
                "--region <region>"
            ),
            console=(
                "Config console in each Region, Settings, Edit, enable recording for all "
                "resource types, Save."
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

        # Check each region for configuration recorder
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
                        f"1. Check if the AWS Config service-linked role exists: aws iam get-role --role-name AWSServiceRoleForConfig. "
                        f"2. If the role doesn't exist, create it: aws iam create-service-linked-role --aws-service-name config.amazonaws.com. "
                        f"3. Create a configuration recorder in {region}: aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=arn:aws:iam::{self.account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig --recording-group allSupported=true,includeGlobalResourceTypes=true --region {region}"
                    ),
                )
            else:
                # Configuration recorder exists, check if it's enabled
                recorder_name = recorders[0].get('name', 'default')
                recorder_role_arn = recorders[0].get('roleARN', '')

                # Construct the Config Recorder ARN
                recorder_arn = f"arn:aws:config:{region}:{self.account_id}:configurationRecorder/{recorder_name}"

                # Find the status for this recorder
                recorder_status = next((status for status in recorder_statuses if status.get('name') == recorder_name), None)

                if recorder_status and recorder_status.get('recording', False):
                    # Configuration recorder exists and is recording
                    yield self.passed(
                        region=region,
                        resource_id=recorder_arn,
                        actual_value=f"Configuration recorder '{recorder_name}' exists and is recording",
                    )
                elif recorder_status:
                    # Configuration recorder exists but is not recording
                    yield self.failed(
                        region=region,
                        resource_id=recorder_arn,
                        actual_value=f"Configuration recorder '{recorder_name}' exists but is not recording",
                        remediation=(
                            f"Start the configuration recorder in {region} using the AWS CLI command: "
                            f"aws configservice start-configuration-recorder --configuration-recorder-name {recorder_name} --region {region}"
                        ),
                    )
                else:
                    # The recorder exists, but DescribeConfigurationRecorderStatus
                    # returned no entry for it. AWS answered and its answer is silent
                    # about this recorder, so whether it is recording is undetermined --
                    # which is an ERROR, not a FAIL asserting the control is absent.
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
