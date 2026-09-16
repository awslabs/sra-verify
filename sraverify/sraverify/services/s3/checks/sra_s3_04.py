"""
SRA-S3-04: S3 block public policy is enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.s3.base import S3Check


class SRA_S3_04(S3Check):
    """Check if S3 block public policy is enabled for the account."""

    meta = CheckMeta(
        check_id="SRA-S3-04",
        title="S3 block public policy is enabled",
        description=(
            "This check verifies whether S3 should block public bucket policies for buckets. "
            "Setting this causes Amazon S3 to reject calls that attaches a public access bucket policy to a S3 bucket."
        ),
        check_logic=(
            "Check if BlockPublicPolicy is set to true in the account's public access block configuration."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="S3",
        resource_type="AWS::S3::AccountPublicAccessBlock",
        remediation=Remediation(
            text=(
                "Enable S3 Block Public Policy at the account level so that Amazon S3 "
                "rejects any call attaching a public access bucket policy to a bucket."
            ),
            cli=(
                "aws s3control put-public-access-block --account-id <account-id> "
                "--public-access-block-configuration BlockPublicPolicy=true"
            ),
            console=(
                "S3 console, Block Public Access settings for this account, Edit, select "
                "Block public access to buckets and objects granted through new public "
                "bucket or access point policies, Save changes."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding for the account-level public access block setting.
        """
        # Get public access block configuration using the base class method
        # This will use the cache if available or make API calls if needed
        public_access_response = self.get_public_access()

        if "Error" in public_access_response:
            error = public_access_response['Error']
            if self.is_not_configured(error):
                yield self.failed(
                    region="global",
                    resource_id=self.account_id,
                    actual_value="No public access block configuration found",
                )
            else:
                yield self.error(
                    region="global",
                    resource_id=self.account_id,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
            return

        public_access_config = public_access_response.get(
            'PublicAccessBlockConfiguration', {}
        )

        # Check if the configuration exists and BlockPublicPolicy is enabled
        if not public_access_config:
            yield self.failed(
                region="global",  # S3 public access block is a global setting
                resource_id=self.account_id,
                actual_value="No public access block configuration found",
                remediation=(
                    "Enable S3 Block Public Access at the account level using the AWS CLI command: "
                    f"aws s3control put-public-access-block --account-id {self.account_id} "
                    "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
                    "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                ),
                checked_value="BlockPublicPolicy: true",
            )
            return

        block_public_policy = public_access_config.get('BlockPublicPolicy', False)

        if block_public_policy:
            yield self.passed(
                region="global",  # S3 public access block is a global setting
                resource_id=self.account_id,
                actual_value="BlockPublicPolicy setting is true",
                checked_value="BlockPublicPolicy: true",
            )
        else:
            yield self.failed(
                region="global",  # S3 public access block is a global setting
                resource_id=self.account_id,
                actual_value="BlockPublicPolicy setting is false",
                remediation=(
                    "Enable S3 Block Public Policy at the account level using the AWS CLI command: "
                    f"aws s3control put-public-access-block --account-id {self.account_id} "
                    "--public-access-block-configuration BlockPublicPolicy=true"
                ),
                checked_value="BlockPublicPolicy: true",
            )
