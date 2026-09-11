"""
SRA-S3-02: S3 block public ACLs is set.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.s3.base import S3Check


class SRA_S3_02(S3Check):
    """Check if S3 block public ACLs is enabled for the account."""

    meta = CheckMeta(
        check_id="SRA-S3-02",
        title="S3 block public ACLs is set",
        description=(
            "This check verifies whether S3 public block access control lists (ACLs) for buckets and object is enabled. "
            "Setting this fails prevents from setting a public ACL on S3 buckets and Objects. It also prevent creating "
            "a bucket with public ACL and uploading a object with public ACL."
        ),
        check_logic=(
            "Check if BlockPublicAcls is set to true in the account's public access block configuration."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="S3",
        resource_type="AWS::S3::AccountPublicAccessBlock",
        remediation=Remediation(
            text=(
                "Enable S3 Block Public ACLs at the account level so that a public ACL "
                "cannot be set on a bucket or an object, and so that creating a bucket or "
                "uploading an object with a public ACL is rejected."
            ),
            cli=(
                "aws s3control put-public-access-block --account-id <account-id> "
                "--public-access-block-configuration BlockPublicAcls=true"
            ),
            console=(
                "S3 console, Block Public Access settings for this account, Edit, select "
                "Block public access to buckets and objects granted through new access "
                "control lists, Save changes."
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
        public_access_config = self.get_public_access()

        # Check if the configuration exists and BlockPublicAcls is enabled
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
                checked_value="BlockPublicAcls: true",
            )
            return

        block_public_acls = public_access_config.get('BlockPublicAcls', False)

        if block_public_acls:
            yield self.passed(
                region="global",  # S3 public access block is a global setting
                resource_id=self.account_id,
                actual_value="BlockPublicAcls setting is true",
                checked_value="BlockPublicAcls: true",
            )
        else:
            yield self.failed(
                region="global",  # S3 public access block is a global setting
                resource_id=self.account_id,
                actual_value="BlockPublicAcls setting is false",
                remediation=(
                    "Enable S3 Block Public Access at the account level using the AWS CLI command: "
                    f"aws s3control put-public-access-block --account-id {self.account_id} "
                    "--public-access-block-configuration BlockPublicAcls=true"
                ),
                checked_value="BlockPublicAcls: true",
            )
