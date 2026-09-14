"""
SRA-S3-03: S3 ignore public ACL is enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.s3.base import S3Check


class SRA_S3_03(S3Check):
    """Check if S3 ignore public ACLs is enabled for the account."""

    meta = CheckMeta(
        check_id="SRA-S3-03",
        title="S3 ignore public ACL is enabled",
        description=(
            "This check verifies whether the IgnorePublicACLs is set to True. Setting this causes Amazon S3 "
            "to ignore all public ACLs on buckets and objects in the bucket."
        ),
        check_logic=(
            "Check if IgnorePublicAcls is set to true in the account's public access block configuration."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="S3",
        resource_type="AWS::S3::AccountPublicAccessBlock",
        remediation=Remediation(
            text=(
                "Enable S3 Ignore Public ACLs at the account level so that Amazon S3 "
                "ignores every public ACL already attached to a bucket or an object."
            ),
            cli=(
                "aws s3control put-public-access-block --account-id <account-id> "
                "--public-access-block-configuration IgnorePublicAcls=true"
            ),
            console=(
                "S3 console, Block Public Access settings for this account, Edit, select "
                "Block public access to buckets and objects granted through any access "
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

        # Check if the configuration exists and IgnorePublicAcls is enabled
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
                checked_value="IgnorePublicAcls: true",
            )
            return

        ignore_public_acls = public_access_config.get('IgnorePublicAcls', False)

        if ignore_public_acls:
            yield self.passed(
                region="global",  # S3 public access block is a global setting
                resource_id=self.account_id,
                actual_value="IgnorePublicAcls setting is true",
                checked_value="IgnorePublicAcls: true",
            )
        else:
            yield self.failed(
                region="global",  # S3 public access block is a global setting
                resource_id=self.account_id,
                actual_value="IgnorePublicAcls setting is false",
                remediation=(
                    "Enable S3 Ignore Public ACLs at the account level using the AWS CLI command: "
                    f"aws s3control put-public-access-block --account-id {self.account_id} "
                    "--public-access-block-configuration IgnorePublicAcls=true"
                ),
                checked_value="IgnorePublicAcls: true",
            )
