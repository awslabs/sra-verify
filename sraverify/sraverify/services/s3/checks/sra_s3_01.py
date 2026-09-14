"""
SRA-S3-01: S3 restrict public bucket is enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.s3.base import S3Check


class SRA_S3_01(S3Check):
    """Check if S3 restrict public bucket is enabled for the account."""

    meta = CheckMeta(
        check_id="SRA-S3-01",
        title="S3 restrict public bucket is enabled",
        description=(
            "This check verifies whether S3 should restrict public policies for S3 buckets. "
            "Setting this restricts access to this bucket to only AWS service principals and authorized users "
            "within this account if the bucket has a public policy."
        ),
        check_logic=(
            "Check if RestrictPublicBuckets is set to true in the account's public access block configuration."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="S3",
        resource_type="AWS::S3::AccountPublicAccessBlock",
        remediation=Remediation(
            text=(
                "Enable S3 Restrict Public Buckets at the account level so that a bucket "
                "carrying a public policy is reachable only by AWS service principals and "
                "authorized users within this account."
            ),
            cli=(
                "aws s3control put-public-access-block --account-id <account-id> "
                "--public-access-block-configuration RestrictPublicBuckets=true"
            ),
            console=(
                "S3 console, Block Public Access settings for this account, Edit, select "
                "Block public and cross-account access to buckets and objects through any "
                "public bucket or access point policies, Save changes."
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

        # Check if the configuration exists and RestrictPublicBuckets is enabled
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
                checked_value="RestrictPublicBuckets: true",
            )
            return

        restrict_public_buckets = public_access_config.get('RestrictPublicBuckets', False)

        if restrict_public_buckets:
            yield self.passed(
                region="global",  # S3 public access block is a global setting
                resource_id=self.account_id,
                actual_value="RestrictPublicBuckets setting is true",
                checked_value="RestrictPublicBuckets: true",
            )
        else:
            yield self.failed(
                region="global",  # S3 public access block is a global setting
                resource_id=self.account_id,
                actual_value="RestrictPublicBuckets setting is false",
                remediation=(
                    "Enable S3 Restrict Public Buckets at the account level using the AWS CLI command: "
                    f"aws s3control put-public-access-block --account-id {self.account_id} "
                    "--public-access-block-configuration RestrictPublicBuckets=true"
                ),
                checked_value="RestrictPublicBuckets: true",
            )
