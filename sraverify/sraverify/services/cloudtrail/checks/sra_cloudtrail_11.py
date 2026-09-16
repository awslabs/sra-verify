"""
SRA-CLOUDTRAIL-11: Organization CloudTrail Logs Centralized in Log Archive Account.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.cloudtrail.base import CloudTrailCheck


class SRA_CLOUDTRAIL_11(CloudTrailCheck):
    """Check if organization trails logs are delivered to a centralized S3 bucket in the Log Archive account."""

    meta = CheckMeta(
        check_id="SRA-CLOUDTRAIL-11",
        title="Organization trail Logs are delivered to a centralized S3 bucket in the Log Archive Account",
        description=(
            "This check verifies whether the corresponding S3 buckets that stores organization trail logs "
            "in created in Log Archive account. This separates the management and usage of CloudTrail log "
            "privileges. The Log Archive account is dedicated to ingesting and archiving all security-related "
            "logs and backups."
        ),
        check_logic=(
            "Check if organization trails are configured to deliver logs to S3 buckets owned by "
            "the Log Archive account by comparing the S3 bucket ARN with the provided Log Archive account IDs."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="CloudTrail",
        resource_type="AWS::CloudTrail::Trail",
        remediation=Remediation(
            text=(
                "Point the organization trail at an S3 bucket owned by the Log Archive "
                "account so that log storage is separated from log administration."
            ),
            cli=(
                "aws cloudtrail update-trail --name <trail-name> "
                "--s3-bucket-name aws-controltower-logs-<log-archive-account-id>-<region>"
            ),
            console=(
                "CloudTrail console, Trails, select the organization trail, Edit Storage "
                "location, and choose an existing bucket owned by the Log Archive account."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per organization trail, or one Finding when the check
            cannot be completed.
        """
        # Get organization trails
        org_response = self.get_organization_trails()

        if "Error" in org_response:
            error = org_response['Error']
            if self.is_not_configured(error):
                yield self.failed(
                    region="global",
                    resource_id=f"organization/{self.account_id}",
                    actual_value="No CloudTrail trail exists for this account, so no organization trail is configured",
                )
            else:
                yield self.error(
                    region="global",
                    resource_id=f"organization/{self.account_id}",
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
            return

        org_trails = org_response.get('trailList', [])

        if not org_trails:
            yield self.failed(
                region="global",
                resource_id=f"organization/{self.account_id}",
                checked_value="S3 bucket in Log Archive account",
                actual_value="No organization trails found",
                remediation=(
                    "Create an organization trail with S3 bucket in the Log Archive account using the AWS CLI command: "
                    "aws cloudtrail create-trail --name org-trail --is-organization-trail "
                    "--s3-bucket-name aws-controltower-logs-{LOG_ARCHIVE_ACCOUNT_ID}-{REGION}"
                ),
            )
            return

        log_archive_accounts = self.log_archive_accounts

        if not log_archive_accounts:
            yield self.error(
                region="global",
                resource_id=f"organization/{self.account_id}",
                checked_value="S3 bucket in Log Archive account",
                actual_value="Log Archive Account ID not provided",
                remediation="Provide the Log Archive account IDs using --log-archive-account flag",
            )
            return

        # Check each organization trail for S3 bucket ownership
        for trail in org_trails:
            trail_name = trail.get('Name', 'Unknown')
            trail_arn = trail.get('TrailARN', 'Unknown')
            s3_bucket_name = trail.get('S3BucketName', '')

            # Get the home region from the trail
            home_region = trail.get('HomeRegion', 'Unknown')

            # We need to determine the owner of the S3 bucket
            # For this check, we'll use the bucket name to infer ownership
            # Another implementation could be to make an S3 API call to get the bucket owner
            # But for this example, we'll assume the bucket name contains the account ID or has a specific pattern

            # Check if we can determine the bucket owner from the trail configuration
            bucket_owner_account = None

            # Try to get the bucket owner from the S3BucketOwnerName field if available
            s3_bucket_owner = trail.get('S3BucketOwnerName', '')
            if s3_bucket_owner:
                # If we have the bucket owner name, we can check if it's in the log archive accounts
                # This is a simplification - in reality, you'd need to map account IDs to account names
                bucket_owner_account = s3_bucket_owner

            # If we couldn't determine the bucket owner, check if the bucket name contains the account ID
            if not bucket_owner_account:
                for log_archive_account in log_archive_accounts:
                    if log_archive_account in s3_bucket_name:
                        bucket_owner_account = log_archive_account
                        break

            # Create appropriate resource IDs based on whether the bucket is in the Log Archive account
            if bucket_owner_account and bucket_owner_account in log_archive_accounts:
                resource_id = f"cloudtrail logs being delivered to Log Archive account {log_archive_accounts[0]} and bucket name {s3_bucket_name}"
            else:
                resource_id = f"cloudtrail logs not being delivered to S3 bucket in the Log Archive account"

            # If we still couldn't determine the bucket owner, we'll need to make an API call
            # For this example, we'll just report that we couldn't determine the bucket owner
            if not bucket_owner_account:
                # Generate a recommended bucket name using the first log archive account
                recommended_bucket_name = f"aws-controltower-logs-{log_archive_accounts[0]}-{home_region}"

                # The bucket owner could not be resolved, so whether the bucket
                # lives in a Log Archive account is undetermined -- an ERROR, not a
                # FAIL asserting it does not.
                yield self.error(
                    region="global",
                    resource_id=resource_id,
                    checked_value=f"S3 bucket in Log Archive account ({', '.join(log_archive_accounts)})",
                    actual_value=(
                        f"The owning account of S3 bucket '{s3_bucket_name}' used by "
                        f"organization trail '{trail_name}' was not resolved"
                    ),
                    remediation=(
                        f"Update the organization trail '{trail_name}' to use an S3 bucket in the Log Archive account "
                        f"using the AWS CLI command: aws cloudtrail update-trail --name {trail_name} "
                        f"--s3-bucket-name {recommended_bucket_name}"
                    ),
                )
                continue

            # Check if the bucket owner is in the log archive accounts
            if bucket_owner_account in log_archive_accounts:
                # Trail is using an S3 bucket in the Log Archive account
                yield self.passed(
                    region="global",
                    resource_id=resource_id,
                    checked_value=f"S3 bucket in Log Archive account ({', '.join(log_archive_accounts)})",
                    actual_value=(
                        f"Organization trail '{trail_name}' is using S3 bucket '{s3_bucket_name}' "
                        f"owned by Log Archive account {bucket_owner_account}"
                    ),
                )
            else:
                # Trail is not using an S3 bucket in the Log Archive account
                # Generate a recommended bucket name using the first log archive account
                recommended_bucket_name = f"aws-controltower-logs-{log_archive_accounts[0]}-{home_region}"

                yield self.failed(
                    region="global",
                    resource_id=resource_id,
                    checked_value=f"S3 bucket in Log Archive account ({', '.join(log_archive_accounts)})",
                    actual_value=(
                        f"Organization trail '{trail_name}' is using S3 bucket '{s3_bucket_name}' "
                        f"owned by account {bucket_owner_account}, which is not a Log Archive account"
                    ),
                    remediation=(
                        f"Update the organization trail '{trail_name}' to use an S3 bucket in the Log Archive account "
                        f"using the AWS CLI command: aws cloudtrail update-trail --name {trail_name} "
                        f"--s3-bucket-name {recommended_bucket_name}"
                    ),
                )
