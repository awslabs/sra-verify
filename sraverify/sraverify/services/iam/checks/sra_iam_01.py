"""
Check for IAM users in an AWS account (SRA-IAM-01).
"""
from collections.abc import Iterable
from typing import Any, Dict, List, Set

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.iam.base import IAMCheck


class SRA_IAM_01(IAMCheck):
    """Detect the presence of IAM users in an AWS account.

    AWS Security Reference Architecture (SRA) guidance directs customers to
    use federated identity through AWS IAM Identity Center and to assume IAM
    roles rather than provision long-lived IAM users. Any IAM user in an
    account is a deviation worth reporting as a HIGH severity finding.
    """

    meta = CheckMeta(
        check_id="SRA-IAM-01",
        title="Account contains no IAM users",
        description=(
            "This check verifies that the AWS account contains no IAM users. "
            "AWS Security Reference Architecture (SRA) guidance recommends "
            "federated identity through AWS IAM Identity Center and assuming "
            "IAM roles over provisioning IAM users with long-lived credentials. "
            "Long-lived credentials associated with an IAM user increase the "
            "risk of credential exposure, complicate credential rotation, and "
            "contribute to identity sprawl. Replace each IAM user with "
            "federated access through IAM Identity Center or an IAM role."
        ),
        check_logic=(
            "Call the IAM ListUsers API against the global endpoint "
            "(us-east-1) and paginate until all users are retrieved. "
            "One FAIL finding is created for each IAM user returned by the "
            "API call. If no IAM users are returned, one PASS finding is "
            "created for the account. If the API call fails, one ERROR "
            "finding is created and no PASS or FAIL findings are produced."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="IAM",
        resource_type="AWS::IAM::User",
        remediation=Remediation(
            text=(
                "Replace each IAM user with federated access through AWS IAM "
                "Identity Center or with an IAM role that issues temporary "
                "credentials, then delete the IAM user once migration is "
                "complete."
            ),
            cli=(
                "aws iam list-users\n"
                "aws iam delete-user --user-name <user-name>"
            ),
            console=(
                "IAM Identity Center console, Users, to provision federated "
                "access; then IAM console, Users, select the user, Delete."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per IAM user, or one Finding for the account.
        """
        region = self.GLOBAL_REGION  # "us-east-1"

        response = self.list_users()

        # Error path: a single ERROR finding, no PASS or FAIL findings.
        if "Error" in response:
            error = response["Error"]
            yield self.error(
                region=region,
                resource_id=self.account_id,
                actual_value=(
                    f"{error['Operation']} failed: {error['Code']}: "
                    f"{error['Message']}"
                ),
                remediation=self._remediation_for(error),
            )
            return

        # Deduplicate users by ARN, preserving first occurrence.
        users = response.get("Users", [])
        seen_arns: Set[str] = set()
        distinct_users: List[Dict[str, Any]] = []
        for user in users:
            arn = user.get("Arn")
            if arn and arn not in seen_arns:
                seen_arns.add(arn)
                distinct_users.append(user)

        # PASS path: zero IAM users found in the account.
        if not distinct_users:
            yield self.passed(
                region=region,
                resource_id=self.account_id,
                actual_value="0 IAM users found in the account.",
            )
            return

        # FAIL path: one finding per distinct IAM user ARN.
        remediation = (
            "Replace the IAM user with federated access through AWS IAM "
            "Identity Center or assume an IAM role with temporary "
            "credentials, then delete the IAM user after migration is "
            "complete."
        )
        for user in distinct_users:
            yield self.failed(
                region=region,
                resource_id=user["Arn"],
                actual_value=(
                    f"IAM user '{user.get('UserName', '')}' exists in the "
                    "account."
                ),
                remediation=remediation,
            )
