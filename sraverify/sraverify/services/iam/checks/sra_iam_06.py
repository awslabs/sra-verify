"""
Check that the account password policy meets the SRA Verify baseline (SRA-IAM-06).
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import GLOBAL_REGION, Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.iam.base import IAMCheck

#: CIS AWS Foundations Benchmark / Security Hub CSPM IAM.15.
_MIN_LENGTH = 14
#: CIS AWS Foundations Benchmark / Security Hub CSPM IAM.16.
_MIN_REUSE_PREVENTION = 24
#: Security Hub CSPM IAM.7 defaults, in report order.
_REQUIRED_FLAGS: tuple[str, ...] = (
    "RequireUppercaseCharacters",
    "RequireLowercaseCharacters",
    "RequireNumbers",
    "RequireSymbols",
)


class SRA_IAM_06(IAMCheck):
    """Account password policy meets the SRA Verify baseline."""

    meta = CheckMeta(
        check_id="SRA-IAM-06",
        title="Account password policy meets the SRA Verify baseline",
        description=(
            "This check verifies that the account has a custom IAM password policy and "
            "that it is at least as strict as the SRA Verify baseline: a minimum length "
            "of 14, at least one uppercase letter, lowercase letter, number and symbol, "
            "and reuse prevention of 24 passwords. AWS SRA recommends setting every "
            "member and management account password policy to the organization's "
            "security standard. SRA Verify cannot read that standard, so it applies the "
            "baseline from CIS AWS Foundations Benchmark (Security Hub CSPM IAM.15 and "
            "IAM.16) and the character classes of IAM.7. Password expiry is not "
            "required. An account without a custom policy uses the AWS default and fails."
        ),
        check_logic=(
            "Call IAM GetAccountPasswordPolicy. FAIL on NoSuchEntity (no custom "
            "policy). FAIL naming each setting below baseline: MinimumPasswordLength "
            "< 14, PasswordReusePrevention < 24 or absent, or any Require* flag false. "
            "PASS otherwise. ERROR on any other error. One global row."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service="IAM",
        resource_type="AWS::Organizations::Account",
        remediation=Remediation(
            text=(
                "Set an account password policy that requires at least 14 characters, "
                "uppercase, lowercase, numbers and symbols, and prevents reuse of the "
                "last 24 passwords, or stricter if the organization standard requires it."
            ),
            cli=(
                "aws iam update-account-password-policy --minimum-password-length 14 "
                "--require-uppercase-characters --require-lowercase-characters "
                "--require-numbers --require-symbols --password-reuse-prevention 24 "
                "--allow-users-to-change-password"
            ),
            console=(
                "IAM console, Account settings, Password policy, Edit, Custom, set the "
                "values, Save changes."
            ),
        ),
        sra_sections=("Management account", "AWS Identity and Access Management"),
        additional_urls=(
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html",
            "https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One global Finding for the account.
        """
        response = self.get_account_password_policy()

        if "Error" in response:
            error = response["Error"]
            if self.is_not_configured(error):
                yield self.failed(
                    region=GLOBAL_REGION,
                    resource_id=self.account_id,
                    actual_value=(
                        "No custom password policy is set; the account uses the AWS "
                        "default policy"
                    ),
                )
            else:
                yield self.error(
                    region=GLOBAL_REGION,
                    resource_id=self.account_id,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
            return

        policy = response.get("PasswordPolicy", {})
        shortfalls = []

        length = policy.get("MinimumPasswordLength")
        if not isinstance(length, int) or length < _MIN_LENGTH:
            shortfalls.append(f"MinimumPasswordLength {length} < {_MIN_LENGTH}")

        # AWS omits PasswordReusePrevention when reuse prevention is off.
        reuse = policy.get("PasswordReusePrevention")
        if reuse is None:
            shortfalls.append("PasswordReusePrevention not set")
        elif reuse < _MIN_REUSE_PREVENTION:
            shortfalls.append(f"PasswordReusePrevention {reuse} < {_MIN_REUSE_PREVENTION}")

        for flag in _REQUIRED_FLAGS:
            if policy.get(flag) is not True:
                shortfalls.append(f"{flag} false")

        if shortfalls:
            yield self.failed(
                region=GLOBAL_REGION,
                resource_id=self.account_id,
                actual_value=f"Password policy is below baseline: {'; '.join(shortfalls)}",
            )
        else:
            yield self.passed(
                region=GLOBAL_REGION,
                resource_id=self.account_id,
                actual_value=(
                    f"Password policy meets baseline: MinimumPasswordLength {length}, "
                    f"PasswordReusePrevention {reuse}, all four character classes required"
                ),
            )
