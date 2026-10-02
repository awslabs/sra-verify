"""
SRA-SECURITYHUB-17: The effective Security Hub policy enables every scanned Region per account.
"""
from collections.abc import Iterable

from sraverify.core.accounts import is_active_account
from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityhub.base import SECURITYHUB_POLICY_TYPE, SecurityHubCheck


class SRA_SECURITYHUB_17(SecurityHubCheck):
    """Check if every active account's effective Security Hub policy covers the scan."""

    meta = CheckMeta(
        check_id="SRA-SECURITYHUB-17",
        title="Effective Security Hub V2 policy enables every scanned Region for every active account",
        description=(
            "This check verifies that the effective Security Hub policy for every active "
            "account enables Security Hub in each scanned Region. A root policy can be narrowed "
            "by a child policy on an OU or account using @@remove or @@assign, and "
            "disable_in_regions takes precedence over enable_in_regions, so a root attachment "
            "alone does not prove coverage. The effective policy is what AWS applies to the "
            "account. One row is produced per active account."
        ),
        check_logic=(
            "Call organizations:ListAccounts, keep State ACTIVE, then DescribeEffectivePolicy "
            "with PolicyType SECURITYHUB_POLICY per account. Passes if every scanned Region is "
            "enabled (named or ALL_SUPPORTED) and not disabled (named or ALL_SUPPORTED). Fails "
            "on EffectivePolicyNotFoundException or any uncovered Region, naming them."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="SecurityHub",
        resource_type="AWS::Organizations::Account",
        remediation=Remediation(
            text=(
                "Remove the child Security Hub policy that disables or drops these Regions for "
                "this account's OU or the account itself, or attach a Security Hub policy that "
                "enables them."
            ),
            cli=(
                "aws organizations list-policies-for-target --target-id <ou-or-account-id> "
                "--filter SECURITYHUB_POLICY\n"
                "aws organizations detach-policy --policy-id <policy-id> "
                "--target-id <ou-or-account-id>"
            ),
            console=(
                "AWS Organizations console, AWS accounts, select the account, Policies tab, "
                "Security Hub policies, review the effective policy and the policies on its "
                "path."
            ),
        ),
        sra_sections=("Security Tooling account", "AWS Security Hub"),
        additional_urls=(
            "https://docs.aws.amazon.com/organizations/latest/APIReference/API_DescribeEffectivePolicy.html",
            "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_security_hub_syntax.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per active organization account.
        """
        checked_value = (
            f"Effective {SECURITYHUB_POLICY_TYPE} enables Security Hub in every scanned Region"
        )
        # Organizations is global; the Region only picks a client endpoint.
        region = self.regions[0]

        accounts_response = self.organization.accounts()
        if "Error" in accounts_response:
            error = accounts_response["Error"]
            yield self.error(
                region="global",
                resource_id=f"organizations:accounts/{self.account_id}",
                checked_value=checked_value,
                actual_value=(
                    f"{error['Operation']} failed: {error['Code']}: {error['Message']}"
                ),
                remediation=self._remediation_for(error),
            )
            return

        active = sorted(
            (
                account
                for account in accounts_response.get("Accounts", [])
                if is_active_account(account) and account.get("Id")
            ),
            key=lambda account: account["Id"],
        )

        for account in active:
            account_id = account["Id"]
            label = f"{account.get('Name', account_id)} ({account_id})"

            response = self.get_effective_policy(
                region, SECURITYHUB_POLICY_TYPE, account_id
            )
            # Inside the per-account loop, so one undetermined account costs one
            # row rather than every account after it.
            if "Error" in response:
                error = response["Error"]
                if self.is_not_configured(error):
                    yield self.failed(
                        region="global",
                        resource_id=account_id,
                        checked_value=checked_value,
                        actual_value=f"No Security Hub policy is in effect for {label}",
                    )
                else:
                    yield self.error(
                        region="global",
                        resource_id=account_id,
                        checked_value=checked_value,
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            content = (response.get("EffectivePolicy") or {}).get("PolicyContent")
            region_lists = self.securityhub_policy_regions(content)
            if region_lists is None:
                yield self.failed(
                    region="global",
                    resource_id=account_id,
                    checked_value=checked_value,
                    actual_value=(
                        f"The effective Security Hub policy for {label} has no "
                        f"securityhub block, so it enables no Region"
                    ),
                )
                continue

            enable, disable = region_lists
            missing = self.regions_not_enabled(enable, disable, list(self.regions))
            if missing:
                yield self.failed(
                    region="global",
                    resource_id=account_id,
                    checked_value=checked_value,
                    actual_value=(
                        f"The effective Security Hub policy for {label} does not enable "
                        f"{', '.join(missing)} (enable_in_regions: "
                        f"[{', '.join(enable) or 'none'}], disable_in_regions: "
                        f"[{', '.join(disable) or 'none'}])"
                    ),
                    remediation=(
                        f"Enable Security Hub in {', '.join(missing)} for account "
                        f"{account_id}: remove the child Security Hub policy that disables "
                        f"them, or attach one that enables them"
                    ),
                )
            else:
                yield self.passed(
                    region="global",
                    resource_id=account_id,
                    checked_value=checked_value,
                    actual_value=(
                        f"The effective Security Hub policy for {label} enables all "
                        f"{len(self.regions)} scanned Regions"
                    ),
                )
