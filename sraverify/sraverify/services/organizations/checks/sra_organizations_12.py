"""
Check if the effective Amazon Bedrock policy names a Guardrail for every account.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.organizations.base import OrganizationsCheck

#: The Organizations policy type that carries Amazon Bedrock Guardrail
#: enforcement.
BEDROCK_POLICY_TYPE = "BEDROCK_POLICY"


class SRA_ORGANIZATIONS_12(OrganizationsCheck):
    """Check if the effective Amazon Bedrock policy names a Guardrail per account."""

    meta = CheckMeta(
        check_id="SRA-ORGANIZATIONS-12",
        title="Effective Amazon Bedrock policy names a Guardrail for every active account",
        description=(
            "This check verifies that the effective Amazon Bedrock policy for every active "
            "account in the organization names at least one Guardrail. The effective policy is "
            "the result of inheritance from the root and OUs plus any policy attached directly "
            "to the account, so this proves enforcement lands where model inference happens "
            "rather than only where a policy was attached. One row is produced per active "
            "account."
        ),
        check_logic=(
            "Call organizations:ListAccounts, keep accounts with Status ACTIVE, then call "
            "organizations:DescribeEffectivePolicy with PolicyType BEDROCK_POLICY per account. "
            "Parse EffectivePolicy.PolicyContent and collect every "
            "bedrock.guardrail_inference.<region>.<config>.identifier. Passes if at least one "
            "identifier is present. Fails on EffectivePolicyNotFoundException or an empty set."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="Organizations",
        resource_type="AWS::Organizations::Account",
        remediation=Remediation(
            text=(
                "Attach an Amazon Bedrock policy that names a versioned Guardrail to the root, "
                "or to an OU or account on this account's path, so the effective policy "
                "resolves to a Guardrail."
            ),
            cli=(
                "aws organizations attach-policy --policy-id <bedrock-policy-id> "
                "--target-id <root-ou-or-account-id>"
            ),
            console=(
                "AWS Organizations console, AWS accounts, select the account, Policies tab, "
                "Amazon Bedrock policies, Attach."
            ),
        ),
        sra_sections=("Management account", "AWS Organizations"),
        additional_urls=(
            "https://docs.aws.amazon.com/organizations/latest/APIReference/API_DescribeEffectivePolicy.html",
            "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_bedrock_best_practices.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per active organization account.
        """
        # Organizations is a global service, use "global" as region
        region = "global"
        checked_value = (
            f"Effective {BEDROCK_POLICY_TYPE} names at least one Guardrail"
        )

        accounts_response = self.get_accounts()

        if "Error" in accounts_response:
            error = accounts_response["Error"]
            if self.is_not_configured(error):
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value=(
                        f"AWS Organizations reports the control absent: "
                        f"{error['Code']}"
                    ),
                    checked_value=checked_value,
                )
            else:
                yield self.error(
                    region=region,
                    resource_id=None,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                    checked_value=checked_value,
                )
            return

        org_accounts = accounts_response.get("Accounts", [])

        if not org_accounts:
            # The caller is always a member of the organization it is asking
            # about, so an empty list is a response no verdict follows from
            # rather than evidence a policy is missing.
            yield self.error(
                region=region,
                resource_id=None,
                actual_value="ListAccounts succeeded but returned no organization accounts",
                remediation=(
                    "Re-run the check from the organization management account and "
                    "confirm the member role may call organizations:ListAccounts"
                ),
                checked_value=checked_value,
            )
            return

        # Organizations retired the account Status field in favour of State but
        # was still returning both as of 2026-09-16, so accept either.
        active_accounts = [
            account for account in org_accounts
            if account.get("State") == "ACTIVE" or account.get("Status") == "ACTIVE"
        ]

        if not active_accounts:
            yield self.error(
                region=region,
                resource_id=None,
                actual_value=(
                    f"ListAccounts returned {len(org_accounts)} account(s) but none "
                    f"is ACTIVE"
                ),
                remediation=(
                    "Re-run the check; if it persists, confirm the organization has "
                    "at least one active account"
                ),
                checked_value=checked_value,
            )
            return

        # One call per account. A root or OU target is rejected, so there is no
        # cheaper shape available; the per-account error branch stays inside the
        # loop so one undetermined account costs one row rather than all of them.
        for account in sorted(active_accounts, key=lambda a: a.get("Id", "")):
            account_id = account.get("Id", "Unknown")
            account_name = account.get("Name", "Unknown")

            policy_response = self.get_effective_policy(
                BEDROCK_POLICY_TYPE, account_id
            )

            if "Error" in policy_response:
                error = policy_response["Error"]
                if self.is_not_configured(error):
                    # EffectivePolicyNotFoundException: AWS answered, and the
                    # answer is that no Bedrock policy reaches this account.
                    yield self.failed(
                        region=region,
                        resource_id=account_id,
                        actual_value=(
                            f"No effective {BEDROCK_POLICY_TYPE} reaches account "
                            f"{account_id} ({account_name})"
                        ),
                        checked_value=checked_value,
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=account_id,
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                        checked_value=checked_value,
                    )
                continue

            identifiers = self.guardrail_identifiers_of(policy_response)

            if identifiers:
                yield self.passed(
                    region=region,
                    resource_id=account_id,
                    actual_value=(
                        f"Effective {BEDROCK_POLICY_TYPE} for account {account_id} "
                        f"names {len(identifiers)} Guardrail(s): "
                        f"{', '.join(identifiers)}"
                    ),
                    checked_value=checked_value,
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=account_id,
                    actual_value=(
                        f"Effective {BEDROCK_POLICY_TYPE} for account {account_id} "
                        f"({account_name}) names no Guardrail"
                    ),
                    checked_value=checked_value,
                )
