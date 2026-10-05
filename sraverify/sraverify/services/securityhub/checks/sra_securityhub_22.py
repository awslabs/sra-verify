"""
SRA-SECURITYHUB-22: Every active account is centrally managed by Security Hub CSPM central configuration.
"""
from collections.abc import Iterable

from sraverify.core.accounts import is_active_account
from sraverify.core.aws_errors import is_error
from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityhub.base import SELF_MANAGED_POLICY_ID, SecurityHubCheck

#: Appended to the management account's no-association and FAILED remediations.
#: An association with the Organizations management account fails unless that
#: account already has Security Hub CSPM enabled (view-policy.html,
#: "Troubleshooting association failure"), so the recommended
#: start-configuration-policy-association would otherwise fail on its own.
MGMT_HINT = (
    " This is the organization management account: enable Security Hub CSPM in it "
    "first so it becomes a member, or the association fails"
)


class SRA_SECURITYHUB_22(SecurityHubCheck):
    """Check if every active account has a SUCCESS central configuration association."""

    meta = CheckMeta(
        check_id="SRA-SECURITYHUB-22",
        title=(
            "Security Hub CSPM central configuration associates every active account with a "
            "configuration policy"
        ),
        description=(
            "This check verifies that every active account in the organization is centrally "
            "managed by the Security Hub CSPM delegated administrator: its configuration policy "
            "association names a configuration policy rather than SELF_MANAGED_SECURITY_HUB, "
            "and the association status is SUCCESS. A self-managed account configures its own "
            "standards and controls, so a policy that passes SRA-SECURITYHUB-13 does not reach "
            "it; a PENDING or FAILED association means the policy's settings are not yet, or "
            "not fully, applied. Associations exist only in the home Region, which is resolved "
            "from the finding aggregator. One row per active account."
        ),
        check_logic=(
            "Resolve the home Region from securityhub:ListFindingAggregators, call "
            "securityhub:ListConfigurationPolicyAssociations there, and list the active "
            "organization accounts. Per account, passes if an ACCOUNT association names a "
            "policy other than SELF_MANAGED_SECURITY_HUB with AssociationStatus SUCCESS. Fails "
            "otherwise: no association, self-managed, or PENDING/FAILED."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.AUDIT,
        service="Security Hub CSPM",
        resource_type="AWS::SecurityHub::PolicyAssociation",
        remediation=Remediation(
            text=(
                "In the delegated administrator account and home Region, associate the "
                "configuration policy with the organization root (or with each OU and "
                "account), and resolve any FAILED association from its status message."
            ),
            cli=(
                "aws securityhub start-configuration-policy-association "
                "--configuration-policy-identifier <policy-arn> --target RootId=<root-id> "
                "--region <home-region>"
            ),
            console=(
                "Security Hub CSPM console in the delegated administrator account and home "
                "Region, Settings, Configuration, Policies, select the policy, Edit targets, "
                "add the root or the account."
            ),
        ),
        sra_sections=("Security Tooling account", "AWS Security Hub CSPM"),
        additional_urls=(
            "https://docs.aws.amazon.com/securityhub/latest/userguide/central-configuration-intro.html",
            "https://docs.aws.amazon.com/securityhub/latest/userguide/view-policy.html",
            "https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_ListConfigurationPolicyAssociations.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per active account, or one scope row when the home Region,
            the associations or the account list cannot be read.
        """
        checked_value = (
            "Every active account has a SUCCESS association with a configuration policy"
        )
        scope_id = f"securityhub:configuration-policy-association/{self.account_id}"

        # 1. The home Region, from the aggregator. First, so that a failure here
        #    resolves the check before the account list is read.
        probe_region = self.regions[0]
        listed = self.get_finding_aggregators(probe_region)
        if "Error" in listed:
            error = listed["Error"]
            if self.is_not_configured(error):
                yield self.failed(
                    region="global",
                    resource_id=scope_id,
                    checked_value=checked_value,
                    actual_value=(
                        f"Security Hub CSPM is not enabled in {probe_region}, so central "
                        f"configuration cannot reach it from {probe_region}"
                    ),
                    remediation=(
                        f"Enable Security Hub CSPM in the delegated administrator account in "
                        f"{probe_region}, then enable central configuration"
                    ),
                )
            else:
                yield self.error(
                    region="global",
                    resource_id=scope_id,
                    checked_value=checked_value,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: {error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
            return

        home_region = self.home_region_of(listed)
        if not home_region:
            # From an account that owns no aggregator (the management account,
            # for instance) the check resolves here and never issues
            # ListConfigurationPolicyAssociations.
            yield self.failed(
                region="global",
                resource_id=scope_id,
                checked_value=checked_value,
                actual_value=(
                    "No Security Hub CSPM finding aggregator exists, so central "
                    "configuration is not in use"
                ),
            )
            return

        if home_region not in self.regions:
            yield self.error(
                region="global",
                resource_id=scope_id,
                checked_value=checked_value,
                actual_value=(
                    f"Central configuration lives in home Region {home_region}, which is "
                    f"not among the scanned Regions ({', '.join(self.regions)})"
                ),
                remediation=(
                    f"Re-run the check with {home_region} included in --regions so the "
                    f"configuration policy associations can be read from the home Region"
                ),
            )
            return

        # 2. The associations, from the home Region.
        associations = self.get_configuration_policy_associations(home_region)
        if "Error" in associations:
            error = associations["Error"]
            if self.is_not_configured(error):
                yield self.failed(
                    region=home_region,
                    resource_id=scope_id,
                    checked_value=checked_value,
                    actual_value=(
                        "Security Hub CSPM central configuration is not enabled for this "
                        "account, so no account is centrally managed"
                    ),
                    remediation=(
                        "Enable central configuration from the delegated administrator "
                        "account, then associate a configuration policy with the root"
                    ),
                )
            else:
                yield self.error(
                    region=home_region,
                    resource_id=scope_id,
                    checked_value=checked_value,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: {error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
            return
        summaries = associations.get("ConfigurationPolicyAssociationSummaries", [])

        # 3. The organization's active accounts.
        accounts = self.organization.accounts()
        if "Error" in accounts:
            error = accounts["Error"]
            if self.is_not_configured(error):
                yield self.failed(
                    region=home_region,
                    resource_id=scope_id,
                    checked_value=checked_value,
                    actual_value=(
                        "No organization exists, so no account can be centrally managed"
                    ),
                )
            else:
                yield self.error(
                    region=home_region,
                    resource_id=scope_id,
                    checked_value=checked_value,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: {error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
            return
        active = sorted(
            account["Id"]
            for account in accounts.get("Accounts", [])
            if is_active_account(account) and account.get("Id")
        )

        # The management account only changes remediation wording; an error
        # result here means "unknown", and the hint is simply omitted.
        management = self.organization.management_account_id()
        management_id = None if is_error(management) else management

        # 4. One row per active account, in ascending account-ID order.
        for account_id in active:
            hint = MGMT_HINT if account_id == management_id else ""
            summary = self.association_of(summaries, account_id)
            if summary is None:
                yield self.failed(
                    region=home_region,
                    resource_id=account_id,
                    checked_value=checked_value,
                    actual_value=(
                        f"Account {account_id} has no configuration policy association"
                    ),
                    remediation=(
                        f"Associate a configuration policy with account {account_id} or "
                        f"with its OU or the root in {home_region}.{hint}"
                    ),
                )
                continue

            policy_id = summary.get("ConfigurationPolicyId") or "unknown"
            status = summary.get("AssociationStatus") or "UNKNOWN"
            kind = summary.get("AssociationType") or "UNKNOWN"

            if policy_id == SELF_MANAGED_POLICY_ID:
                yield self.failed(
                    region=home_region,
                    resource_id=account_id,
                    checked_value=checked_value,
                    actual_value=f"Account {account_id} is self-managed ({kind}, {status})",
                    remediation=(
                        f"Associate a configuration policy with account {account_id}: aws "
                        f"securityhub start-configuration-policy-association "
                        f"--configuration-policy-identifier <policy-arn> "
                        f"--target AccountId={account_id} --region {home_region}"
                    ),
                )
            elif status != "SUCCESS":
                message = summary.get("AssociationStatusMessage")
                detail = f": {message}" if message else ""
                if status == "PENDING":
                    remediation = (
                        f"The association for {account_id} is still propagating; re-run "
                        f"the check later"
                    )
                else:
                    remediation = (
                        f"Resolve the {status} association for {account_id} in "
                        f"{home_region} using its status message, then re-associate the "
                        f"policy.{hint}"
                    )
                yield self.failed(
                    region=home_region,
                    resource_id=account_id,
                    checked_value=checked_value,
                    actual_value=(
                        f"Account {account_id} is associated with configuration policy "
                        f"{policy_id} ({kind}) but the association is {status}{detail}"
                    ),
                    remediation=remediation,
                )
            else:
                yield self.passed(
                    region=home_region,
                    resource_id=account_id,
                    checked_value=checked_value,
                    actual_value=(
                        f"Account {account_id} is centrally managed by configuration "
                        f"policy {policy_id} ({kind}, SUCCESS)"
                    ),
                )
