"""
Check if Security Incident Response is enabled for all organization accounts.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityincidentresponse.base import SecurityIncidentResponseCheck


class SRA_SECURITYINCIDENTRESPONSE_04(SecurityIncidentResponseCheck):
    """Check if Security Incident Response is enabled for all organization accounts."""

    meta = CheckMeta(
        check_id="SRA-SECURITYINCIDENTRESPONSE-04",
        title="Security Incident Response enabled for all organization accounts",
        description=(
            "Verifies that all active organization accounts are covered by Security "
            "Incident Response"
        ),
        check_logic=(
            "Gets all organization accounts and checks if each is associated with "
            "Security Incident Response membership"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.AUDIT,
        service="SecurityIncidentResponse",
        resource_type="AWS::Organizations::DelegatedAdministrator",
        remediation=Remediation(
            text=(
                "Associate every active organization account with the AWS Security "
                "Incident Response membership, either by adding the organizational "
                "units that contain them or by associating the accounts directly."
            ),
            console=(
                "AWS Security Incident Response console, Settings, Membership "
                "coverage, add the organizational units or accounts that are not yet "
                "associated."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per organization account, or one Finding describing why
            coverage could not be determined.
        """
        # Discover the region where Security Incident Response is configured
        region = self.discover_sir_region()

        # Get all organization accounts.
        accounts_response = self.get_organization_accounts()
        if "Error" in accounts_response:
            error = accounts_response["Error"]
            if self.is_not_configured(error):
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value=(
                        "This account is not a member of an AWS Organization, so no "
                        "organization accounts can be covered by Security Incident Response"
                    ),
                )
            else:
                yield self.error(
                    region=region,
                    resource_id=None,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation="Check IAM permissions for Organizations API access"
                )
            return

        org_accounts = accounts_response.get("Accounts", [])
        if not org_accounts:
            # A successful ListAccounts that names no accounts. The calling
            # account is always a member of its own organization, so this is not
            # a reachable configuration -- it is a response the check cannot
            # evaluate, which is an ERROR rather than a FAIL.
            yield self.error(
                region=region,
                resource_id=None,
                actual_value="ListAccounts succeeded but returned no organization accounts",
                remediation="Confirm the scan is running against an account that belongs to an AWS Organization"
            )
            return

        # Get active memberships
        memberships_response = self.list_memberships()
        if "Error" in memberships_response:
            error = memberships_response["Error"]
            if self.is_not_configured(error):
                # Same finding as the no-active-membership branch below.
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value="No Security Incident Response membership exists",
                )
            else:
                yield self.error(
                    region=region,
                    resource_id=None,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation="Check IAM permissions for Security Incident Response API access"
                )
            return

        memberships = memberships_response.get("items", [])
        active_memberships = [m for m in memberships if m.get("membershipStatus") == "Active"]

        if not active_memberships:
            # A missing or inactive membership is a real control gap, not a
            # scan-environment problem, so it is a FAIL. Reporting it as ERROR
            # with "create a membership first" advice sent operators looking for
            # a permissions issue that does not exist.
            yield self.failed(
                region=region,
                resource_id=None,
                actual_value="No active Security Incident Response memberships found",
                remediation="Create and activate a Security Incident Response membership first"
            )
            return

        # Use first active membership
        membership_id = active_memberships[0].get("membershipId")

        # Get active organization accounts
        active_accounts = [acc for acc in org_accounts if acc.get("Status") == "ACTIVE"]
        account_ids = [acc.get("Id") for acc in active_accounts]

        # Process accounts in batches of 100 (API limit)
        batch_size = 100
        for i in range(0, len(account_ids), batch_size):
            batch_account_ids = account_ids[i:i + batch_size]

            response = self.batch_get_member_account_details(membership_id, batch_account_ids)

            if "Error" in response:
                error = response["Error"]
                # One row per account in the batch, deliberately: the batch is an
                # implementation detail of the 100-account API limit, and coverage
                # is asserted per account. Collapsing the batch into one row would
                # drop up to 100 accounts out of the report.
                if self.is_not_configured(error):
                    for account_id in batch_account_ids:
                        yield self.failed(
                            region=region,
                            resource_id=account_id,
                            actual_value=(
                                f"Membership {membership_id} no longer exists, so "
                                f"account {account_id} is not covered"
                            ),
                        )
                    continue

                actual_value = (
                    f"{error['Operation']} failed: {error['Code']}: "
                    f"{error['Message']}"
                )
                for account_id in batch_account_ids:
                    yield self.error(
                        region=region,
                        resource_id=account_id,
                        actual_value=actual_value,
                        remediation="Check IAM permissions for Security Incident Response BatchGetMemberAccountDetails API access or ensure you specified the region where Security Incident Response is enabled with the --regions flag"
                    )
                continue

            # Process results
            items = response.get("items", [])
            errors = response.get("errors", [])

            # Per-account errors carried inside a *successful* batch response.
            # These are not error results -- they have no Code or Operation, only
            # the batch API's own accountId and message.
            for batch_error in errors:
                account_id = batch_error.get("accountId")
                yield self.error(
                    region=region,
                    resource_id=account_id,
                    actual_value=f"BatchGetMemberAccountDetails reported: {batch_error.get('message', 'no message')}",
                    remediation="Check account status and Security Incident Response configuration"
                )

            # Check each account's association status
            for item in items:
                account_id = item.get("accountId")
                relationship_status = item.get("relationshipStatus")

                if relationship_status == "Associated":
                    yield self.passed(
                        region=region,
                        resource_id=account_id,
                        actual_value=f"Account {account_id} is associated with Security Incident Response"
                    )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=account_id,
                        actual_value=f"Account {account_id} relationship status is {relationship_status}",
                        remediation="Associate the account with Security Incident Response membership through organizational units or direct association"
                    )
