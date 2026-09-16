"""
Security Incident Response client.

Every method returns a dict: the boto3 response on success, or the error result
built by ``AWSClient.aws_error``. Each method catches exactly ``AWS_EXCEPTIONS``
and hands the exception over; anything else raised is a programming defect and
propagates to the orchestrator's guard.

Six methods across three boto3 services -- ``security-ir`` for the membership
APIs, ``organizations`` for the delegated-administrator and account lookups, and
``iam`` for the triage service linked role. All three clients are acquired in
``__init__``.

A membership lives in a single home Region, and ``ListMemberships`` answers with an
empty ``items`` list in every other Region rather than an error. The base class
sweeps Regions on that basis, which is why an unreachable endpoint has to arrive
as an error result rather than as a raised exception: the sweep cannot tell "not
this Region" from "could not ask" unless the failure is a value.
"""
from typing import Any, List, Mapping

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.logging import logger
from sraverify.core.scan_context import ScanContext


class SecurityIncidentResponseClient(AWSClient):
    """Client for interacting with AWS Security Incident Response."""

    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize the Security Incident Response client wrapper for a region.

        Args:
            region: AWS region name
            ctx: Per-scan ``ScanContext`` providing the cached, bounded boto3
                clients used by this wrapper
        """
        super().__init__(region, ctx)
        self.org_client = ctx.get_client('organizations', region=region)
        self.sir_client = ctx.get_client('security-ir', region=region)
        self.iam_client = ctx.get_client('iam', region=region)

    def list_delegated_administrators(
        self, service_principal: str = "security-ir.amazonaws.com"
    ) -> Mapping[str, Any]:
        """
        List delegated administrators for the Security Incident Response principal.

        Returns:
            The ``ListDelegatedAdministrators`` response on success, i.e.
            ``{"DelegatedAdministrators": [...]}``, or the error result.
        """
        try:
            return self.org_client.list_delegated_administrators(
                ServicePrincipal=service_principal
            )
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_memberships(self) -> Mapping[str, Any]:
        """
        List Security Incident Response memberships in this Region.

        A membership lives in a single home Region chosen at onboarding, and this
        call returns an empty ``items`` list -- not an error -- in every other
        Region. The base class sweeps Regions on that basis, which is why an
        unreachable endpoint here has to arrive as an error result rather than as a
        raised exception: the sweep cannot tell "not this Region" from "could not
        ask" unless the failure is a value.

        Returns:
            The ``ListMemberships`` response on success, i.e. ``{"items": [...]}``,
            or the error result.
        """
        try:
            return self.sir_client.list_memberships()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_membership(self, membership_id: str) -> Mapping[str, Any]:
        """
        Get Security Incident Response membership details.

        Returns:
            The ``GetMembership`` response on success, or the error result.
        """
        try:
            return self.sir_client.get_membership(membershipId=membership_id)
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def batch_get_member_account_details(
        self, membership_id: str, account_ids: List[str]
    ) -> Mapping[str, Any]:
        """
        Get member account details for multiple accounts.

        Returns:
            The ``BatchGetMemberAccountDetails`` response on success, i.e.
            ``{"items": [...], "errors": [...]}``, or the error result.
        """
        try:
            return self.sir_client.batch_get_member_account_details(
                membershipId=membership_id,
                accountIds=account_ids
            )
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_accounts(self) -> Mapping[str, Any]:
        """
        List all accounts in the organization, following pagination.

        ``organizations:ListAccounts`` returns at most 20 accounts per page.
        Reading only the first page would silently drop the remaining accounts,
        and because SRA-SECURITYINCIDENTRESPONSE-04 asserts that *every* active
        account is covered, a dropped account becomes an all-PASS result rather
        than a visible failure. Matches the paginated approach already used by
        the macie, securityhub and securitylake clients.

        Returns:
            ``{"Accounts": [...]}`` on success, or the error result. The whole
            paginator loop is inside the ``try``: a failure on page three has to
            arrive as an error result rather than as a short list, because a short
            list is indistinguishable from a smaller organization.
        """
        try:
            accounts: List[Mapping[str, Any]] = []
            paginator = self.org_client.get_paginator('list_accounts')
            for page in paginator.paginate():
                accounts.extend(page.get('Accounts', []))
            logger.debug(f"Found {len(accounts)} organization accounts")
            return {"Accounts": accounts}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_role(self, role_name: str) -> Mapping[str, Any]:
        """
        Get IAM role details.

        Returns:
            The ``GetRole`` response on success, i.e. ``{"Role": {...}}``, or the
            error result. ``NoSuchEntity`` from here is declared semantic on the
            base class: the role genuinely does not exist, which is the control
            being absent rather than an inability to look.
        """
        try:
            return self.iam_client.get_role(RoleName=role_name)
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)
