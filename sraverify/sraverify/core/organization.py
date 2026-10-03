"""
The Organizations provider: every read of AWS Organizations data for a scan.

Reached from a check as ``self.organization`` and from the context as
``ctx.organization``. Not a ``SecurityCheck``, not a service base, not a mixin:
it is constructed by ``ScanContext.__init__`` and lives exactly as long as the
scan. Accessors are cached on the context's response cache under the
``organizations`` namespace; a failure is returned unchanged and never cached.

Four decisions are embedded here:

* **It holds the context by weak reference.** ``ctx`` owns the provider, so a
  strong back-reference would make ``ctx -> provider -> ctx`` a cycle, and
  ``del ctx`` in ``run_checks``'s ``finally`` would wait for a cyclic-GC pass
  instead of freeing the context, the provider and every cached boto3 client by
  refcount, immediately.
* **It builds its client wrapper per call, never memoised.** ``AWSClient``
  stores ``ctx`` on the wrapper, so a memoised wrapper would be a second cycle
  (``provider -> wrapper.ctx -> ctx``). ``ctx.get_client`` caches the boto3
  client itself, so the per-call cost is two attribute assignments and one
  locked dict lookup, and constructing a ``ScanContext`` binds no client at all.
* **There is no no-client path.** ``ScanContext.get_client`` always constructs
  -- it reads bundled endpoint data and never touches the network -- and
  ``OrganizationsClient`` binds the result in ``__init__``, so the
  ``no_client_result(service="Organizations", region="global")`` branch that
  ``OrganizationsCheck.get_accounts`` carried on ``main`` was dead code and is not
  reproduced here.
* **No ``active_account_ids()`` helper in Phase 1.** Every consumer keeps its own
  ``is_active_account`` filter, so moving a call site to the provider changes one
  token and nothing else.

One fetch per accessor per key per scan is a guarantee for sequential
execution. The cache is double-checked, not single-flight, so concurrent first
callers may each issue the call; per-key in-flight coordination is a follow-up,
to land before or with concurrent scanning. No lock is added here.
"""
from __future__ import annotations

import weakref
from typing import TYPE_CHECKING, Any, Callable, ClassVar, Mapping

from sraverify.core.aws_errors import (
    ErrorResult,
    NotConfigured,
    NotConfiguredTable,
    is_error,
)
from sraverify.core.logging import logger
from sraverify.core.organizations_client import OrganizationsClient

if TYPE_CHECKING:
    from sraverify.core.scan_context import ScanContext

#: The namespace is the one ``OrganizationsCheck.NAMESPACE`` names; the key is
#: the one ``main``'s ``OrganizationsCheck.get_accounts`` used.
NAMESPACE: str = "organizations"
ACCOUNTS_KEY: str = "all_accounts"


class OrganizationsProvider:
    """Cached, typed access to AWS Organizations for one scan."""

    #: Organizations operations whose codes mean "not configured", consulted by
    #: ``SecurityCheck.is_not_configured`` *after* the check's service table.
    #: The one place an operation in ``OWNED_OPERATIONS`` is classified: no
    #: service table declares one (Property 43), so two checks reading the same
    #: answer from the same operation can no longer classify it differently.
    #: Restricted to ``OWNED_OPERATIONS`` because the table is keyed by
    #: operation name, and ``ListPolicies`` (shared with ``fms``) would be
    #: consulted for every Firewall Manager check too; its entry stays on
    #: ``OrganizationsCheck``.
    #:
    #: Every entry cites the API reference page for that operation. The two new
    #: ones, ``ListDelegatedAdministrators`` and ``ListAccounts``, move FAIL
    #: rows only in an account that is not a member of any organization, which
    #: the test organization cannot produce; they are held by the citation, a
    #: zero-moved live A/B and the per-row ledger in
    #: ``tests/unit/core/test_provider_classification.py`` (Requirement 13.12).
    #: ``AWSOrganizationsNotInUseException`` is deliberately not declared for
    #: ``ListRoots``, ``ListOrganizationalUnitsForParent``,
    #: ``ListAccountsForParent``, ``ListPoliciesForTarget`` or ``DescribePolicy``:
    #: their consumers have no FAIL arm written for "no organization".
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {
        "ListDelegatedAdministrators": {
            "AWSOrganizationsNotInUseException": NotConfigured(evidence=(
                "https://docs.aws.amazon.com/organizations/latest/APIReference/"
                "API_ListDelegatedAdministrators.html -- 'Your account isn't a member of "
                "an organization.' (page fetched 2026-10-02). No organization means no "
                "delegated administrator can be registered for any principal."
            )),
        },
        "ListAccounts": {
            "AWSOrganizationsNotInUseException": NotConfigured(evidence=(
                "https://docs.aws.amazon.com/organizations/latest/APIReference/"
                "API_ListAccounts.html -- 'Your account isn't a member of an "
                "organization.' (page fetched 2026-10-02). No organization means no "
                "accounts to enrol."
            )),
        },
        "DescribeOrganization": {
            "AWSOrganizationsNotInUseException": NotConfigured(evidence=(
                "https://docs.aws.amazon.com/organizations/latest/APIReference/"
                "API_DescribeOrganization.html -- 'Your account isn't a member of an "
                "organization.' (page fetched 2026-10-02). Moved from ConfigCheck and "
                "OrganizationsCheck, which declared the identical pair."
            )),
        },
        "DescribeEffectivePolicy": {
            "EffectivePolicyNotFoundException": NotConfigured(evidence=(
                "https://docs.aws.amazon.com/organizations/latest/APIReference/"
                "API_DescribeEffectivePolicy.html -- no policy of the type is in effect "
                "for the target. Observed 2026-09-16 for every active account (the "
                "aws_call_failed record quoted in OrganizationsCheck's former entry). "
                "Moved from OrganizationsCheck and SecurityHubCheck."
            )),
        },
    }

    #: Operations this provider issues whose names no other service's client issues.
    #: ``ListPolicies`` is excluded because ``fms:ListPolicies`` shares the name.
    #: The provider table may declare only these (Property 43), and the AST guard's
    #: boto3-spelling set is these in snake_case (Property 41).
    OWNED_OPERATIONS: ClassVar[frozenset[str]] = frozenset({
        "ListAccounts", "DescribeOrganization", "ListDelegatedAdministrators",
        "ListRoots", "ListOrganizationalUnitsForParent", "ListPoliciesForTarget",
        "DescribePolicy", "DescribeEffectivePolicy", "ListAccountsForParent",
    })

    def __init__(self, ctx: ScanContext) -> None:
        """Hold ``ctx`` weakly. Issues no AWS call and binds no boto3 client.

        Args:
            ctx: The ScanContext that owns this provider.
        """
        # Weak, not strong: ctx owns this object, and a strong back-reference
        # would make ctx -> provider -> ctx a cycle that only the cyclic
        # collector frees. run_checks relies on refcount-immediate release.
        self._ctx_ref: weakref.ReferenceType[ScanContext] = weakref.ref(ctx)

    @property
    def _ctx(self) -> ScanContext:
        """The owning context.

        Raises:
            RuntimeError: If the context has already been released.
        """
        ctx = self._ctx_ref()
        if ctx is None:
            # Unreachable while the provider is reached through ctx.organization:
            # the caller holds ctx, so the referent cannot have been collected.
            raise RuntimeError("OrganizationsProvider outlived its ScanContext")
        return ctx

    def accounts(self) -> Mapping[str, Any]:
        """Every account in the organization, cached once per scan.

        Takes no Region: the answer is organization-wide.

        "One sweep per scan" holds for sequential execution, which is how
        ``run_checks`` runs today. The cache is not single-flight: two
        concurrent first callers can each miss and each paginate. Per-key
        in-flight coordination belongs with concurrent scanning (Phase 2).

        Returns:
            ``{"Accounts": [...]}`` with every page merged, or the error result
            unchanged. A failure is never cached, so the next caller re-issues.
        """
        ctx = self._ctx
        if ctx._has(NAMESPACE, ACCOUNTS_KEY):
            logger.debug("Organizations: Using cached organization accounts")
            return ctx._get(NAMESPACE, ACCOUNTS_KEY)

        logger.debug("Organizations: Fetching organization accounts")
        # A wrapper per call, never memoised: memoising it would store
        # wrapper.ctx -> ctx on the provider, which is the cycle the weakref
        # above exists to avoid.
        response = OrganizationsClient(ctx).list_accounts()
        if is_error(response):
            return response  # never cached; the next caller re-issues

        ctx._set(NAMESPACE, ACCOUNTS_KEY, response)
        logger.debug(
            f"Organizations: Cached {len(response.get('Accounts', []))} "
            f"organization accounts"
        )
        return response

    def _cached(
        self, key: str, fetch: Callable[[OrganizationsClient], Mapping[str, Any]]
    ) -> Mapping[str, Any]:
        """The one miss path every accessor but ``accounts()`` shares.

        Args:
            key: The cache key in the ``organizations`` namespace.
            fetch: Issues the call on a fresh client wrapper.

        Returns:
            The cached or fetched success dict, or the error result unchanged.
            A failure is never cached, so the next caller re-issues.
        """
        ctx = self._ctx
        if ctx._has(NAMESPACE, key):
            logger.debug(f"Organizations: Using cached {key}")
            return ctx._get(NAMESPACE, key)
        logger.debug(f"Organizations: Fetching {key}")
        # A wrapper per miss, never memoised (see the module docstring).
        response = fetch(OrganizationsClient(ctx))
        if is_error(response):
            return response  # never cached; the next caller re-issues
        ctx._set(NAMESPACE, key, response)
        logger.debug(f"Organizations: Cached {key}")
        return response

    def describe(self) -> Mapping[str, Any]:
        """The organization, cached once per scan.

        Returns:
            The ``DescribeOrganization`` response, or the error result.
        """
        return self._cached(
            "organization", lambda client: client.describe_organization()
        )

    def management_account_id(self) -> str | ErrorResult:
        """The management account's ID, read from ``describe()``.

        Returns:
            The account ID string, or ``describe()``'s error result unchanged.
        """
        response = self.describe()
        if is_error(response):
            return response
        return response["Organization"]["MasterAccountId"]

    def delegated_administrators(self, service_principal: str) -> Mapping[str, Any]:
        """The delegated administrators for one service principal, cached per principal.

        Args:
            service_principal: e.g. ``"securityhub.amazonaws.com"``.

        Returns:
            ``{"DelegatedAdministrators": [...]}`` with every page merged, or the
            error result.
        """
        return self._cached(
            f"delegated_admins:{service_principal}",
            lambda client: client.list_delegated_administrators(service_principal),
        )

    def roots(self) -> Mapping[str, Any]:
        """The organization roots.

        Returns:
            ``{"Roots": [...]}``, or the error result.
        """
        return self._cached("roots", lambda client: client.list_roots())

    def ous_for_parent(self, parent_id: str) -> Mapping[str, Any]:
        """The organizational units directly under a root or OU.

        Args:
            parent_id: Root or OU ID.

        Returns:
            ``{"OrganizationalUnits": [...]}``, or the error result.
        """
        return self._cached(
            f"ous:{parent_id}",
            lambda client: client.list_organizational_units_for_parent(parent_id),
        )

    def policies(self, policy_type: str) -> Mapping[str, Any]:
        """The organization policies of one type.

        Args:
            policy_type: e.g. ``"SERVICE_CONTROL_POLICY"``.

        Returns:
            ``{"Policies": [...]}``, or the error result.
        """
        return self._cached(
            f"policies:{policy_type}",
            lambda client: client.list_policies(policy_type),
        )

    def policies_for_target(self, target_id: str, policy_type: str) -> Mapping[str, Any]:
        """The policies of one type attached directly to a root, OU or account.

        Args:
            target_id: Root, OU or account ID.
            policy_type: e.g. ``"SECURITYHUB_POLICY"``.

        Returns:
            ``{"Policies": [...]}``, or the error result.
        """
        return self._cached(
            f"policies_for_target:{target_id}:{policy_type}",
            lambda client: client.list_policies_for_target(target_id, policy_type),
        )

    def describe_policy(self, policy_id: str) -> Mapping[str, Any]:
        """One policy with its stored content.

        Args:
            policy_id: Policy ID.

        Returns:
            The ``DescribePolicy`` response, or the error result.
        """
        return self._cached(
            f"policy:{policy_id}",
            lambda client: client.describe_policy(policy_id),
        )

    def effective_policy(self, policy_type: str, target_id: str) -> Mapping[str, Any]:
        """The effective management policy of one type for an account.

        Args:
            policy_type: A management policy type, e.g. ``"BEDROCK_POLICY"``.
            target_id: An account ID. A root or OU answers
                ``InvalidInputException``.

        Returns:
            The ``DescribeEffectivePolicy`` response, or the error result.
        """
        return self._cached(
            f"effective_policy:{policy_type}:{target_id}",
            lambda client: client.describe_effective_policy(policy_type, target_id),
        )

    def accounts_for_parent(self, parent_id: str) -> Mapping[str, Any]:
        """The accounts directly under a root or OU.

        Args:
            parent_id: Root or OU ID.

        Returns:
            ``{"Accounts": [...]}``, or the error result.
        """
        return self._cached(
            f"accounts:{parent_id}",
            lambda client: client.list_accounts_for_parent(parent_id),
        )
