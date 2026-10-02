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

One ``ListAccounts`` sweep per scan is a guarantee for sequential execution.
The cache is double-checked, not single-flight, so concurrent first callers may
each run a sweep; per-key in-flight coordination is a Phase 2 item, to land
before concurrent scanning does. No lock is added here.
"""
from __future__ import annotations

import weakref
from typing import TYPE_CHECKING, Any, ClassVar, Mapping

from sraverify.core.aws_errors import NotConfiguredTable, is_error
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
    #: Empty in Phase 1 on purpose: no service declares ``ListAccounts`` today,
    #: so ``AWSOrganizationsNotInUseException`` from it is ERROR on both
    #: reference trees and stays ERROR until Phase 2 produces A/B evidence of
    #: the rows an entry would move.
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {}

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
