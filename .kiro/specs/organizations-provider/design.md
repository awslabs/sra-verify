# Design Document

**Feature:** Organizations provider

**Requirements:** `requirements.md` (this directory)

**Supersedes:** GitLab MR !54, `refactor/shared-org-accounts-accessor` (986bced on main c55893a). Phase 1 of this design is the MR that replaces it.

**Evidence:** `.tmp/review/mr54-strategic-review.md`, `.tmp/review/endpoint_probe.txt`, `.tmp/review/endpoint_probe2.txt`, and the !54 developer's A/B report `sratester/org-accounts-refactor-test-report.md`. File and line references are to the !54 branch unless marked `main`.

**Revision:** 5. Revision 5 (2026-10-02) applies the MR !55 review. The owner decided the partition question: fail fast. The scan Region is the first `--regions` value, else the session's Region, else the scan is refused with `PartitionUndeterminedError` (CLI exit 2, no file, no AWS call); the mechanism is specified in `.tmp/sratester/organizations-provider/failfast-design.md` and summarised in Partition Derivation below. The other merge blockers and follow-ups landed with it: `SecurityHubCheck.get_organization()` and `get_enabled_regions` bind the scan Region, so Phase 1 leaves no `us-east-1` pin on an Organizations binding; Properties 12 and 15 are AST rules over package code, so the suite runs from an installed wheel and prose may name the retired mixin; the IAM generator warns on an unbindable `get_client` / `.client` site anywhere in the package; one sweep per scan is scoped to sequential execution; and Property 13 is catalog-wide. Requirements 2.8, 2.9, 9.8, 10.10 and 13.7 and Properties 32–36 are new; no existing criterion or property was renumbered. Revision 4 (2026-10-01) applied the second-pass review (`.tmp/spec-work/design-review-pass2.md`: 0 HIGH, 2 MEDIUM, 10 NIT, all 19 first-pass fixes confirmed against the tree): the three expected suite failures between tasks 8 and 12 are now named in Migration step 3 and `tasks.md`, Property 12's walk includes `sraverify/README.md`, and the remaining items were line-reference and count corrections. Revision 1 was reviewed (`.tmp/spec-work/design-review.md`: 0 HIGH, 5 MEDIUM, 14 NIT); revision 2 dispositioned every finding in "Responses to the design review" at the end of this document. Revision 3 re-verified revision 2's new file:line claims against the tree and added two items found in that pass: Open Question 12 (Requirement 5.2's by-key clause versus `SecurityHubCheck.get_organization()`) and the direct-call clause in Property 28's test.

## Overview

Six services in this scanner read the organization's account list, eight ask who the delegated administrator is, four describe the organization, and on `main` every one of those reads is a private copy: its own boto3 binding, its own cache slot, its own Region, its own idea of what an error means. MR !54 collapsed the six `ListAccounts` copies into a mixin inherited by six service base classes. The owner declined that shape, because a cross-service accessor inherited by a service base is a second inheritance axis that the property suite enumerates by `vars(base)` and therefore cannot see, and because the mixin pinned every one of those paths to `us-east-1`. This design puts organization data where the repository already keeps per-scan, cross-service state: on the `ScanContext`, reached from a check through a read-only delegating property, `self.organization`, exactly like `self.regions` and `self.audit_accounts`.

Concretely, Phase 1 adds two modules under `core/`. `core/organizations_client.py` is the existing `OrganizationsClient` moved out of `services/organizations/` with one change: its Region is derived from the scan (first `--regions` value, else the session's Region, else `None`) instead of the literal `us-east-1`, so the call reaches the scanned partition's endpoint. `core/organization.py` is `OrganizationsProvider`: one object per scan, constructed by `ScanContext.__init__`, exposing `accounts()` as a cached typed accessor under the `organizations` namespace and owning one `NOT_CONFIGURED_ERRORS` table that `SecurityCheck.is_not_configured` consults after the check's own service table. The fifteen call sites change one token each (`self.get_organization_accounts()` becomes `self.organization.accounts()`), the Security Lake primer stops reading a cache slot by key, the mixin and the hand-maintained `_SHARED_ACCESSORS` list are deleted, and the IAM policy generator learns to see a boto3 call issued from `core/`. Phase 1 is verdict-stable against both `main` and the !54 branch; the two admitted differences are set-ordering cells that already vary and the Inspector first-page effect, which the 13-account test organization cannot exercise.

The design is deliberately smaller than the problem. `ListDelegatedAdministrators` is still issued from eight service clients after Phase 1, `DescribeOrganization` from four paths, and `IAMCheck` still classifies `AWSOrganizationsNotInUseException` differently from seven other services. Those are Phase 2 (Requirement 13), a second MR against the merged Phase 1 that grows the provider's surface, retires every `org_client` binding, and moves verdicts only with A/B evidence per row. Phase 1 lands the seam those changes need: the provider, the two-table discriminator, the one-way import rule, and the generator that can see the result.

## Architecture

The three layers are unchanged. What changes is that per-scan state gains a fourth member beside the session, the Region list and the account lists, and that one `<Service>Client` moves down a tier into `core/` because every service needs it.

```
SecurityCheck            core/check.py                meta, registration, passed/failed/error,
    ↑ extends                                         context delegation: session, regions,
    |                                                 account_*, audit_accounts,
    |                                                 log_archive_accounts, organization
<Service>Check           services/<svc>/base.py       _setup_clients + cached typed accessors
    ↑ extends                                         under NAMESPACE; NOT_CONFIGURED_ERRORS
SRA_<SERVICE>_NN         services/<svc>/checks/...    meta = CheckMeta(...) + execute()
                              ↓ uses
<Service>Client          services/<svc>/client.py     raw boto3, paginators, aws_error


Orthogonal, per scan:

ScanContext              core/scan_context.py         session, regions, account lists,
  │                                                   Client_Config, boto3 client cache,
  │                                                   namespaced response cache, one Lock
  ├── .organization ──► OrganizationsProvider   core/organization.py
  │                       accounts()                  cached under ("organizations",
  │                       NOT_CONFIGURED_ERRORS       "all_accounts"); Phase 2 adds the rest;
  │                           ↓ builds per call       holds ctx by weakref, so no cycle
  │                     OrganizationsClient     core/organizations_client.py
  │                       7 methods, AWSClient,       Region = scan_region(ctx), never a
  │                       byte-identical handler      literal; boto3 client cached by ctx
  └── get_client(service, region)              what every client, and the provider's
                                               client, binds in __init__
```

A check reaches the provider only as `self.organization`, which is `self._require_ctx("organization").organization`. The provider reaches AWS only through `OrganizationsClient`, which reaches boto3 only through `ctx.get_client`. Nothing in the chain is a `SecurityCheck`, nothing is registered, and nothing is inherited by a service base, so `test_accessor_cache_property`'s `vars(base)` enumeration is a complete statement about the bases again and the `_SHARED_ACCESSORS` escape hatch is deleted rather than tested.

### The import graph runs one way

```
sraverify.services.<svc>.{base,client,checks.sra_*}
        │  import
        ▼
sraverify.core.{check, aws_client, aws_errors, scan_context, organization,
                organizations_client, accounts, availability, finding, ...}
        │  import
        ▼
boto3 / botocore / stdlib
```

`core/` imports nothing from `services/`, statically. The one `core → services` edge is `core/discovery.py`'s `importlib.import_module` at run time, and it is unchanged. This is why the mixin could not live in `core/` and the provider can: the mixin needed `services.organizations.client`, and importing any `services` submodule runs `services/__init__.py`, which imports every check, which imports `core.check` (`.tmp/review/q1-cycle.txt`: importing `services.organizations.client` alone registers all 182 checks). Relocating the client under `core/` removes the only reason the account-list code had to sit under `services/`.

Two import edges inside `core/` need care, because `ScanContext` becomes a constructor of the provider and the provider's client inherits `AWSClient`, which today imports `ScanContext` at module level:

```
core/scan_context.py ──► core/organization.py ──► core/organizations_client.py ──► core/aws_client.py
                                                                                        │
                              (annotation only; TYPE_CHECKING)  ◄───────────────────────┘
```

`core/aws_client.py` uses `ScanContext` only in the `__init__` annotation and already has `from __future__ import annotations`; its import moves under `if TYPE_CHECKING:`. `core/organization.py` and `core/organizations_client.py` import `ScanContext` the same way. `core/scan_context.py` then imports `OrganizationsProvider` at module top and constructs it in `__init__`. No function-level import, no lazy import of a `core` module from another `core` module; the layering test in Requirement 4 holds `core` against `services`, and this keeps `core`'s internal graph acyclic at run time as well. `core/check.py` imports `OrganizationsProvider` for its table; `check.py` already imports `scan_context`, and `organization.py` does not import `check.py`, so no cycle.

### Where each former copy goes

| On `main`                                                                                                       | On the !54 branch                                     | After Phase 1                                                                                 |
| --------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `OrganizationsCheck.get_accounts` → `OrganizationsClient.list_accounts`, pinned `us-east-1`                     | `OrganizationAccountsMixin.get_organization_accounts` | `ctx.organization.accounts()` → `core/organizations_client.OrganizationsClient.list_accounts` |
| `InspectorClient.list_organization_accounts` (first page only)                                                  | mixin                                                 | provider                                                                                      |
| `MacieClient.list_accounts` (per Region slot)                                                                   | mixin                                                 | provider                                                                                      |
| `SecurityHubClient.list_accounts` (per Region slot)                                                             | mixin                                                 | provider                                                                                      |
| `SecurityLakeClient.list_accounts` (per Region slot)                                                            | mixin                                                 | provider                                                                                      |
| `SecurityIncidentResponseCheck.get_organization_accounts` (uncached)                                            | mixin                                                 | provider                                                                                      |
| `SecurityLakeCheck._prime_region_log_sources` reads `("securitylake", "organization_accounts:<region>")` by key | reads `("organizations", "all_accounts")` by key      | calls `self.organization.accounts()`; seeds nothing on an error result                        |

Everything else that touches Organizations — eight `org_client` bindings for `ListDelegatedAdministrators`, `SecurityHubCheck.get_organization()`'s raw `DescribeOrganization`, `ScanContext.get_management_account_id`, `OrganizationsCheck`'s six other accessors — is left as it is in Phase 1 and named in Migration and Rollout for Phase 2, with one exception: every such binding that named a Region literal or none now takes the scan Region (`SecurityHubCheck.get_organization()`'s Organizations client, and `ScanContext`'s `sts`, `account`, `organizations` and `ec2` clients; see Partition Derivation).

## Components and Interfaces

The technology stack is locked: Python ≥ 3.11, boto3/botocore (≥ 1.43.96 as pinned), the existing `ScanContext` primitives, `pytest` + `hypothesis` for the suite, and `ast` + `pyyaml` + `botocore`'s bundled service list for the IAM generator. No new dependency. No new lock. No new top-level package.

### Module layout decision: two flat modules under `core/`

The relocated client goes in `core/organizations_client.py` and the provider in `core/organization.py`. A `core/organizations/` subpackage was rejected because `core/` is flat today, the client-contract harness and the IAM generator both enumerate by module path, and the first subpackage under `core/` would read as a service package to anyone who skims the tree. A `providers/` sibling top-level package was rejected because it would be a third top-level package whose import direction needs its own rule, where `core/` already has one (Requirement 4). The provider module is named for the attribute it backs (`ctx.organization`), the way `core/accounts.py` is named for the thing `is_active_account` judges, and so that `sraverify.core.organization` and `sraverify.services.organizations` are not two paths that differ by one letter. The client keeps its class name, `OrganizationsClient`, because the adapter table, the IAM generator's attribution and the docstrings all name it.

`services/organizations/client.py` is **deleted**, not kept as a re-export. A re-export would leave a `client.py` under `services/organizations/` for the harness's path enumeration and the AST rules to scan, and would be a second import path for one class. `services/organizations/base.py` imports from `sraverify.core.organizations_client`. `services/organizations/accounts.py` is deleted with the mixin (Requirement 4.4).

### `core/organizations_client.py`

```python
"""
The Organizations client, and the Region it is built for.

Organizations is partition-global: one endpoint per partition, reached from any
Region in that partition. The client therefore derives its Region from the scan
(``scan_region``) rather than pinning ``us-east-1``, which is correct only in the
``aws`` partition. Every method returns the boto3 response on success or the
error result built by ``AWSClient.aws_error``; each catches exactly
``AWS_EXCEPTIONS``.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Mapping

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.regions import resolve_scan_region

if TYPE_CHECKING:
    from sraverify.core.scan_context import ScanContext


def scan_region(ctx: ScanContext) -> str:
    """Return the scan Region: the first ``--regions`` value, else the session's.

    Never ``None``. Applies ``resolve_scan_region`` to ``ctx.regions`` and
    ``ctx.session`` -- the inputs ``ctx.scan_region`` was computed from -- and
    raises ``PartitionUndeterminedError`` (raised, not asserted, so ``python -O``
    cannot restore the aws-global fallback) on a hand-built context with neither.
    Never calls ``ctx.get_enabled_regions()``, so it issues no AWS call.
    """
    return resolve_scan_region(ctx.regions, ctx.session)


class OrganizationsClient(AWSClient):
    """Client for AWS Organizations, built for the scan's partition."""

    def __init__(self, ctx: ScanContext) -> None:
        region = scan_region(ctx)
        super().__init__(region, ctx)
        self.client = ctx.get_client("organizations", region=region)

    # The seven methods below are byte-identical to services/organizations/client.py
    # on the !54 branch: describe_organization, list_roots,
    # list_organizational_units_for_parent, list_policies, list_accounts,
    # describe_effective_policy, list_accounts_for_parent. Each paginator loop sits
    # wholly inside its try; each handler is `except AWS_EXCEPTIONS as e: return
    # self.aws_error(e)`.
```

`scan_region` is a module-level function rather than a method so `services/iam/client.py` can apply the same rule to its `org_client` binding in Phase 1 (Requirement 2.5): `self.org_client = ctx.get_client('organizations', region=scan_region(ctx))`. The first positional argument stays the string literal `'organizations'`, which is what the IAM generator attributes on. Because both constructors derive the Region identically, both resolve to the same `(service, region)` key in `ScanContext.get_client` and share one boto3 instance, which is the property the `us-east-1` pin was originally bought for.

### `core/organization.py`

```python
"""
The Organizations provider: every read of AWS Organizations data for a scan.

Reached from a check as ``self.organization`` and from the context as
``ctx.organization``. Not a ``SecurityCheck``, not a service base, not a mixin:
it is constructed by ``ScanContext.__init__`` and lives exactly as long as the
scan. It holds the context by *weak* reference, so ``ctx`` owning the provider
creates no cycle and ``del ctx`` in ``run_checks``'s ``finally`` still frees the
context, the provider and every cached boto3 client by refcount, immediately,
as it does today. Accessors are cached on the context's response cache under the
``organizations`` namespace; a failure is returned unchanged and never cached.

There is no no-client path, by design. ``ScanContext.get_client`` always
constructs -- it reads bundled endpoint data and never touches the network -- and
``OrganizationsClient`` binds the result in ``__init__``, so the
``no_client_result(service="Organizations", region="global")`` branch that
``OrganizationsCheck.get_accounts`` carried on ``main`` was dead code and is not
reproduced here.
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
#: the one !54 and ``main``'s ``OrganizationsCheck.get_accounts`` both used.
NAMESPACE: str = "organizations"
ACCOUNTS_KEY: str = "all_accounts"


class OrganizationsProvider:
    """Cached, typed access to AWS Organizations for one scan."""

    #: Organizations operations whose codes mean "not configured", consulted by
    #: ``SecurityCheck.is_not_configured`` *after* the check's service table.
    #: Empty in Phase 1 on purpose: no service declares ``ListAccounts`` today,
    #: so ``AWSOrganizationsNotInUseException`` from it is ERROR on both
    #: reference trees and stays ERROR until Phase 2 produces A/B evidence of
    #: the rows an entry would move (Requirement 3.3).
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {}

    def __init__(self, ctx: ScanContext) -> None:
        # Weak, not strong: ctx owns this object, and a strong back-reference
        # would make ctx -> provider -> ctx a cycle that only the cyclic
        # collector frees. run_checks relies on refcount-immediate release.
        self._ctx_ref: weakref.ReferenceType[ScanContext] = weakref.ref(ctx)

    @property
    def _ctx(self) -> ScanContext:
        ctx = self._ctx_ref()
        if ctx is None:
            # Unreachable while the provider is reached through ctx.organization:
            # the caller holds ctx, so the referent cannot have been collected.
            raise RuntimeError("OrganizationsProvider outlived its ScanContext")
        return ctx

    def accounts(self) -> Mapping[str, Any]:
        """Every account in the organization, cached once per scan.

        Returns ``{"Accounts": [...]}`` with every page merged, or the error
        result unchanged. Takes no Region: the answer is organization-wide.
        """
        ctx = self._ctx
        if ctx._has(NAMESPACE, ACCOUNTS_KEY):
            logger.debug("Organizations: Using cached organization accounts")
            return ctx._get(NAMESPACE, ACCOUNTS_KEY)

        logger.debug("Organizations: Fetching organization accounts")
        # A wrapper per call, never memoised: it is two attribute assignments
        # and a locked dict lookup (ctx.get_client caches the boto3 client), and
        # memoising it would store wrapper.ctx -> ctx on the provider, which is
        # the cycle the weakref above exists to avoid. !54's mixin did the same.
        response = OrganizationsClient(ctx).list_accounts()
        if is_error(response):
            return response  # never cached; the next caller re-issues

        ctx._set(NAMESPACE, ACCOUNTS_KEY, response)
        logger.debug(
            f"Organizations: Cached {len(response.get('Accounts', []))} "
            f"organization accounts"
        )
        return response

    # Phase 2 accessors, named here so the seam is visible and NOT present in
    # Phase 1 code (Requirement 1.2 fixes Phase 1 at exactly one data accessor):
    #   describe()                                   -> DescribeOrganization
    #   management_account_id()                      -> derived from describe()
    #   delegated_administrators(service_principal)  -> ListDelegatedAdministrators
    #   roots()                                      -> ListRoots
    #   ous_for_parent(parent_id)                    -> ListOrganizationalUnitsForParent
    #   policies(policy_type)                        -> ListPolicies
    #   policies_for_target(target_id, policy_type)  -> ListPoliciesForTarget
    #   describe_policy(policy_id)                   -> DescribePolicy
    #   effective_policy(policy_type, target_id)     -> DescribeEffectivePolicy
    #   accounts_for_parent(parent_id)               -> ListAccountsForParent
```

Four decisions are embedded here. **The provider is constructed eagerly, holds the context weakly, and builds its client per call.** Requirement 1.1 wants the provider built by `ScanContext.__init__` and dropped with `del ctx`; Requirement 1.6 leaves client acquisition to the design. A strong `self._ctx = ctx` would make `ctx → provider → ctx` a cycle, and a memoised wrapper a second one (`provider → wrapper.ctx → ctx`, because `AWSClient.__init__` stores `ctx`), so release of the context and every boto3 client hung off `ctx._clients` would wait for a cyclic-GC pass instead of happening the moment `run_checks`'s `finally` drops `ctx`. `scanner.py`'s comments and `structure.md`'s "`del`'d in a `finally` block so its boto3 clients become collectible" sentence both describe refcount-immediate release, and the weakref keeps them true without amendment. Building the wrapper inside `accounts()` means `ScanContext(...)` does not call `session.client(...)` at all, so the hundreds of contexts the suite constructs over mock sessions, and any future caller that builds a context and never reads organization data, pay nothing; a cache hit builds no wrapper either, since `_has` is tested first. The per-call cost is two attribute assignments and one locked dict lookup. **No `active_account_ids()` in Phase 1.** Requirement 1.7 allows a pure helper; Requirement 6.1 requires every call site to change one token and nothing else. A helper would invite exactly the call-site rewrite Requirement 6 forbids, and Requirement 1.2 fixes Phase 1 at one accessor. Every consumer keeps its own `is_active_account` loop. If a Phase 2 check wants the convenience, it is a six-line pure function over a success dict, added then. **No second lock.** Cache reads and writes go through `_has`/`_get`/`_set`, which take the context's lock; with no memoised state on the provider there is nothing else to protect. **The provider's public surface is exactly `accounts()`.** Its other members are `NOT_CONFIGURED_ERRORS` (a class attribute, not a callable) and the underscore-prefixed `_ctx_ref` and `_ctx`; Property 4 and Property 26 hold the set.

### `core/scan_context.py` — the `organization` property

```python
from sraverify.core.organization import OrganizationsProvider   # module top

class ScanContext:
    def __init__(self, session, regions=None, ...):
        ...                                   # existing body, unchanged
        self._lock: threading.Lock = threading.Lock()
        # Last, after every attribute it may read exists. Constructing it
        # issues no AWS call and binds no boto3 client (see OrganizationsProvider).
        self._organization: OrganizationsProvider = OrganizationsProvider(self)

    @property
    def organization(self) -> OrganizationsProvider:
        """The Organizations provider for this scan. Read-only; no setter."""
        return self._organization
```

`ctx` holds the provider strongly and the provider holds `ctx` by `weakref.ref`, so the object graph under a `ScanContext` stays acyclic as it is today. When `run_checks`'s `finally` drops `ctx` (and the frame has already dropped the last `check`, which is why `findings = list(check.execute())` exists), the context's refcount reaches zero, it is freed at once, the provider's refcount reaches zero and it is freed at once, and the boto3 clients in `ctx._clients` go with them, with no dependence on the cyclic collector's schedule. `test_context_isolation_property` is unchanged (Requirement 1.9) because a `Finding` still holds no reference to either; a new test holds the deterministic claim directly: a `weakref` to the provider is dead immediately after `del ctx`, **without** calling `gc.collect()` (Property 28). `ScanContext` is already weak-referenceable — the existing isolation test takes a `weakref` to it — and `MagicMock(spec=ScanContext)` is too, though no harness constructs a real provider over a mock context (they stub `ctx.organization` instead; see Testing Strategy).

Revision 5 adds the scan Region. `__init__` copies the explicit Region list (`list(regions)`), then computes `self._scan_region = resolve_scan_region(self._explicit_regions, session)` before the lock, caches and provider exist, so a context with no determinable Region cannot be constructed; `scan_region` is a read-only property. `get_client(service, region=None)` treats `None` as the scan Region, so `get_client(svc)` and `get_client(svc, region=ctx.scan_region)` share one cache key and the `"__global__"` sentinel is gone. The three lazy accessors keep their `raise` semantics in Phase 1 (migrating them is Requirement 13.3), but `get_account_info` binds `sts` and `account`, `get_management_account_id` binds `organizations` (the same key as `OrganizationsClient`, so one boto3 instance), and `get_enabled_regions` binds `ec2`, each with `region=self._scan_region` written explicitly so the AST rule of Property 34 can hold `core/` to it.

### `core/check.py` — `organization`, the shadow rule, and the two-table discriminator

```python
from sraverify.core.organization import OrganizationsProvider

#: Context-delegating properties a class attribute must not shadow. Checked by
#: the same walk as _SHADOWED_META_NAMES, with the same CheckIdentityError.
_SHADOWED_CONTEXT_NAMES: Final = ("organization",)

class SecurityCheck(ABC):
    @property
    def organization(self) -> OrganizationsProvider:
        """The Organizations provider for the current scan, from the context."""
        return self._require_ctx("organization").organization

    def is_not_configured(self, error: Mapping[str, str]) -> bool:
        return _is_not_configured_in(
            (type(self).NOT_CONFIGURED_ERRORS, OrganizationsProvider.NOT_CONFIGURED_ERRORS),
            error,
        )
```

`organization` is the eighth context-delegating property. A read before `initialize(ctx)` raises `RuntimeError` reading `SRA-INSPECTOR-07.organization was read before initialize(ctx); …`, and an assignment raises `AttributeError`, because it is a property with no setter — identical to the other seven (Requirement 5.1).

The shadow rule is enforced in `__init_subclass__` rather than by a catalog-wide test (Requirement 5.3 leaves the choice). Every other shape rule lives there; a class attribute named `organization` on a check or on an intermediate base would shadow the property and silently win at run time, and an import-time `CheckIdentityError` makes `--list-checks` catch it with no credentials, which a test does only when it runs. The walk is the one already written for `_SHADOWED_META_NAMES` — `cls.__mro__` down to but excluding `SecurityCheck` — with a second name tuple and a message that says "context property" rather than "metadata field". The tuple holds `organization` only: widening it to the seven older names is correct but is not asked for and would be a behaviour change on its own.

The discriminator gains precedence, not a second predicate call. `is_not_configured(table, error)` in `core/aws_errors.py` is unchanged for its existing callers and tests; beside it:

```python
def declared_fact(table: NotConfiguredTable, error: Mapping[str, str]) -> NotConfigured | None:
    """The NotConfigured declared for error's (Operation, Code), or None."""
    by_code = table.get(error.get("Operation", ""))
    return by_code.get(error.get("Code", "")) if by_code else None


def is_not_configured_in(
    tables: Sequence[NotConfiguredTable], error: Mapping[str, str]
) -> bool:
    """First table to *declare* the pair decides, needle included.

    A table that declares (Operation, Code) with a message needle that does not
    match has still classified the pair -- as not semantic -- and a later table
    must not overrule it. Anything declared in no table is False.
    """
    for table in tables:
        fact = declared_fact(table, error)
        if fact is not None:
            if fact.message is None:
                return True
            return fact.message.lower() in error.get("Message", "").lower()
    return False
```

`is_not_configured(table, error)` becomes `is_not_configured_in((table,), error)`. The reason precedence is "first table to declare the pair" and not "first table to answer True" is Requirement 3.2's last clause: a service that has classified a pair keeps its classification *and its message needle*. `macie2` declares `AccessDeniedException` with a needle; if the provider table ever declared the same pair without one, an `or` of two booleans would let the provider's unconditional `True` overrule the service's "the needle did not match, this is a real denial". The provider table is reached through the class, `OrganizationsProvider.NOT_CONFIGURED_ERRORS`, for the same reason the service table is read through `type(self)`: classification is a class-level fact, it must not depend on `initialize(ctx)` having run, and an instance attribute must not be able to shadow it. `_SERVICE_ONLY_NAMES` is unchanged: the provider is not a check and a check still may not declare a table (Requirement 3.7).

### `services/organizations/base.py`

```python
from sraverify.core.organizations_client import OrganizationsClient

class OrganizationsCheck(SecurityCheck):            # no mixin
    NAMESPACE = "organizations"
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = { ...unchanged three entries... }

    def _setup_clients(self):
        # Organizations is partition-global: one client, Region derived from the scan.
        self._org_client = OrganizationsClient(ctx=self._ctx)
        self._clients.clear()
    # get_org_client, get_organization, get_roots, get_ous_for_parent,
    # list_policies, get_accounts_for_parent, get_effective_policy,
    # guardrail_identifiers_of: unchanged. get_accounts is not reintroduced.
```

The module and class docstrings stop saying "pinned to `us-east-1`" (Requirement 2.6). `InspectorCheck`, `MacieCheck`, `SecurityHubCheck`, `SecurityIncidentResponseCheck` and `SecurityLakeCheck` each drop `OrganizationAccountsMixin` from their bases and the import that brought it; `InspectorCheck._setup_clients`'s docstring stops saying each wrapper obtains an `organizations` client (Requirement 6.3).

### The fifteen call sites

One token each. In the twelve regional checks (`sra_inspector_07`, `sra_macie_07`, `sra_securityhub_08`, `sra_securitylake_01`, `sra_securitylake_06` through `_13`) the call stays inside the Region loop (Non-Goal 6); in the three global checks (`sra_organizations_12`, `sra_securityhub_17`, `sra_securityincidentresponse_04`) it stays where it is before the `return`. Every `continue`, `return`, `"Error" in` test, `is_not_configured` arm and filter stays:

```python
        for region in self.regions:
            members_response = self.organization.accounts()      # was self.get_organization_accounts()
            if "Error" in members_response:
                error = members_response['Error']
                if self.is_not_configured(error):
                    yield self.failed(...)
                else:
                    yield self.error(..., actual_value=f"{error['Operation']} failed: {error['Code']}: {error['Message']}",
                                     remediation=self._remediation_for(error))
                continue
```

The trailing `# was self.get_organization_accounts()` comment in that snippet is illustrative for this document only and is **not** committed: a committed occurrence of `get_organization_accounts` in any consumer module fails Property 12 and Property 30. The modules: `sra_inspector_07`, `sra_macie_07`, `sra_organizations_12`, `sra_securityhub_08`, `sra_securityhub_17`, `sra_securitylake_01`, `sra_securitylake_06` through `_13`, `sra_securityincidentresponse_04`. No docstring or `check_logic` text changes, so `--list-checks` is `cmp`-identical to `docs/checks.txt` (Requirement 6.6).

### `services/securitylake/base.py` — the primer

```python
    def _prime_region_log_sources(self, region: str) -> None:
        response = self.get_log_sources(region)
        if is_error(response):
            logger.debug(
                f"SecurityLake: could not prime log sources in {region}; seeding "
                f"nothing rather than fabricating [] per account "
                f"({response['Error']['Code']})"
            )
            return

        org_accounts = self.organization.accounts()
        if is_error(org_accounts):
            logger.debug(
                f"SecurityLake: could not list organization accounts to prime "
                f"{region}; seeding nothing ({org_accounts['Error']['Code']})"
            )
            return

        account_ids = [
            a.get("Id")
            for a in org_accounts.get("Accounts", [])
            if isinstance(a, dict) and a.get("Id")
        ]
        if self.account_id and self.account_id not in account_ids:
            account_ids.append(self.account_id)
        # ... per_account bucketing and the per-account _set loop, unchanged ...
```

The `self._ctx._get(ORGANIZATION_ACCOUNTS_NAMESPACE, ORGANIZATION_ACCOUNTS_KEY) or {}` read and the three-line comment above it (`securitylake/base.py:474–476` for the comment and `477–480` for the read) are gone (Requirement 7.1, 7.5). On the guarded path — every one of the eight log-source checks has already called and guarded `accounts()` at the top of its Region loop — the call is a `_has` hit and issues nothing (Requirement 7.3). On the unguarded path, which exists only if a future caller reaches the primer first, an error result seeds nothing: not `[]` per account, and not the scanned account alone, which is what produced the 176-row regression. The `self.account_id` append after a *successful* read is kept because the scanned account can legitimately be absent from the list when the scan runs from the management account's perspective of a partially listed organization, and it is what `main` and !54 both do.

### `services/inspector/base.py` — the batch accessor

```python
#: ``BatchGetAccountStatus`` accepts up to 100 account IDs per request. Batches
#: are smaller than the cap on purpose: 10 is what both reference trees issue,
#: and keeping it holds the Phase 1 call count -- and the per-scan
#: ``aws_call_failed`` count the acceptance gate compares -- unchanged.
BATCH_GET_ACCOUNT_STATUS_CAP: Final = 100
BATCH_GET_ACCOUNT_STATUS_BATCH: Final = 10

    def batch_get_account_status(self, region: str, account_ids: List[str]) -> Mapping[str, Any]:
        ...
        for start in range(0, len(account_ids), BATCH_GET_ACCOUNT_STATUS_BATCH):
            batch = account_ids[start:start + BATCH_GET_ACCOUNT_STATUS_BATCH]
            ...
        if len(responses) == 1:
            result = responses[0]                      # cached by identity, as today
        else:
            result = {"accounts": [a for r in responses for a in r.get("accounts", [])]}   # unchanged merge
```

The batch size stays at 10 (Requirement 8.3). Raising it to 100 would be correct and would issue fewer calls for organizations above 10 accounts, but the Phase 1 gate compares per-scan `aws_call_failed` counts and debug logs across three trees, and a change in how many `BatchGetAccountStatus` requests a scan issues is one more difference to explain in a gate whose value is that there is nothing to explain. The docstring's "accepts at most 10 accounts" becomes the comment above (Requirement 8.1). The multi-batch merge is **not** otherwise touched: it carries `accounts` only, as on both reference trees. Revision 1 of this design extended it to carry `failedAccounts` too; that is dropped, because Requirement 8 asks for the cap invariant, the docstring correction and the batch-size decision and nothing else, nothing in the package reads `failedAccounts` (`grep failedAccounts services/` finds no reader), and the smallest Inspector diff is the one the A/B can attribute. It is recorded as a candidate follow-up in Open Questions. A failing batch still fails the whole call, uncached (Requirement 8.4).

### `util/generate_iam_policy.py` — the walk

The generator stops keying on the file name `client.py` and walks every module under the package. Discovery stays AST-based and offline; the alternative — import the package and walk `AWSClient.__subclasses__()` — was rejected because it misses the calls the requirement is about (`ScanContext` is not an `AWSClient`; `SecurityHubCheck.get_organization()`'s raw call is on a check base), because importing `sraverify.services` registers 182 checks as a side effect, and because the generator must run from a checkout with no scan environment.

```python
#: Directories pruned from the walk, by name, at any depth. tests/ so a mock
#: session in a fixture cannot become a policy statement; the rest are build and
#: tool output. Any directory whose name starts with "." is pruned as well
#: (.venv, .pytest_cache, .hypothesis), and so is any *.egg-info.
PRUNED_DIRS: frozenset[str] = frozenset({"tests", "__pycache__", "build", "dist"})
#: Modules excluded by name, each with its reason. Keys are POSIX paths relative
#: to the *package* directory -- the one holding sraverify/__init__.py -- so the
#: key for sraverify/sraverify/core/session.py is "core/session.py", whatever
#: base_dir the walk started from.
EXCLUDED_MODULES: Dict[str, str] = {
    "core/session.py": (
        "builds the scan session; its one call, sts:AssumeRole, is issued by the "
        "operator's principal to *become* the member role, so it is granted by the "
        "role's trust policy and the operator's policy, never by the member role"
    ),
}

def find_python_modules(base_dir: str = "./sraverify") -> List[str]:
    """Every .py under base_dir, minus PRUNED_DIRS, dot-prefixed dirs, *.egg-info
    and EXCLUDED_MODULES, sorted.

    base_dir is the project root (the directory holding pyproject.toml, .venv and
    the package directory), exactly what find_client_files walked; the package
    directory is located as the child named "sraverify" that holds __init__.py.
    Unlike find_client_files, dot-prefixed directories are pruned, so .venv is
    never read -- which is where !54's three "unknown" warnings came from.
    """

@functools.lru_cache(maxsize=1)
def known_service_ids() -> frozenset[str]:
    """botocore's bundled service ids. Offline; no credentials."""
    return frozenset(botocore.session.get_session().get_available_services())

def bind_clients(tree: ast.Module) -> Dict[str, str]:
    """As today, plus: the literal first argument must be in known_service_ids()."""
```

The service-id check is what makes the whole-package walk safe. `bind_clients` recognises `<receiver>.get_client('<literal>', ...)` and `<receiver>.client('<literal>', ...)`, and `get_client` is overloaded in this package: on `ScanContext` its first argument is a boto3 service id, on `SecurityCheck` it is a Region. `services/firewallmanager/base.py:105` and `services/waf/base.py:115` both write `client = self.get_client('us-east-1')`; under the old walk those modules were never read, and under the new one they would bind `client → "us-east-1"` and emit a `Us-east-1Permissions` statement. Requiring the literal to be a known service id rejects both, and anything like them, without a per-module special case. Local-variable bindings are kept (Requirement 9.2); `ScanContext`'s `sts_client`, `account_client`, `org_client` and `ec2_client` are all locals.

The per-module warning narrows. Walking the whole package, "a module that binds nothing" describes almost every module, so a warning per such module is noise. The warning fires for a module that declares a class whose base list names `AWSClient` and binds nothing — the exact failure the warning exists for, a client whose acquisition form the generator no longer recognises. `extract_service_name` is replaced by the module path relative to the package directory in warning text, the same `core/session.py`-style path `EXCLUDED_MODULES` is keyed by.

The output format is unchanged: one statement per service, Sid `f"{service.capitalize()}Permissions"`, actions sorted. The complete action diff against the committed artefacts is in Data Models.

## Data Models

No new persistent model. Four existing shapes are reused and one table is declared.

### The cache slot

| Namespace       | Key            | Value                                                     | Written by                              | Read by                                                       |
| --------------- | -------------- | --------------------------------------------------------- | --------------------------------------- | ------------------------------------------------------------- |
| `organizations` | `all_accounts` | the success dict `{"Accounts": [...]}`, every page merged | `OrganizationsProvider.accounts()` only | `OrganizationsProvider.accounts()` only; no base class by key |

The namespace is fixed by Requirement 1.3: it is the string `OrganizationsCheck.NAMESPACE` already names and the one the primer's foreign read has to disappear from. The key is the one both `main`'s `OrganizationsCheck.get_accounts` and !54's mixin used, kept so a `--debug` log from any of the three trees reads the same. The rest of the `organizations` namespace — `organization`, `roots`, `ous:<parent>`, `policies:<type>`, `accounts:<parent>`, `effective_policy:<type>:<target>` — is still written by `OrganizationsCheck`'s six accessors in Phase 1 and becomes the provider's in Phase 2. One foreign by-key read of that namespace also survives Phase 1: `SecurityHubCheck.get_organization()` reads and writes the `organization` key through its own `_ORGANIZATIONS_NAMESPACE = "organizations"` / `_ORGANIZATION_CACHE_KEY = "organization"` constants (`securityhub/base.py:211–212`, `934–973`), so that a Security Hub check and an Organizations check share one `DescribeOrganization` answer. Requirement 6.5 and Non-Goal 8 leave that method exactly as it is until Phase 2, so Phase 1 removes the primer's foreign read of `all_accounts` and no other; Open Question 12 records the tension with Requirement 5.2's wording. The steering sentence Requirement 11.1 asks for is therefore scoped to the slot: *the `all_accounts` slot is written by the provider and read by no base class by key.*

The value is the client's response dict, by identity. The provider does not copy, filter, sort or reshape it, so a check receives the same object every caller receives and the `is_active_account` filter runs where it always has.

### The error result

Unchanged, from `core/aws_errors.py`: `{"Error": {"Code": str, "Message": str, "Operation": str}}`, every field non-blank. A failed sweep arrives in a check as

```python
{"Error": {"Code": "AccessDeniedException",
           "Message": "You don't have permissions to access this resource.",
           "Operation": "ListAccounts"}}
```

and the check renders it as `ListAccounts failed: AccessDeniedException: You don't have permissions to access this resource.` (Requirement 3.6). `Operation` is read from `ClientError.operation_name` by `AWSClient.aws_error`; nothing in the provider path types an operation literal.

### The provider table

```python
NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {}
```

Type `NotConfiguredTable = Mapping[str, Mapping[str, NotConfigured]]`, operation → code → `NotConfigured(evidence, message=None)`, the same type and the same evidence rule as every service table (Requirement 3.1). Empty in Phase 1 (Requirement 3.3, 3.4). The shape a Phase 2 entry takes, for the record and for `test_discriminator_property.py`'s enumeration, which gains the provider table alongside the eighteen service tables:

```python
NOT_CONFIGURED_ERRORS = {
    "ListDelegatedAdministrators": {
        "AWSOrganizationsNotInUseException": NotConfigured(
            evidence="https://docs.aws.amazon.com/organizations/latest/APIReference/"
                     "API_ListDelegatedAdministrators.html -- ... ; A/B rows moved: <list>",
        ),
    },
}
```

### Classification inputs

`is_not_configured_in` takes a `Sequence[NotConfiguredTable]`; `SecurityCheck.is_not_configured` passes exactly `(type(self).NOT_CONFIGURED_ERRORS, OrganizationsProvider.NOT_CONFIGURED_ERRORS)`. Two tables, in that order, always; a check cannot vary the sequence.

### The generator's output

Unchanged in shape: `{"Version": "2012-10-17", "Statement": [{"Sid", "Effect", "Action", "Resource"}, ...]}`, one statement per boto3 service id, sorted; and the CloudFormation `SRAVerifyLeastPrivilege` wrapper around it. The complete action diff Phase 1 produces against the committed `generated_sraverify_iam_policy.json` (Requirement 9.3):

| Change    | Action                               | Statement                  | Source module                                                                                           |
| --------- | ------------------------------------ | -------------------------- | ------------------------------------------------------------------------------------------------------- |
| added     | `account:GetAccountInformation`      | `AccountPermissions`       | `core/scan_context.py` (`get_account_info`)                                                             |
| added     | `ec2:DescribeRegions`                | `Ec2Permissions`           | `core/scan_context.py` (`get_enabled_regions`)                                                          |
| unchanged | `organizations:ListAccounts`         | `OrganizationsPermissions` | now attributed from `core/organizations_client.py` instead of `services/organizations/client.py`        |
| unchanged | `organizations:DescribeOrganization` | `OrganizationsPermissions` | additionally attributed from `core/scan_context.py` and `services/securityhub/base.py`; already present |
| unchanged | `sts:GetCallerIdentity`              | `StsPermissions`           | additionally attributed from `core/scan_context.py` and `utils/banner.py`; already present              |
| excluded  | `sts:AssumeRole`                     | —                          | `core/session.py`, excluded by `EXCLUDED_MODULES` with its reason                                       |

Nothing is removed. `AccountPermissions` already exists in the generated statement for `account:GetAlternateContact`, so `GetAccountInformation` joins it rather than creating a statement. The template carries two `AccountPermissions` statements and both are touched by exactly one decision: the hand-written `SRAVerifyCheckPermissions` policy (line 51–54) already grants `account:GetAccountInformation` and is left as it is, because it predates the generator and removing it is a change to a deployed policy outside this feature; the `SRAVerifyLeastPrivilege` policy's `AccountPermissions` statement (line 79–82, today `account:GetAlternateContact` only) is the hand-maintained mirror of `generated_sraverify_cf_policy.yaml` and **gains `account:GetAccountInformation`**, so the generated artefact and the template statement that mirrors it agree (Requirement 9.4's "updated to match"). The action therefore appears twice in the template after Phase 1, once per policy; Open Question 6 records that. `ec2:DescribeRegions` is added to the same policy's `Ec2Permissions` statement (line 145–150), where it is absent today and has been masked by the buildspec always passing `--regions`. Those two statement edits are the whole template diff.

## Partition Derivation

**Decision (owner, revision 5): fail fast.** The scan Region is the first explicit `--regions` value; else `session.region_name`; else the scan is refused with `PartitionUndeterminedError`. A non-empty `--regions` whose first value is not a usable Region string (a `str`, non-blank, with no leading or trailing whitespace) raises the same error and does not fall through to the session: explicit input wins, and explicit input that is wrong is a usage error. The rule is one pure function, `core/regions.py::resolve_scan_region(regions, session) -> str`, which imports only `core.errors`, issues no AWS call and never calls `get_enabled_regions()`. `session.region_name` already folds in `Session(region_name=…)`, `AWS_DEFAULT_REGION` and the profile's `region =`, so nothing re-reads the environment. boto3 does not read `AWS_REGION` (botocore maps `region` to `AWS_DEFAULT_REGION` only), and the rule deliberately does not consult it either: the guard and the clients built from the same session must never disagree, and reading the environment is an application concern. The live gate found the first fail-fast message advising `AWS_REGION`, a remedy that still exits 2; the message now names `AWS_DEFAULT_REGION` and says boto3 ignores `AWS_REGION`.

Three callers apply that rule to the same inputs. `SRAVerify` calls it first in `run_checks` (and the CLI calls the public `SRAVerify.resolve_scan_region()` ahead of the banner), so an undetermined scan is refused before selection, before a `ScanContext` exists, and before any AWS call. `get_session` calls it before `sts:AssumeRole`, the one AWS call made before a scan exists, and builds both the STS client and the assumed session for that Region; `SRAVerify` passes `region=regions[0]` to it, so the session Region and the scan Region agree by construction. `ScanContext.__init__` calls it to store `ctx.scan_region`, as a backstop for a library caller that builds a context directly. The CLI maps the error to exit 2 with no file, exactly as it maps `UnknownCheckError` and `NoChecksSelectedError`; when both the partition and the filters are bad, the partition error is reported.

The evidence is botocore's bundled endpoint data (1.43.105, `.tmp/review/endpoint_probe.txt` and `endpoint_probe2.txt`). `organizations` is partition-global, not Region-less: `us-east-1` and `eu-west-1` both resolve to `organizations.us-east-1.amazonaws.com`; `us-gov-west-1` and `us-gov-east-1` both resolve to `organizations.us-gov-west-1.amazonaws.com`; `cn-north-1` and `cn-northwest-1` to `organizations.cn-northwest-1.amazonaws.com.cn`; `us-iso-east-1` to the C2S endpoint. So any Region in the scanned partition is a correct choice, and the only wrong choice is a Region in a different partition — which is exactly what the literal `us-east-1` is from a GovCloud session, and what botocore's `aws-global` default is for a Region-less client. Revision 4 let a scan with neither `--regions` nor a session Region reach that default; revision 5 refuses it, because a guarantee that holds only when a Region happens to be supplied is not a guarantee.

Every boto3 binding in `core/`, `scanner.py`, `cli.py` and `utils/` names its Region with a value derived from the scan (Property 34, empty allowlist): `ScanContext.get_client`'s default, the `sts` / `account` / `organizations` / `ec2` lookups, `OrganizationsClient`, `get_session`'s STS client, and the banner's STS client. Because a Region-less `get_client(svc)` now means the scan Region, the Region-less `sts` and `iam` bindings in service clients reach the scan's partition too, without editing them. `scan_region(ctx)` is total (`-> str`); the revision 4 `GLOBAL_REGION` log label for a `None` Region is gone with the `None` case, and `GLOBAL_REGION` remains only the `Finding` label for non-regional rows.

**Out of scope: genuinely `us-east-1`-only control planes.** Shield, WAF for CloudFront, Firewall Manager's admin API and CloudFront bind the literal `us-east-1` on purpose and are untouched. Outside the `aws` partition they address commercial endpoints with that partition's credentials, so they produce ERROR rows, never a fabricated FAIL. Making them partition-aware needs a per-partition control-plane Region map and is a separate change. The claim this design makes is therefore: Organizations, STS, the Account API, Region discovery, and every Region-less client binding derive the partition from the scan Region, and a scan whose Region cannot be determined refuses to start.

Rejected alternatives, briefly. *Default to `us-east-1`*: wrong in every partition but one, silently. *`botocore`'s `get_partition_for_region` mapped to a canonical Region per partition*: duplicates a table botocore owns, and picks a Region the operator never named. *`ctx.get_enabled_regions()[0]`*: issues `ec2:DescribeRegions` before a Region is known, which is the question being answered. *A `--partition` flag*: a new input to say something the existing inputs already say.

What the offline tests assert (Requirement 2.4, Properties 6, 32–34): explicit `us-gov-west-1` and `eu-west-1` are used as given; a session configured for `us-gov-west-1` is used when there are no explicit Regions; neither raises at `ScanContext` construction with no client built; `get_session` with `--role` and no Region raises before any STS client is built; the CLI exits 2 with no file and no client; and `get_enabled_regions` asks the scan Region. Partition correctness then follows from the endpoint data and is not asserted live, because the test organization and the CodeBuild deployment are both commercial (Requirement 12.5); the report says so, and says that the specific error a cross-partition call returns is inferred rather than observed.

## Error Handling

The three tiers are unchanged in principle; the provider path adds nothing a check has to learn. Restated for the operations this design touches:

**Client tier — `core/organizations_client.py`.** Each of the seven methods catches exactly `AWS_EXCEPTIONS` and returns `self.aws_error(e)`. A `ClientError` on any page of `list_accounts` returns an error result with `Operation == "ListAccounts"` and the AWS code and message verbatim; a `BotoCoreError` (unreachable endpoint, missing credentials, timeout) returns one with `Operation == "Request"` and the exception type name as `Code`. The whole paginator loop is inside the `try`, so a failure on page three is an error result and not a short list. One `aws_call_failed operation=ListAccounts region=<derived> code=<Code> message=<JSON>` record at `debug`, emitted by `aws_error` and nowhere else (Requirement 1.8). Anything that is not an AWS exception — `AttributeError` from a botocore too old to know the operation, `KeyError` — propagates. Recoverable from the caller's view: the check gets a dict either way.

**Provider tier — `core/organization.py`.** `accounts()` does not inspect the error beyond `is_error`. On an error result it returns the result unchanged and writes nothing, so the slot stays empty and the next caller — the next Region of the same check, or the next check — re-issues the call (Requirement 1.4). It never returns `{}`, `[]` or `None`. It has no no-client branch (Requirement 1.5). It logs two `debug` records on the happy path (fetch, then cached-N) and one on a hit, and nothing on a failure beyond what the client logged. `_set`'s backstop still refuses an error result if some future edit tries to cache one, and logs a `warning` naming `organizations:all_accounts`; that is the storage layer's defence and this design does not rely on it.

**Check tier — the fifteen call sites.** Unchanged shape: `"Error" in response`, then `self.is_not_configured(error)` decides FAIL versus ERROR against the service table and then the provider table, then `self.error(..., actual_value=f"{Operation} failed: {Code}: {Message}", remediation=self._remediation_for(error))`. In Phase 1 the provider table is empty and no service table declares `ListAccounts`, so **every** failed sweep is an ERROR row, which is what both reference trees produce (Requirement 3.3). The orchestrator's per-check guard in `run_checks` is unchanged and, after this design, still has nothing to catch from the Organizations path: a synthetic ERROR row from `accounts()` would mean a programming defect.

### The same error, two checks

A `ListAccounts` denial — observed shape from a member account that is neither management nor a delegated administrator — produces one ERROR row per Region in `SRA-SECURITYHUB-08` and one global row in `SRA-ORGANIZATIONS-12`. The cells differ exactly where the checks differ, and nowhere else:

| Cell          | `SRA-SECURITYHUB-08` (audit, regional)                                                                                                                                                                                                                                                                                                                | `SRA-ORGANIZATIONS-12` (management, global)                  |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| `Status`      | `ERROR`                                                                                                                                                                                                                                                                                                                                               | `ERROR`                                                      |
| `Region`      | `us-east-1` (one row per scanned Region; the call is re-issued per Region because a failure is not cached)                                                                                                                                                                                                                                            | `global`                                                     |
| `ResourceId`  | the check's own, e.g. `securityhub/us-east-1/organization`                                                                                                                                                                                                                                                                                            | the check's own                                              |
| `ActualValue` | `ListAccounts failed: AccessDeniedException: You don't have permissions to access this resource.`                                                                                                                                                                                                                                                     | identical text                                               |
| `Remediation` | from `_remediation_for`: the message matches neither the not-the-administrator needles nor the IAM-denial needles, so the third access-denied bucket: `ListAccounts was refused without saying why. Check both causes: whether the member role is granted the action … and whether the scanned account is the Security Hub delegated administrator …` | same bucket, `… the Organizations delegated administrator …` |
| `Service`     | `Security Hub`                                                                                                                                                                                                                                                                                                                                        | `Organizations`                                              |

The remediation names `self.service`, so the Security Hub row advises checking the *Security Hub* delegated administrator for a failure that is Organizations'. That wording is what both reference trees emit today and Phase 1 preserves it (Requirement 3.6); whether `_remediation_for` should name the operation's service rather than the check's when the two differ is a Phase 2 question, recorded in Open Questions, and is only answerable once the provider owns every Organizations operation and the row text can be A/B'd.

### Failure modes outside the row

| Condition                                                                              | Where it surfaces                                                                                                                                             | Recoverable?                                                                  | Logged                                                                                           |
| -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| The provider is called after its context was collected (`_ctx_ref()` is `None`)        | `RuntimeError("OrganizationsProvider outlived its ScanContext")` from `accounts()`; unreachable through `ctx.organization`, since the caller then holds `ctx` | Programming defect; not an AWS outcome                                        | By the caller                                                                                    |
| A check declares `organization` as a class attribute                                   | Import time, `CheckIdentityError`                                                                                                                             | Fatal to the import; fix the check                                            | Exception message names class and attribute                                                      |
| A check reads `self.organization` before `initialize(ctx)`                             | `RuntimeError` naming `<CHECK-ID>.organization`                                                                                                               | Programming defect                                                            | By the caller                                                                                    |
| The primer is reached before any caller guarded `accounts()` and the sweep fails       | Primer logs at `debug`, seeds nothing, returns; `check_log_source_configured` then reads an absent slot as `[]` for that account                              | Yes: the slot is empty, not poisoned; the check's own guard reports the ERROR | `SecurityLake: could not list organization accounts to prime <region>; seeding nothing (<Code>)` |
| `botocore` lacks the `list_accounts` paginator (impossible at the pinned floor)        | `AttributeError` escapes the client → synthetic ERROR row                                                                                                     | Programming/environment defect                                                | By the orchestrator                                                                              |
| The generator's `known_service_ids()` cannot load (`botocore` absent in the tool venv) | `generate_iam_policy.py` exits non-zero before writing                                                                                                        | Fatal to the run; install the dev group                                       | stderr                                                                                           |

### Validation of inputs

The provider takes no external input. `scan_region`'s inputs are `ctx.regions` (the context's own copy of the explicit list, or `[]`) and `ctx.session.region_name`; `resolve_scan_region` accepts only a usable Region string from either and raises `PartitionUndeterminedError` otherwise. It does not validate a name against endpoint data: an unknown name resolves to the `aws` partition and surfaces from botocore on the first call as an error result like any other. `accounts()` validates nothing on the response: it is cached by identity on `not is_error(response)` and consumers already tolerate a missing `Accounts` key with `.get("Accounts", [])`. The generator's one external input is the tree it walks; a file that does not parse raises `SyntaxError` from `ast.parse` and the run fails, which is the right outcome for a tool whose output feeds a deployed policy.

## Correctness Properties

Each statement below is held by the test suite, offline, with no credentials. Enumeration is by reflection or by AST over the real tree wherever the statement ranges over modules, bases or checks, so a module added later is covered without a second edit. Where a statement needs to call the provider or a client method, it goes through an adapter declared in the test module, and a companion statement proves the adapter set equals the reflected set in both directions. Source-text matching is used for 8 and 30 only, where a text match is the intent. The rules numbered 10, 12, 15 and 34 are AST rules, so prose (a docstring, a comment, a steering paragraph explaining the migration) can name a forbidden symbol without failing them, and every file they read is a package `.py` located from `sraverify.__file__`, so they run from an installed wheel. Requirements 12 and 13 range over live scans and a later MR; they are held by the acceptance gate and the Phase 2 design, not here.

### Property 1: One sweep serves the whole scan

*For any* scan context over a mock session, and any sequential sequence of calls to `ctx.organization.accounts()` made from checks built on any of the six consuming bases across any set of Regions (the cache is double-checked, not single-flight, so concurrent first callers are out of scope until Requirement 13.7), the `organizations` mock's `get_paginator("list_accounts").paginate` is invoked exactly once, every later call returns the same object, and no regional `organizations` mock (`(organizations, <region>)` for a scanned Region other than the derived one) receives any call.

**Validates: Requirements 1.3, 10.3**

### Property 2: Every page is merged

*For any* paginated `ListAccounts` response of two or more pages, `accounts()` returns a dict whose `Accounts` list is the concatenation of every page's `Accounts` in page order, whichever consuming base asks first.

**Validates: Requirements 1.2, 10.3**

### Property 3: A failure is returned unchanged, never cached, and re-issued until a success is cached

*For any* `ClientError` or `BotoCoreError` raised on any page of the sweep, `accounts()` returns a value satisfying `is_error` with `Operation == "ListAccounts"` for a `ClientError` and `Operation == "Request"` for a `BotoCoreError`, `ctx._has("organizations", "all_accounts")` is `False` afterwards, and *for any* n subsequent callers while the mock keeps failing the sweep is started n more times; once the mock succeeds, exactly one more sweep starts and every further caller is a cache hit.

**Validates: Requirements 1.4, 10.3**

### Property 4: The provider filters for nobody

*For any* successful sweep, the object `accounts()` returns is the client's response dict by identity (`is`), with no element added, removed, re-ordered or copied; the set of public callables in `vars(OrganizationsProvider)` (names not starting with `_` for which `inspect.isfunction` holds) is exactly `{"accounts"}`; and the set of top-level names `core/organization.py` defines (every `ClassDef`, `FunctionDef`, `Assign` and `AnnAssign` target at module level, by AST, excluding names starting with `_`) is exactly `{"OrganizationsProvider", "NAMESPACE", "ACCOUNTS_KEY"}` — so no filtering helper exists anywhere in the module, by construction rather than by inspection of what a function does.

**Validates: Requirement 1.7**

### Property 5: Constructing a context constructs no boto3 client

*For any* `ScanContext` constructed over a mock session, `session.client` is not called during construction, `ctx.organization` is an `OrganizationsProvider`, and the first `session.client("organizations", ...)` call happens on the first `accounts()` call and not before.

**Validates: Requirements 1.1, 1.6**

### Property 6: The Organizations client is built for the scan's partition

*For any* `ScanContext`, `scan_region(ctx)` is `ctx.regions[0]` when `ctx.regions` is non-empty, else `ctx.session.region_name`, and equals `ctx.scan_region`; the first `accounts()` call passes exactly that string to both `AWSClient.__init__` and `ctx.get_client("organizations", region=...)`, so the `aws_call_failed` record carries `region=<that value>`. In particular `regions=["us-gov-west-1"]` yields `"us-gov-west-1"`, `regions=["eu-west-1"]` yields `"eu-west-1"`, and no explicit Regions over a session configured for `us-gov-west-1` yields `"us-gov-west-1"`; no explicit Regions over a session with `region_name=None` (or with no `region_name` attribute at all) raises `PartitionUndeterminedError` at `ScanContext` construction, with no client built. `ctx.get_enabled_regions` is never called on this path.

**Validates: Requirements 2.2, 2.3, 2.4**

### Property 7: The IAM client's Organizations binding derives its Region the same way

*For any* `ScanContext`, constructing `IAM_Client(ctx)` requests `ctx.get_client("organizations", region=scan_region(ctx))`, so that it and `OrganizationsClient(ctx)` resolve to the same `(service, region)` client-cache key, and the source of `services/iam/client.py` contains no `region='us-east-1'` literal on an `organizations` binding.

**Validates: Requirement 2.5**

### Property 8: Only the relocated client issues `ListAccounts`

*For any* `.py` module under `core/` and `services/` other than `core/organizations_client.py`, the source does not contain `get_paginator("list_accounts")` in either quote style, and `core/organizations_client.py` does contain it (non-vacuity); and *for any* `.py` module under `core/` and `services/` other than `core/organization.py`, the source does not contain `.list_accounts(`, while `core/organization.py` contains `.list_accounts(` exactly once **and** contains neither `get_paginator(` nor the receiver text `.client.`, which proves the provider's one occurrence is a call on the wrapper and not on a boto3 client. The two spellings have two permitted sets because a text rule cannot tell the boto3 method `list_accounts` from the wrapper method of the same name that the provider must call; the client module defines `def list_accounts(` and issues the boto3 call through `get_paginator`, so it never contains the `.list_accounts(` spelling, and `.list_accounts_for_parent(` in `services/organizations/base.py` does not match it either.

**Validates: Requirements 2.7, 10.4**

### Property 9: The relocated client honours the client contract

*For any* of the seven public methods of `core.organizations_client.OrganizationsClient`, driven through its adapter: a simulated `ClientError` returns an error result carrying the adapter's operation, `EndpointConnectionError` and `NoCredentialsError` return error results with `Operation == "Request"`, `RuntimeError` propagates, the success path returns the adapter's success shape, and exactly one `aws_call_failed` record is emitted per failure. The module passes the static rules: every `except` is `AWS_EXCEPTIONS as e` with body `return self.aws_error(e)`, the class inherits `AWSClient`, every `ctx.get_client` call sits in `__init__`, and no method is annotated `-> bool`. The adapter table and `vars(OrganizationsClient)`'s public methods are equal sets, and the class is enumerated by the harness exactly once.

**Validates: Requirements 2.1, 10.2**

### Property 10: `core` imports nothing from `services`

*For any* module under `sraverify/core/`, no `Import` node has an `alias.name` equal to or starting with `sraverify.services`, no `ImportFrom` node has a `module` equal to or starting with `sraverify.services` (and none has `level > 0` resolving into `services`), and no `ast.Constant` whose value is a `str` equals or starts with `sraverify.services`. No module is exempted: `core/discovery.py` needs none, because it receives the package name as the `package_name` argument that `services/__init__.py` passes as `__name__`, and today no `core/` module carries such a constant (the only occurrence of the dotted path in `core/` is a comment at `core/check.py:375`, which the AST does not see). Comments, docstrings and f-string fragments that contain the word `services` are out of scope on purpose; the property is about the import edge, not the vocabulary.

**Validates: Requirements 4.1, 4.2**

### Property 11: No service base inherits anything between itself and `SecurityCheck`

*For any* `<Service>Check` class declared in a `services/<svc>/base.py`, `cls.__mro__[1]` is `SecurityCheck`; equivalently the MRO strictly between the base and `SecurityCheck` is empty.

**Validates: Requirement 4.5**

### Property 12: The mixin is gone

*For any* `.py` file under the package directory (`Path(sraverify.__file__).parent`, which includes `tests/`), **excluding the asserting test module itself**, no `Name`, `Attribute`, import alias, imported module path (or any of its dotted segments), or function or class definition is one of `OrganizationAccountsMixin`, `ORGANIZATION_ACCOUNTS_NAMESPACE`, `ORGANIZATION_ACCOUNTS_KEY` or `get_organization_accounts`, no import names `sraverify.services.organizations.accounts`, and that path does not exist. The rule is an AST walk over package code only: string constants are not identifiers, so docstrings, comments and Markdown (the steering docs and the README included) may name the history, and the module reads nothing outside the package, so it runs from an installed wheel. A non-vacuity case shows the extractor finds the mixin in an in-memory source that imports and uses it, and nothing in one that names it only in a docstring, a comment and a string.

**Validates: Requirements 4.4, 5.2**

### Property 13: `organization` is read-only and requires a context

*For any* registered check class (parametrized over the whole catalog), instantiated and not initialized, reading `.organization` raises `RuntimeError` whose message contains both the check ID and `organization`; assigning to `.organization` on any instance raises `AttributeError`; and after `initialize(ctx)` over a real `ScanContext` with `regions=["us-east-1"]` and an inert session, the property returns `ctx.organization` by identity, issuing no call.

**Validates: Requirement 5.1**

### Property 14: Nothing shadows `organization`

*For any* registered check class and every class in its MRO below `SecurityCheck`, `"organization" not in vars(klass)`; and *for any* `SecurityCheck` subclass created in a module whose stem matches `sra_*` with `organization` in its class body, `__init_subclass__` raises `CheckIdentityError` naming the class and the attribute, leaving the registry unchanged.

**Validates: Requirement 5.3**

### Property 15: Only `services/organizations/base.py` builds the Organizations client in Phase 1

*For any* `base.py` under `services/`, the module neither imports `OrganizationsClient` nor calls it (an `ast.Call` on that name) unless it is `services/organizations/base.py`; and *for any* `sra_*` module, by AST, no `Attribute` named `_has`, `_get` or `_set` has a context receiver (an attribute named `_ctx` or `ctx` on any object, or a bare `_ctx` / `ctx` name), no `organization` attribute has such a receiver, and `OrganizationsClient` is neither used nor imported. Prose naming them is not a hit, and an in-memory fixture shows each receiver shape is caught.

**Validates: Requirement 5.2**

### Property 16: The service table decides first, the provider table second, and declaration is what counts

*For any* error result and any pair of tables `(service, provider)`: if the service table declares `(Operation, Code)`, `is_not_configured_in((service, provider), error)` equals the service table's verdict with its needle applied, whatever the provider table says; if only the provider table declares it, the result is the provider table's verdict; if neither declares it, the result is `False`. Held with a synthetic provider entry patched onto `OrganizationsProvider.NOT_CONFIGURED_ERRORS` for the test's duration, never committed.

**Validates: Requirements 3.2, 3.4**

### Property 17: The provider table is a well-formed discriminator table

*For any* entry in `OrganizationsProvider.NOT_CONFIGURED_ERRORS`, the operation and code are non-blank strings, the value is a `NotConfigured` whose `evidence` is non-blank and contains no placeholder token, and `is_not_configured_in` returns `False` for any `(Operation, Code)` not in it. In Phase 1 the table is `{}` and declares nothing for `ListAccounts`.

**Validates: Requirements 3.1, 3.3**

### Property 18: A failed sweep reaches `error()` with the operation and code, never `failed()`

*For any* registered check, with every service accessor and `ctx.organization.accounts()` returning a non-semantic error result whose `Operation` is `ListAccounts`, every row `execute()` yields has `Status.ERROR`, an `ActualValue` matching `^ListAccounts failed: <Code>: ` where the row was produced from that result, and a non-blank `Remediation`; no row is `PASS` or `FAIL`.

**Validates: Requirements 3.6, 10.1**

### Property 19: A guarded primer issues no second sweep

*For any* `SecurityLakeCheck` whose caller has called `accounts()` once and then `check_log_source_configured(region, source, account, version)` for any member account, the `ListAccounts` sweep count is 1, and the primer wrote one `list_log_sources:<account>:<region>` slot per organization account.

**Validates: Requirement 7.3**

### Property 20: The primer seeds every member account from the provider, including one on a later page

*For any* two-page `ListAccounts` armed on the mock and a regional `ListLogSources` response naming an account present only on the second page, `check_log_source_configured("us-east-1", "ROUTE53", <that account>, "2.0")` is `True`.

**Validates: Requirements 7.1, 7.4**

### Property 21: The primer seeds nothing when the sweep fails

*For any* `SecurityLakeCheck` reached at `_prime_region_log_sources(region)` directly, with the sweep armed to fail and `ListLogSources` armed to succeed, no `list_log_sources:<account>:<region>` slot is written for any account including the scanned one, the method returns `None`, and one `debug` record naming the error code is emitted.

**Validates: Requirements 7.2, 7.4**

### Property 22: No `BatchGetAccountStatus` request exceeds the cap, and the merge is lossless

*For any* list of 101 distinct account IDs driven through `InspectorCheck.batch_get_account_status(region, ids)` over a mock client, every client call received at most 100 IDs, the calls' inputs partition the 101 without loss or duplication, and the merged result's `accounts` has 101 entries in input order. *For any* batch that returns an error result, the accessor returns that error result, caches nothing, and no partial `accounts` list is returned.

**Validates: Requirements 8.2, 8.4**

### Property 23: The generator sees a call issued from `core/`

*For any* run of `build()` over the package, the attributed set contains `ec2 → describe_regions` and `account → get_account_information` (from `core/scan_context.py`), `organizations → list_accounts` (from `core/organizations_client.py` and from no module under `services/`), and `sts → get_caller_identity`; and does not contain `sts → assume_role`, because `core/session.py` is in `EXCLUDED_MODULES`. The seven operations of `OrganizationsClient` are all attributed to `organizations`.

**Validates: Requirements 9.1, 9.3, 9.5**

### Property 24: A string literal that is not a boto3 service id binds nothing

*For any* module source containing `client = self.get_client('us-east-1')` followed by `client.get_admin_account()`, `bind_clients` returns `{}` and `collect_calls` attributes nothing; and *for any* literal in `known_service_ids()`, the same shape binds. `services/firewallmanager/base.py` and `services/waf/base.py`, walked for real, contribute no attribution.

**Validates: Requirement 9.1**

### Property 25: Regenerating is a no-op against the committed artefacts

*For any* run of the generator over the tree, the derived policy's action set equals the committed `generated_sraverify_iam_policy.json`'s action set exactly, and the committed set contains `ec2:DescribeRegions` and `account:GetAccountInformation`.

**Validates: Requirements 9.3, 9.5**

### Property 26: The provider's accessor table is complete, exact and used by the catalog harness

*For any* public method of `OrganizationsProvider` other than the class attribute `NOT_CONFIGURED_ERRORS`, the provider adapter table in the provider test module has exactly one entry naming it and its operation, and vice versa; and the catalog-wide classification harness's stub for `ctx.organization` is built from that table, so a provider accessor added without a table row fails the completeness test rather than running unpatched against a `MagicMock`.

**Validates: Requirements 10.1, 10.6**

### Property 27: The new `core` modules write nothing to stdout

*For any* module under `core/` including `organization.py` and `organizations_client.py`, the source contains no `print(`, no `sys.stdout` or `sys.__stdout__`, no `warnings.warn`, and no logging handler construction.

**Validates: Requirement 10.7**

### Property 28: The provider is unreachable from a finding and collectible with the context

*For any* list of findings returned by `run_checks`, no `ScanContext` and no `OrganizationsProvider` is reachable from any finding through `gc.get_referents` (the isolation test's walk forbids `ScanContext`, `SecurityCheck` and `OrganizationsProvider` by type); *for any* `ScanContext`, `ctx.organization._ctx_ref` is a `weakref.ReferenceType` whose referent is `ctx` and no attribute of the provider holds `ctx` strongly; and *for any* `ScanContext` whose provider has been used (one `accounts()` call over a mock session, so a wrapper has been built and discarded) and which is then dropped by its only external reference, a `weakref` to its provider is dead **immediately**, with `gc.disable()` in force and no `gc.collect()` call — the deterministic, refcount-only release Requirement 1.1's "dropped with `del ctx`" describes.

**Validates: Requirements 1.1, 1.9**

### Property 29: The provider logs a fetch once and a hit thereafter, and never an `aws_call_failed`

*For any* successful sweep followed by n cache hits, the `sraverify` logger receives exactly one record containing `Fetching organization accounts`, exactly one containing `Cached <N> organization accounts`, exactly n containing `Using cached organization accounts`, and zero `aws_call_failed` records; *for any* failed sweep, exactly one `aws_call_failed` record is emitted, carrying `operation=ListAccounts` when the failure was a `ClientError` and `operation=Request` (`UNKNOWN_OPERATION`) when it was a `BotoCoreError`, and that record's `funcName` is `aws_error` in `core/aws_client.py` — the provider emits none of its own.

**Validates: Requirement 1.8**

### Property 30: Every consumer migrated by exactly one token

*For any* of the fifteen consumer modules, the source contains `self.organization.accounts()` exactly once, contains `get_organization_accounts` zero times, and its `CheckMeta` is unchanged, so `sraverify --list-checks` is `cmp`-identical to `docs/checks.txt`.

**Validates: Requirements 6.1, 6.6, 10.9**

### Property 31: The service base tables need no new row

*For any* service, `test_every_public_base_method_is_classified` holds against `vars(base)` with no `get_organization_accounts` row and no provider row, and the public client-method count across the seventeen remaining `services/*/client.py` classes plus the relocated client is 108, with the relocated client's seven counted where they were.

**Validates: Requirements 6.4, 10.6**

### Property 32: The scan Region follows one precedence

*For any* explicit Region list whose first element is a usable Region string and any session, `resolve_scan_region` returns that element by identity; *for any* `None` or empty list and a session whose `region_name` is a usable Region string, it returns the session Region; *for any* non-empty list whose first element is not usable (blank, padded, `None`, not a `str`) it raises `PartitionUndeterminedError` with `reason == "invalid"` and `bad_value` that element, without consulting the session; and otherwise it raises with `reason == "absent"` and `bad_value is None`. The message is one line naming `--regions`. `ctx.scan_region` equals `scan_region(ctx)`, has no setter, and is unchanged after the caller mutates the list it passed in; `get_session(role_arn=R)` binds STS and the assumed session to the same Region, and keeps today's wrapped `Exception` for profile and AssumeRole failures.

**Validates: Requirements 2.2, 2.4**

### Property 33: An undetermined scan exits 2 with no file and no AWS call

*For any* CLI invocation with no `--regions` and no session Region, with or without `--role` and with or without an otherwise bad `--check`, `main` returns 2, the output path does not exist, no boto3 client is built (so neither the banner's `sts:GetCallerIdentity` nor `sts:AssumeRole` is attempted), stdout carries no banner, and exactly one ERROR record names `--regions` and `AWS_DEFAULT_REGION` (and `AWS_REGION` set alone is the same exit 2); `run_checks` raises before a `ScanContext` is constructed; and `--list-checks` without `--role` returns 0 with no client built.

**Validates: Requirement 2.8**

### Property 34: No Region-less or literal-Region binding in core, scanner, cli or utils

*For any* module under `core/`, `scanner.py`, `cli.py` and `utils/`, every `get_client` call whose service id (first positional, else `service_name=`) is a string literal passes `region=` with a non-literal value, and every `.client` call passes `region_name=` with a non-literal value; the allowlist is empty; an in-memory fixture shows four violations caught and four compliant lines (including the wrapper lookup `self.get_client(region)`) passed; and `ScanContext.get_client(svc)` and `get_client(svc, region=ctx.scan_region)` return the same client, with no `session.client` call receiving `region_name=None`.

**Validates: Requirement 2.9**

### Property 35: An unbindable client site warns, except the two allowlisted shapes

*For any* module the IAM generator walks, a `get_client(...)` or `.client(...)` call whose service id is not a literal boto3 service id yields exactly one warning naming `<module>:<line>`, unless it is the SecurityCheck-family wrapper lookup (bare `self` receiver, one positional argument, no keywords, inside a class with a `*Check` base) or the factory (`<recv>.client(<param>, ...)` inside a function named `get_client` forwarding its own parameter); the real tree yields no warning of either kind.

**Validates: Requirement 9.8**

### Property 36: The suite runs from an installed wheel

*For any* test module in the built wheel, run with `pytest --pyargs sraverify` from a directory outside the repository with the repository's configuration replaced by `/dev/null`, the test passes or skips with a reason naming a repository-only path that is absent; and the layering module reads only package `.py` files located from `sraverify.__file__`.

**Validates: Requirement 10.10**

## Testing Strategy

Everything in this section runs under `cd sraverify && uv run pytest -q` with no credentials and no network (`tests/conftest.py` refuses outbound HTTP). The branch starts from `refactor/shared-org-accounts-accessor`, so the 24 tests !54 wrote are the starting material and most of the work is adapting them rather than writing from nothing. No `xfail` is introduced. The final collected/passed/skipped counts are recorded in `structure.md` and `tech.md` after the run (the !54 branch reports 8865 passed, 597 skipped, 9462 collected).

### Modules that change

| Module                                                                           | Change                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `test_organization_accounts_property.py`                                         | **Renamed** `test_organization_provider_property.py`; holds Properties 1–4, 19–21, 26, 28, 29 and the provider adapter table. See below for the per-test mapping.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `test_check_classification_property.py`                                          | `_SHARED_ACCESSORS` (line 67), the inherited-name branch of `_accessor_names` (116–122), the second half of `_OPERATION_OF_ACCESSOR` (422–427) and the `_base_class` import are **deleted**. `_make_context()` stubs `ctx.organization` through `stub_organization(ctx)`; `_prepare` forwards `returns=` and `record=` into the stub; `_operation_of(service, name)` consults the provider table for a recorded `organization.<accessor>` name before the service join. Property 18 is the existing Property 14 running with the stub in place.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `test_client_contract_property.py`                                               | Enumeration is by a `_CLIENT_MODULES: dict[str, str]` map (adapter key → dotted module) built as `{svc: f"sraverify.services.{svc}.client" for svc in _service_names() if (services/svc/client.py).exists()} \| {"organizations": "sraverify.core.organizations_client"}`. `_client_classes(key)` imports `_CLIENT_MODULES[key]`; `_client_module_paths()` is derived from the imported modules' `__file__`, so the AST rules scan `core/organizations_client.py`. The parametrize ID format changes from `f"{path.parent.name}/client.py"` (lines 1790 and 1808) to `f"{path.parent.name}/{path.name}"`, and the six failure messages that hard-code `/client.py` (lines 1863, 1918, 1957, 1996, 2053, 2078) interpolate `path.name` the same way, so the relocated module reads `core/organizations_client.py` and every service module reads as before. The `_ORGANIZATIONS` adapter table is unchanged in content. `_build_wrapper` sets `ctx.regions = [_TEST_REGION]` and `ctx.session.region_name = _TEST_REGION` so `scan_region` is deterministic over the mock. Property 9. |
| `test_accessor_cache_property.py`                                                | No table change (Requirement 10.6). `_base_class` stays for its own use. Property 31 is the existing `test_every_public_base_method_is_classified`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `test_discriminator_property.py`                                                 | The table enumeration gains `OrganizationsProvider.NOT_CONFIGURED_ERRORS` alongside the eighteen service tables; a new test holds Property 16 with a synthetic entry via `patch.object(OrganizationsProvider, "NOT_CONFIGURED_ERRORS", {...})`. Property 17.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `test_absent_resource_verdict_property.py`, `test_service_migration_property.py` | Each `MagicMock(spec=ScanContext)` they build gets `stub_organization(ctx)` **defensively** (Requirement 10.1 names them). Neither reaches `ctx.organization` today — the first drives GuardDuty checks only (`_GUARDDUTY`), the second drives one canonical base accessor per service (`_invoke_*`), none of which reads the account list or the primer — so the stub changes no current outcome; it is there so a case added later cannot run against an auto-specced `organization`, which returns a truthy, iterable, non-error `MagicMock`. Only `test_check_classification_property` drives a consumer check through the provider.                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `test_stdout_contract_property.py`                                               | No edit; its module walk picks up the two new `core` modules. Property 27.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `test_context_isolation_property.py`                                             | The finding-reachability walk forbids `OrganizationsProvider` beside `ScanContext` and `SecurityCheck` (revision 5); Property 28's `weakref` half lives in the provider module.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `tests/unit/core/test_check_registration.py`                                     | Gains the `organization`-shadow case, written on the `synthetic_service` fixture (line 193) exactly as `test_a_class_attribute_shadowing_a_metadata_property_raises` (line 873) and its intermediate-base sibling (line 899) are: a well-formed `sra_guardduty_01.py` source with a valid `meta` **plus** `organization = None` in the class body raises `CheckIdentityError` naming the class and `organization`, and a second case puts the attribute on an intermediate base declared in `base.py`. A valid `meta` is required because Identity rule 2 (meta declared in the class body) runs before the shadow rule, so a `type(...)`-built class without `meta` would raise for the wrong reason. Property 14.                                                                                                                                                                                                                                                                                                                                                                   |
| **New** `tests/unit/core/test_scan_context.py`                                   | Property 5; Property 6's three derivation cases and the two raising cases (session `region_name=None`, session with no attribute); Property 7 for `IAM_Client`, plus its raise; and the context half of Properties 32 and 34: `scan_region` read-only and copy-safe, `get_enabled_regions` asks the scan Region, the `sts` / `account` / `organizations` lookups bind it, a Region-less `get_client` is the scan-Region client, and the management lookup shares `OrganizationsClient`'s instance.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `tests/unit/util/test_generate_iam_policy.py`                                    | See "The generator's tests" below. Properties 23–25, and Property 35: the real tree yields no warning, a variable service id in a synthetic `core/x.py` yields exactly one warning naming `core/x.py:3`, the two allowlisted shapes yield none, and the wrapper-lookup shape outside a `*Check` class warns.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| **New** `test_layering_property.py`                                              | Property 10 (AST over `core/`), Property 11 (empty MRO), Property 12 (AST over package code only, with a code-versus-prose non-vacuity case; no steering or README walk, no `_REPO_ROOT`), Property 15 (AST: only `organizations/base.py` imports or calls the client; no `sra_*` reaches the context's cache primitives or `organization`, matched on the receiver, with a fixture), Property 30 (fifteen consumers, one token each), Property 8 (two permitted sets, source text), and Property 34 (no Region-less or literal binding in `core/`, `scanner.py`, `cli.py`, `utils/`; empty allowlist; four-plus-four fixture). Every path is derived from `sraverify.__file__`.                                                                                                                                                                                                                                                                                                                                                                                                      |
| **New** `tests/unit/services/test_inspector_batching.py`                         | Property 22: the 101-ID test and the failing-batch test. `tests/unit/services/` exists and holds only `__init__.py` today.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| **New** `tests/unit/core/test_scan_region.py`                                    | Property 32: precedence (a), (b) and (c), every unusable explicit value, a hypothesis property over usable first values, and the error's shape.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| **New** `tests/unit/core/test_session_region.py`                                 | Property 32's `get_session` half: refusal before AssumeRole, STS and the assumed session bound to the explicit or profile Region, wrapped `Exception` preserved for AssumeRole and profile failures, and the no-role path unchanged.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| **New** `tests/unit/core/test_partition_failfast.py`                             | Property 33's library half: `run_checks` raises before `ScanContext`, `resolve_scan_region()` applies the precedence, and `SRAVerify` passes `regions[0]` to `get_session`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `tests/unit/cli/test_exit_codes.py`                                              | Property 33's CLI half: exit 2 with no file and no client, the partition error ahead of a bad `--check`, `--role` refused before AssumeRole, `--list-checks` region-free without `--role` and exit 2 with it, and precedence (a) and (b) observed on the banner's STS build.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| **New** `tests/unit/services/test_securityhub_organization.py`                   | `SecurityHubCheck.get_organization()` binds `("organizations", region=<scan Region>)` over a GovCloud context, and the module pins no Organizations Region (Requirement 6.5).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `test_catalog_executable_property.py`                                            | Property 13 catalog-wide: `organization` added to the context properties read before `initialize`, plus a no-setter case and an identity-after-`initialize` case for every registered check.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |

### The 24 !54 tests, one by one

| !54 test (`test_organization_accounts_property.py`)              | Phase 1 disposition                                                                                                                                                                                                                                                                                                                                                                                               |
| ---------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `test_every_base_reads_accounts_through_the_mixin` (×6)          | **Deleted.** Replaced by Property 11 (empty MRO) and Property 15 (no base builds the client), which assert the absence the mixin test asserted the presence of.                                                                                                                                                                                                                                                   |
| `test_only_the_organizations_client_issues_list_accounts`        | **Rewritten** as Property 8 in `test_layering_property.py`: forbidden set every module under `core/` and `services/`, not only `client.py`; the paginator spelling permitted in `core/organizations_client.py` only, the `.list_accounts(` spelling in `core/organization.py` only, and the provider module proven to call the wrapper (no `get_paginator(`, no `.client.`); non-vacuity kept for both spellings. |
| `test_every_page_is_merged` (×6)                                 | **Kept**, driving `_check(base, ctx).organization.accounts()` per base. Property 2.                                                                                                                                                                                                                                                                                                                               |
| `test_one_sweep_serves_every_service_and_region_in_the_scan`     | **Kept**; adds the assertion that no regional `organizations` mock was called. Property 1.                                                                                                                                                                                                                                                                                                                        |
| `test_the_slot_is_the_one_organizations_checks_use`              | **Kept**, as "a value cached through one base is what another base's check reads" — same `("organizations", "all_accounts")` key. Property 1.                                                                                                                                                                                                                                                                     |
| `test_a_failure_is_returned_unchanged_and_not_cached` (×6)       | **Kept.** Property 3.                                                                                                                                                                                                                                                                                                                                                                                             |
| `test_a_failure_is_re_issued_and_a_later_success_is_cached`      | **Kept.** Property 3.                                                                                                                                                                                                                                                                                                                                                                                             |
| `test_security_lake_primes_log_sources_for_every_member_account` | **Kept** (the two-page regression test, Requirement 7.4), with `ctx._account_info = {...}` replaced by a `get_account_info` stub (review nit N6). Property 20.                                                                                                                                                                                                                                                    |
| `test_reading_before_initialize_names_the_accessor`              | **Kept**, reading `.organization` and matching `"organization"`. Property 13.                                                                                                                                                                                                                                                                                                                                     |

The module docstring is rewritten to say three regional copies (Macie, Security Hub, Security Lake), not four (review nit N1). The `_Session` stand-in, `_arm_pages`, `_arm_failure`, `_sweeps`, `_scan` and `_check` helpers are kept; `_check` no longer needs a base that inherits anything, so it builds any concrete base's throwaway subclass with `_concrete(base)` as before.

### New tests in the provider module

- **The complement of the primer test** (Property 21): arm the sweep to fail and `ListLogSources` to succeed, call `check._prime_region_log_sources("us-east-1")` directly, assert no `list_log_sources:*:us-east-1` key exists in `ctx._cache["securitylake"]` (or the namespace is absent), and that one `debug` record names the code.
- **Guarded primer issues no sweep** (Property 19): `accounts()` then `check_log_source_configured(...)` for a member; `_sweeps(org) == 1`.
- **Identity, no filtering** (Property 4): `accounts() is org_response`. (Property 5, construction is silent, is not here: it lives in `tests/unit/core/test_scan_context.py`, task 12.7, beside the Region-derivation cases it shares a fixture with.)
- **Log shape** (Property 29): with the `client_log` collector pattern from the client-contract module.
- **Collectible, deterministically** (Property 28): build the context directly (`ctx = ScanContext(session=_Session(...), regions=["us-east-1"])`) and call `ctx.organization.accounts()` on it — **not** through a `_check(base, ctx)` instance, whose `_ctx` would be a second strong reference and defeat the `del` — then `ref = weakref.ref(ctx.organization); assert ctx.organization._ctx_ref() is ctx`; then, inside a `gc.disable()` / `gc.enable()` guard with **no** `gc.collect()`, `del ctx; assert ref() is None`. The `_Session` stand-in holds no reference back to the context, and the wrapper built inside `accounts()` is a temporary that is released when the call returns, so the test's local is the context's only external reference. A strong back-reference or a memoised wrapper would make this assertion fail, which is the point: the test distinguishes refcount release from collector release, which the existing `test_context_isolation_property` (which calls `gc.collect()`) cannot.
- **The provider adapter table** (Property 26), declared in this module (`test_organization_provider_property.py`) together with `stub_organization` below, and imported from here by `test_check_classification_property`, `test_absent_resource_verdict_property` and `test_service_migration_property` — the same direction in which `test_check_classification_property` already imports `_ADAPTERS` from `test_accessor_cache_property`:

```python
@dataclass(frozen=True)
class ProviderAdapter:
    method: str        # "accounts"
    operation: str     # "ListAccounts"
    args: tuple = ()

PROVIDER_ADAPTERS: tuple[ProviderAdapter, ...] = (ProviderAdapter("accounts", "ListAccounts"),)

def test_the_provider_adapter_table_is_complete_and_exact() -> None:
    public = {n for n, o in vars(OrganizationsProvider).items()
              if not n.startswith("_") and inspect.isfunction(o)}
    assert public == {a.method for a in PROVIDER_ADAPTERS}
```

### The harness stub

Defined in `test_organization_provider_property.py` beside `PROVIDER_ADAPTERS`, and shared by the three harnesses that build a `MagicMock(spec=ScanContext)` — `test_check_classification_property`, which drives every consumer check through it, and `test_absent_resource_verdict_property` and `test_service_migration_property`, which apply it defensively:

```python
def stub_organization(ctx: MagicMock, *, returns: Any = None,
                      record: list[str] | None = None) -> MagicMock:
    """Give a mock context an ``organization`` whose accessors fail like the service accessors do."""
    provider = MagicMock(name="OrganizationsProvider", spec=OrganizationsProvider)
    for adapter in PROVIDER_ADAPTERS:
        def _stub(*a, _adapter=adapter, **k):
            if record is not None:
                record.append(f"organization.{_adapter.method}")
            if returns is not None:
                return returns
            return error_result(code="TestDenied",
                                message="simulated denial for the classification property",
                                operation=_adapter.operation)
        getattr(provider, adapter.method).side_effect = _stub
    ctx.organization = provider
    return provider
```

`_make_context()` calls `stub_organization(ctx)`; `_prepare(cls, returns=..., record=...)` calls it again with the arguments it was given, so Property 14a's semantic-pair drive reaches the provider accessor with the same `returns` the service accessors get. The recorded name `organization.accounts` is resolved to `ListAccounts` by:

```python
_PROVIDER_OPERATIONS = {f"organization.{a.method}": a.operation for a in PROVIDER_ADAPTERS}

def _operation_of(service: str, name: str) -> str | None:
    return _PROVIDER_OPERATIONS.get(name) or _OPERATION_OF_ACCESSOR.get((service, name))
```

which replaces the second half of the `_OPERATION_OF_ACCESSOR` union. Because `stub_organization` iterates `PROVIDER_ADAPTERS` and Property 26 proves that table equals the provider's public methods, a Phase 2 accessor added without a table row fails one named test instead of running unpatched — the structural answer to review finding S4.

### The MRO test

```python
@pytest.mark.parametrize("service", _service_names())
def test_no_service_base_inherits_between_itself_and_security_check(service: str) -> None:
    base = _base_class(service)
    between = [k for k in base.__mro__[1:] if k is not SecurityCheck and k is not ABC and k is not object]
    assert between == [], f"{base.__name__} inherits {between}; accessors must be declared on the base or reached through the context"
```

`_base_class` comes from `test_accessor_cache_property`, which already finds the one `SecurityCheck` subclass declared in each `base.py`.

### The 101-account Inspector test

```python
from sraverify.tests.property.test_accessor_cache_property import _concrete   # as the !54 module imports it

def test_batch_get_account_status_never_exceeds_the_api_cap() -> None:
    ids = [f"{n:012d}" for n in range(101)]
    client = MagicMock()
    client.batch_get_account_status.side_effect = lambda batch: {
        "accounts": [{"accountId": a, "state": {"status": "ENABLED"}} for a in batch],
    }
    check = _concrete(InspectorCheck)(); check._ctx = ScanContext(session=MagicMock(), regions=["us-east-1"])
    check._clients["us-east-1"] = client
    result = check.batch_get_account_status("us-east-1", ids)
    sent = [c.args[0] for c in client.batch_get_account_status.call_args_list]
    assert all(len(b) <= 100 for b in sent)
    assert sorted(a for b in sent for a in b) == sorted(ids) and sum(map(len, sent)) == 101
    assert [a["accountId"] for a in result["accounts"]] == ids
```

The assertions are written against the cap (100), not the batch constant (10), so they hold if the constant is ever raised. A second test arms the second batch to return an error result and asserts the accessor returns that result, that `ctx._has("inspector", "batch_status:us-east-1")` is `False`, and that no `accounts` key is present.

### The generator's tests

`test_every_client_module_binds_at_least_one_boto3_client` enumerates modules that declare a class whose bases name `AWSClient` (by AST, over the walked set) and asserts each binds ≥ 1; this picks up `core/organizations_client.py` and drops `services/organizations/client.py` with the file. `test_the_generator_attributes_the_whole_tree` adds `ec2` and `account` to its expected set. `test_the_generated_policy_reproduces_the_committed_artefact` is unchanged in logic and holds against the regenerated files. New: `test_the_relocated_organizations_client_is_attributed_from_core` (seven operations → `organizations`, none from under `services/`); `test_a_region_literal_does_not_bind` (Property 24); `test_the_session_builder_is_excluded_and_assume_role_is_not_an_action`; `test_tests_are_not_walked` (a fixture under `tests/` binding `session.client("securitylake", ...)` contributes nothing). `test_waf_client_attributes_nine_services_exactly` and `test_shield_client_attributes_five_services_exactly` hold unchanged (Requirement 9.5).

### What is integration-tested rather than unit-tested

Verdict stability, the one-sweep property observed live, the negative run from a member account, the IAM simulations and the CodeBuild run are Requirement 12 and run against the test organization; they are described in Migration and Rollout and reported in `sratester/organizations-provider-test-report.md`. Partition correctness is not tested live at all (Requirement 12.5).

## Migration and Rollout

### Phase 1 — the MR that replaces !54

**Branch from `refactor/shared-org-accounts-accessor` (986bced), not from `main`.** The !54 branch already carries the fifteen call-site edits in a one-token-from-final form, the six base-class de-duplications, the 24 tests this design adapts, the test-table deletions, and the A/B scripts under `.tmp/sratester/org-accounts/` with their `main`-vs-branch comparison output. Starting there means the Phase 1 diff against !54 is the provider itself and nothing that !54 already did. The branch name is the implementer's choice; the MR description states that it supersedes !54 and !54 is closed unmerged when this MR merges.

The order below is chosen so the suite is runnable after every step and each step's failure is attributable.

1. **`core/` first.** Add `core/organizations_client.py` (the seven methods copied verbatim, `scan_region`, the derived-Region constructor) and `core/organization.py`. Move `core/aws_client.py`'s `ScanContext` import under `TYPE_CHECKING`. Add `is_not_configured_in` and `declared_fact` to `core/aws_errors.py`. Nothing imports the new modules yet; the suite is green.
2. **`ScanContext.organization` and `SecurityCheck.organization`.** Construct the provider last in `ScanContext.__init__`; add the property; add the property and `_SHADOWED_CONTEXT_NAMES` to `core/check.py`; switch `is_not_configured` to the two-table call. Suite green (the provider table is empty, so no verdict moves).
3. **Relocate.** `services/organizations/base.py` imports the client from `core`, drops the mixin and `get_accounts` stays gone; delete `services/organizations/client.py` and `services/organizations/accounts.py`; drop the mixin from the other five bases and fix the Inspector `_setup_clients` docstring (`inspector/base.py:70–71`); apply `scan_region` to `IAM_Client.org_client` (`iam/client.py:38`). Three more docstrings go stale in this step and are corrected in it, none changing behaviour: the `services/inspector/client.py:9–10` module docstring ("reads them through the shared, paginated `OrganizationAccountsMixin.get_organization_accounts`") becomes "reads them through `self.organization.accounts()`" — it names the mixin and would fail Property 12; the `services/iam/client.py:12` module docstring ("is pinned to `us-east-1` like `OrganizationsClient`") becomes "derives its Region from the scan through `scan_region`, like `OrganizationsClient`"; and the `services/securityhub/base.py:925–928` docstring of `get_organization()` ("pinned to `us-east-1` to match `OrganizationsClient` and populate the shared slot with a value from the same boto3 instance") becomes "still pinned to `us-east-1` in Phase 1; `OrganizationsClient` now derives its Region from the scan, so in a non-`aws` partition this binding and the relocated client no longer share a boto3 instance — retired in Phase 2 (Requirement 13.2)". The method itself is untouched (Non-Goal 8). Three test modules fail from this step until step 5 rewrites them, and each failure is expected: the client-contract harness, which enumerates `services/organizations/client.py` by path (cleared when step 5 remaps `organizations` to `core/organizations_client.py`); `test_organization_accounts_property.py`, which fails at **collection** because its imports name `ORGANIZATION_ACCOUNTS_KEY`, `ORGANIZATION_ACCOUNTS_NAMESPACE` and `OrganizationAccountsMixin` from the deleted module (cleared when step 5 renames and adapts it); and `test_check_classification_property.py` on the fifteen consumer checks, because its `_accessor_names` adds `get_organization_accounts` only `if hasattr(_base_class(service), name)`, which is `False` once the mixin is gone — until step 4 `execute()` raises `AttributeError` on `self.get_organization_accounts()`, and between steps 4 and 5 it reads an auto-specced `ctx.organization` `MagicMock`, the "empty success" that property exists to rule out (cleared when step 5 deletes `_SHARED_ACCESSORS` and stubs `ctx.organization`). None of the three is to be "fixed" any other way; the suite is green again at the end of step 5.
4. **Call sites and the primer.** Fifteen one-token edits; rewrite the primer body; Inspector constants and docstring only (the merge is unchanged).
5. **Tests.** Rename and adapt the provider module; delete `_SHARED_ACCESSORS` and the two derived branches; add `stub_organization` to the three harnesses; remap the client-contract enumeration; add `test_layering_property.py`, the Inspector batching tests, the discriminator precedence test, the registration shadow case, the Region-derivation tests. Run the suite; record the counts.
6. **Generator and artefacts.** Rewrite the walk; regenerate `generated_sraverify_iam_policy.json` and `generated_sraverify_cf_policy.yaml`; confirm the diff is exactly the two added actions; edit `1-sraverify-member-roles.yaml` in exactly two statements, both inside the `SRAVerifyLeastPrivilege` policy that mirrors the generated artefact: add `ec2:DescribeRegions` to `Ec2Permissions` (line 145–150) **and** `account:GetAccountInformation` to that policy's `AccountPermissions` (line 79–82), keeping the hand-written `SRAVerifyCheckPermissions` grant at line 51–54 as it is; confirm the template's `SRAVerifyLeastPrivilege` document and `generated_sraverify_cf_policy.yaml` now carry the same action set; `aws cloudformation validate-template`, checkov and cfn-nag per `security_scanning.md`; update the generator tests.
7. **Steering and README.** The named amendments, each one a sentence or paragraph the implementer can find by the text quoted here.

   `structure.md`: (a) adds the provider to the architecture diagram beside `ScanContext` and `core/organization.py` and `core/organizations_client.py` to the layout tree; (b) in the same layout tree, annotates `services/<svc>/client.py` as "every service except `organizations`, whose client is `core/organizations_client.py`", and adds the same qualification to "Adding a new check" step 2 ("New service? Create … `client.py`") and step 3, which otherwise read as if every service package has a `client.py` — after Phase 1 `services/organizations/` has none; (c) changes "`_has` / `_get` / `_set` are for **service base classes only**" to "**service base classes and providers**"; (d) **removes** the !54-added paragraph at line 625 (the paragraph names the mixin at 627) beginning "The accessor tables enumerate `vars(base)`, so a method a base class inherits is invisible to them" and replaces it with a paragraph on the provider and `self.organization` that does **not** name the mixin, its constants or `get_organization_accounts` even as history — Property 12 walks `.kiro/steering/` and would fail on the name — saying instead that no base class inherits anything between itself and `SecurityCheck` (Property 11) and that organization data is reached through the context; (e) lists `organization` as the eighth context property wherever the seven are enumerated; (f) notes in Caching that the `all_accounts` slot is written by the provider and read by no base class by key; (g) in "Error handling: three tiers", tier 2, changes "which reads the service's declared `NOT_CONFIGURED_ERRORS` table" (line 486) to "which reads the service's declared table and then the provider's"; (h) in the test-module table, renames the row `test_organization_accounts_property.py` (line 613) to `test_organization_provider_property.py` and rewrites its cell to describe the provider contract and "only the provider's client issues `ListAccounts`" without naming the mixin; adds a row for `test_layering_property.py`; and changes "AST rules over all 18 `client.py` files" in the `test_client_contract_property.py` row to "over the 17 `services/*/client.py` files and `core/organizations_client.py`"; (i) updates the global-service example in "Canonical code shapes" to say partition-global with the Region derived from the scan; (j) updates the client-method count (108, unchanged in total but relocated), the property-module count and the collected/passed/skipped counts; (k) in "Known structural oddities", changes "three of its accessors pin `self.regions[0]`" for `securityincidentresponse` to "two" (`get_delegated_administrators()` and `get_role()`), since !54 deleted the third.

   `tech.md`: updates the counts and "~26 hypothesis and reflection modules" to **31** (30 `test_*.py` modules under `tests/property/` on the !54 branch; the rename is count-neutral and `test_layering_property.py` adds one; if the measured count after the run differs, the measured count wins); says in "IAM policy generation" that the generator walks every module in the package rather than `client.py` files, prunes `tests/` and dot-prefixed directories, keys exclusions by package-relative path, and that `ec2:DescribeRegions` and `account:GetAccountInformation` are now in the artefacts; and extends the Deployment section's deploy-roles-first rule with this change as the example of a `core/`-issued call becoming visible to the generator.

   `creating_checks_best_practices.md`: gains the "Organizations data" section (read `self.organization.accounts()`, filter with `is_active_account`, never add an `org_client` or an Organizations accessor to a service base, standard two-arm error branch, `is_not_configured` consults the service table then the provider table) and the same `_has`/`_get`/`_set` amendment as `structure.md` (c); the Account-lists section cross-references the new section; and the known-defect entry at line 545 — "`services/securityincidentresponse/base.py` declares no `NAMESPACE`, and `get_delegated_administrators()`, `get_organization_accounts()` and `get_role()` all pin `self.regions[0]`" — is rewritten to name the two surviving accessors, `get_delegated_administrators()` and `get_role()`, because the third was deleted by !54 and the name fails Property 12.

   `sraverify/README.md` follows the steering in its Architecture, delegating-properties, service-base, client-method, Caching and Tests sections. `product.md` is untouched.
8. **Regenerate `docs/checks.txt` and `cmp`** — expected identical. ASH 3.7.0 per `security_scanning.md`.

**The acceptance gate (Requirement 12), in order:**

- **Scan three trees in one window** — `main` c55893a, !54 986bced, the candidate — with identical arguments, on the management and audit profiles, with `--debug` and stderr kept, for the six consuming services, all twelve Organizations checks and IAM. Reuse the !54 A/B scripts (`.tmp/sratester/org-accounts/`), extended to three inputs and to emit an `order_only` flag per differing cell; join on `(CheckId, Region, ResourceId)`. Admit only the two named differences; expect the Inspector first-page effect to contribute zero rows in the 13-account organization. Any other difference is fixed in code and the affected checks re-scanned on all three trees.
- **Per-scan gates**: 0 synthetic rows, 0 `- ERROR -` records, no `No client available`, `aws_call_failed` count equal to the !54 run's and explainable against `main`'s; and the provider's `Fetching organization accounts` record exactly once per scan with `Using cached organization accounts` on every later read.
- **The negative run**: `SRA-INSPECTOR-07` from a member account that cannot call `ListAccounts`. Every row ERROR with `ActualValue` beginning `ListAccounts failed: AccessDeniedException:`, one per Region, and `aws_call_failed` count equal to the Region count. Record the observed code and message verbatim; it is the evidence any Phase 2 `ListAccounts` entry would cite.
- **IAM simulation**: `simulate-principal-policy` against the deployed `SRAMemberRole` for `ec2:DescribeRegions` (expected implicit deny before the deploy, allow after) and `account:GetAccountInformation` (allow both times, via `SRAVerifyCheckPermissions`); `simulate-custom-policy` on **both** edited-template documents extracted separately — the `SRAVerifyLeastPrivilege` policy (expected: allow `ec2:DescribeRegions`, `account:GetAccountInformation` and `organizations:ListAccounts`, the first two newly) and the `SRAVerifyCheckPermissions` policy (expected: allow `account:GetAccountInformation` as before, implicit deny on the other two, unchanged) — so the record shows which policy grants what and that the generated-mirror policy alone is now sufficient for the three actions.
- **Deploy `1-sraverify-member-roles.yaml` first** — the service-managed StackSet and the separate management-account stack — then the **CodeBuild run** with a `buildspecOverride` whose only change replaces the `git clone -b $GIT_BRANCH …` line with a copy of a tarball of `sraverify/` and `sra-verify-dashboard.html` from the candidate (excluding `.venv`, `build`, `dist`, `*.egg-info`, `__pycache__`, `.hypothesis`), uploaded to the findings bucket and deleted afterwards. Judge from the consolidated CSV: per-account row counts for the fifteen consumers and twelve Organizations checks equal to the previous report's, 0 ERROR rows from those checks, total ERROR delta explained. The visible effect of the role deploy on this run is zero rows, because the buildspec passes `--regions`.
- **Report** to `sratester/organizations-provider-test-report.md`; scratch to `.tmp/sratester/organizations-provider/`. Nothing on the do-not-mutate list is touched; this is a refactor and no mutate-detect-fix-validate cycle runs.

**Version.** Nothing in this design requires a bump: `SRAVerify` and `run_checks` keep their signatures and the MCP server is unaffected (Non-Goal 9). If the owner bumps `__version__` for the new public property, run `uv sync --reinstall-package sraverify` afterwards, because a plain `uv sync` keeps the previous `dist-info`.

### Phase 2 — the rest of the surface

Its own MR, its own design revision against this document, its own A/B against the merged Phase 1, its own report. Named here so nothing is lost (Requirement 13):

- **Grow the provider** to every Organizations operation the package issues: `describe()`, `management_account_id()`, `delegated_administrators(service_principal)`, `roots()`, `ous_for_parent()`, `policies()`, `policies_for_target()`, `describe_policy()`, `effective_policy()`, `accounts_for_parent()`. Three operations — `ListDelegatedAdministrators`, `ListPoliciesForTarget`, `DescribePolicy` — are not on the relocated client today and are added to it then; the client-method count moves and the adapter table with it. Each accessor's cache contract goes in the provider test module's `PROVIDER_ADAPTERS` table, never in the base tables (Requirement 10.6).
- **Retire every `org_client`** binding in the eight service clients; replace `SecurityHubCheck.get_organization()`'s raw call and `IAMCheck.get_organization()` with the provider; make `OrganizationsCheck`'s six accessors delegate to or be replaced by it. Widen Property 8 to every `organizations` operation, keeping its two-set shape: the boto3 spellings (`get_paginator('<op>')` and `.client.<op>(`) permitted in `core/organizations_client.py` only, and the wrapper-method spellings (`.<method>(` for each client method) permitted in `core/organization.py` only.
- **Migrate `ScanContext`'s three raising accessors** — `get_account_info`, `get_management_account_id`, `get_enabled_regions` — to the error-result model (their Region binding already follows the scan Region in Phase 1); decide how a failed `sts:GetCallerIdentity` is reported given `_finding` reads `get_account_info()` for every row.
- **Unify `ListDelegatedAdministrators`** in the provider table with the per-row A/B evidence Requirement 13.4 demands, and decide `ListAccounts` and any further `DescribeOrganization` entries the same way.
- **Regenerate the IAM artefacts** expecting no new action; confirm the `aws_call_failed region=` change on retired paths moves no `Region` cell.
- **Coordinate in-flight first calls per cache key** in the provider before concurrent scanning lands, and **measure the denied-`ListAccounts` fan-out** at full breadth before deciding on any non-retryable marker (Requirement 13.7; Open Questions 13 and 14).
- Carry forward every deferral `structure.md` records (Region relabelling, set ordering, Shield pagination) that Phase 2 does not explicitly close.

## Open Questions

Items the review loop could not settle, and defects found in `requirements.md`. None blocks Phase 1; each names its proposed resolution.

**Status (2026-10-01):** the `requirements.md` wording defects — items 1, 2, 3, 4, 8, 9, 11 and 12 below, plus the regional/global consumer split (twelve regional, three global, not thirteen and two) that `tasks.md` found in Requirement 6.1 and Non-Goal 6 — were applied to `requirements.md` in place, with no criterion added, removed or renumbered, so every `Validates` reference in this document still points where it did. The four design decisions — items 5, 6, 7 and 10 — were accepted by the owner as written. The items are kept below for the record.

1. **Requirement 9.3's action diff is incomplete.** A whole-package walk also attributes `sts:AssumeRole` from `core/session.py`'s `session.client('sts')`. That action belongs to the operator's principal, not the member role, so this design excludes `core/session.py` by name with the reason recorded in `EXCLUDED_MODULES` and a test that the exclusion holds. Requirement 9.3 should list the exclusion so the next reader does not take its absence from the artefacts as a generator defect. `utils/banner.py`'s `sts:GetCallerIdentity` is also newly attributed but already present, so it does not change the artefacts.

2. **(Superseded in revision 5: the `None` case no longer exists; an undetermined scan is refused. Kept for the record.) Requirement 2.3's "pass the derived Region to both" has a `None` case.** `AWSClient.region` is typed `str` and is only a log label. When `scan_region` yields `None`, the boto3 client receives `None` (it must) and the label receives `GLOBAL_REGION`. The requirement could say so explicitly; the design treats it as a clarification, not a deviation.

3. **Requirement 9.5's per-module warning.** "A module that binds nothing is still a warning" would emit roughly two hundred warnings per run over a whole-package walk. The design narrows the warning to modules that declare an `AWSClient` subclass and bind nothing, which is the condition the warning exists to catch. The requirement text should match.

4. **Requirement 11.1's namespace sentence is too strong for Phase 1.** "The `organizations` namespace is written by the provider and read by no base class by key" is false until Phase 2: `OrganizationsCheck`'s six accessors still write `organization`, `roots`, `ous:*`, `policies:*`, `accounts:*` and `effective_policy:*` there. The steering sentence is scoped to the `all_accounts` slot in Phase 1 and widened in Phase 2.

5. **`_remediation_for` names the check's service, not the operation's.** A Security Hub check's ERROR row for a failed `ListAccounts` tells the operator to check the *Security Hub* delegated administrator. Both reference trees say that today and Phase 1 must not change it (Requirement 3.6). Whether Phase 2 should let an ERROR remediation name the operation's service when a provider operation fails is left to the Phase 2 design, which is the first point at which the row text can be A/B'd.

6. **`account:GetAccountInformation` appears twice in the template after Phase 1** — in the hand-written `SRAVerifyCheckPermissions` policy (line 51–54, unchanged) and, newly, in the `SRAVerifyLeastPrivilege` policy's `AccountPermissions` statement (line 79–82), which Migration step 6 edits so the template's generated-mirror policy and `generated_sraverify_cf_policy.yaml` carry the same action set (Requirement 9.4's "updated to match"). The design keeps both because removing the hand-written grant edits a deployed policy for no functional change. The owner may prefer to drop it in a later template-only change.

7. **`_SHADOWED_CONTEXT_NAMES` holds `organization` only.** The seven older context properties have never been guarded against shadowing. Widening the tuple to all eight is correct and is deliberately not done here, because it is a behaviour change on the import path that is not asked for and that could, in principle, fail an import that passes today. Recommended as its own small change after Phase 1.

8. **Requirement 10.4's permitted set is one module short.** It names "the relocated client's" module as the one permitted module for both spellings, but the provider must call the wrapper method `list_accounts`, so `core/organization.py` necessarily contains `.list_accounts(`. A text rule cannot tell that call from a boto3 call. Property 8 therefore permits the paginator spelling in the client module only and the `.list_accounts(` spelling in the provider module only, and proves the provider calls the wrapper (no `get_paginator(`, no `.client.` receiver). Requirement 10.4 should say so; the intent — exactly one module issues the boto3 call — is unchanged.

9. **Requirement 10.1 overstates two harnesses.** It says `test_absent_resource_verdict_property.py` and `test_service_migration_property.py` "drive a Consumer_Check". On the !54 branch neither does: the first drives GuardDuty checks only, the second one canonical base accessor per service. The design still stubs `ctx.organization` in both, defensively, so the requirement's outcome holds; its wording should say "any harness that builds a `MagicMock(spec=ScanContext)`" rather than claim those two reach the provider today.

10. **`failedAccounts` is dropped from the Inspector multi-batch merge.** Revision 1 carried it through the merge; this revision does not, because Requirement 8 does not ask for it and nothing reads it. If a future Inspector check wants the failed members of a batched `BatchGetAccountStatus`, carrying `failedAccounts` through the merge is a two-line change with no reader to regress, and belongs with that check.

11. **Requirement 11.2's module count is wrong.** It says "~26 hypothesis and reflection modules (27 on the branch; …)". `tests/property/` on the !54 branch holds 30 `test_*.py` modules (32 files minus `__init__.py` and `strategies.py`), listed in Migration step 7; Phase 1 makes it 31. The requirement's parenthetical should read 30, and its "whatever Phase 1 makes it" clause is what the design follows.

12. **Requirement 5.2's "read the `organizations` namespace by key" clause is one method too wide for Phase 1.** `SecurityHubCheck.get_organization()` reads and writes `("organizations", "organization")` by key through its own `_ORGANIZATIONS_NAMESPACE` / `_ORGANIZATION_CACHE_KEY` constants (`securityhub/base.py:211–212`, `934–973`), and Requirement 6.5 with Non-Goal 8 requires that method to be left exactly as it is until Phase 2. Both cannot hold at once. The design follows 6.5: Phase 1 removes the primer's foreign read of `all_accounts` — the one the regression came from and the one 5.2's rationale names — and Property 15 is scoped accordingly (cache primitives are forbidden in `sra_*` modules; `base.py` is checked for the client, not for the primitives). Requirement 5.2 should say "read the account list from the `organizations` namespace by key", and Phase 2 widens the prohibition to the whole namespace when `get_organization()` moves behind the provider (Requirement 13.2).

13. **One sweep per scan is a sequential guarantee.** `accounts()` is double-checked, not single-flight: two concurrent first callers each miss and each paginate. That is correct for today's sequential `run_checks` and is now stated as such (Requirements 1.3, 1.10). Proposed resolution: per-key in-flight coordination (a future or event per cache key) in the provider, landing before or with concurrent scanning, Phase 2 (Requirement 13.7).

14. **A denied `ListAccounts` is re-issued per consumer per Region.** Never caching a failure is deliberate and stays; at full breadth it costs on the order of 220 calls in a broad scan. Proposed resolution: measure that path across every consumer and Region before Phase 2 decides whether a narrowly constrained non-retryable marker is justified (Requirement 13.7). Not weakened in Phase 1.

## Responses to the design review

Revision 1 was reviewed against `requirements.md` on the !54 tree (`.tmp/spec-work/design-review.md`): 0 HIGH, 5 MEDIUM, 14 NIT, verdict CHANGES_REQUESTED. Every finding is dispositioned below as **addressed** (the document changed), **backlogged** (recorded as an Open Question or follow-up with the reason) or **declined** (with the reason). Nothing is declined.

| #   | Severity | Finding                                                                                         | Disposition                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| --- | -------- | ----------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | MEDIUM   | Property 8 fails on the provider module, which must contain `.list_accounts(`                   | **Addressed.** Property 8 now has two permitted sets: the paginator spelling in `core/organizations_client.py` only, `.list_accounts(` in `core/organization.py` only, with the provider module proven to call the wrapper (no `get_paginator(`, no `.client.`). Confirmed against the branch that the client module itself never contains `.list_accounts(`, so non-vacuity for that spelling is asserted on the provider. Requirement 10.4's gap is Open Question 8. |
| 2   | MEDIUM   | The accepted `ctx ↔ provider` cycle makes client release gc-dependent                           | **Addressed, recommended fix taken.** The provider holds `weakref.ref(ctx)` behind a `_ctx` property and builds an `OrganizationsClient` per `accounts()` miss instead of memoising one (as !54's mixin did). The "benign race" paragraph is gone. Property 28 now asserts the provider's weakref is dead immediately after `del ctx` with `gc.disable()` in force and no `gc.collect()`. `scanner.py`'s comments and `structure.md`'s sentence stay true unamended.   |
| 3   | MEDIUM   | Property 10's "only mention" clause is false today                                              | **Addressed.** Replaced with AST-only clauses: no `Import`/`ImportFrom` naming `sraverify.services`, no `str` constant equal to or starting with it. Confirmed that no `core/` module carries such a constant and that `discovery.py` needs no exemption (it receives the package name as an argument).                                                                                                                                                                |
| 4   | MEDIUM   | Property 12 fails on itself; `_REPO_ROOT` unnamed; two flagged occurrences not in the edit list | **Addressed.** The asserting module excludes `Path(__file__)` from the walk; `_REPO_ROOT` is `Path(sraverify.__file__).resolve().parent.parent.parent` as in the generator tests; `services/inspector/client.py:9–10` is in step 3 and `creating_checks_best_practices.md:545` in step 7 (rewritten to name `get_delegated_administrators()` and `get_role()`); step 7(d) requires the replacement `structure.md` paragraph not to name the mixin.                     |
| 5   | MEDIUM   | Migration step 6 omitted the `SRAVerifyLeastPrivilege.AccountPermissions` template edit         | **Addressed.** Step 6 now edits both statements of the generated-mirror policy (`Ec2Permissions` and `AccountPermissions`, with line numbers), keeps the hand-written line 51–54 grant, and the gate simulates both template documents separately. Data Models and Open Question 6 say the same thing in the same words.                                                                                                                                               |
| 6   | NIT      | Property-module count wrong (28)                                                                | **Addressed.** 30 on the branch (listed), 31 after Phase 1; step 7 says the measured count wins if it differs.                                                                                                                                                                                                                                                                                                                                                         |
| 7   | NIT      | `stub_organization` / `PROVIDER_ADAPTERS` have no named home                                    | **Addressed.** Both live in `test_organization_provider_property.py` and are imported from there by the three harnesses, the direction `_ADAPTERS` is already imported.                                                                                                                                                                                                                                                                                                |
| 8   | NIT      | Two harnesses described as driving consumer checks do not                                       | **Addressed.** The table row and the harness-stub section say "defensively" and name what each harness actually drives; Requirement 10.1's wording is Open Question 9.                                                                                                                                                                                                                                                                                                 |
| 9   | NIT      | Three stale docstrings not in the edit list                                                     | **Addressed.** `services/iam/client.py:12` and `services/securityhub/base.py:925–928` are corrected in step 3 as docstring-only edits (the Security Hub one records the Phase 1 pin and points to Phase 2); `inspector/client.py:9–10` is the third.                                                                                                                                                                                                                   |
| 10  | NIT      | The call-site snippet's trailing comment would fail Properties 12 and 30                        | **Addressed.** Stated as illustrative and not committed.                                                                                                                                                                                                                                                                                                                                                                                                               |
| 11  | NIT      | The shadow test sketch cannot reach the shadow rule                                             | **Addressed.** Written on the `synthetic_service` fixture (line 193) like `test_a_class_attribute_shadowing_a_metadata_property_raises` (873) and its intermediate-base sibling (899), with a valid `meta`, and the reason given.                                                                                                                                                                                                                                      |
| 12  | NIT      | `EXCLUDED_MODULES` key convention ambiguous; `.venv` walked                                     | **Addressed.** Keys are package-relative POSIX paths (`core/session.py`); `base_dir` is the project root as today; dot-prefixed directories and `*.egg-info` are pruned, so `.venv` is never read — the source of !54's three "unknown" warnings.                                                                                                                                                                                                                      |
| 13  | NIT      | Three `structure.md` amendments implied but unnamed                                             | **Addressed.** Step 7 now enumerates (a)–(k), including the `client.py` qualification in the layout tree and "Adding a new check", the two-table wording in tier 2, the renamed test-module row, and the `securityincidentresponse` "three → two" count.                                                                                                                                                                                                               |
| 14  | NIT      | Property 29 over-generalises the operation label                                                | **Addressed.** `operation=ListAccounts` for a `ClientError`, `operation=Request` for a `BotoCoreError`, matching Property 3.                                                                                                                                                                                                                                                                                                                                           |
| 15  | NIT      | Property 4's last clause not mechanically checkable                                             | **Addressed.** Replaced with `vars(OrganizationsProvider)` public callables `== {"accounts"}` and module-level defined public names `== {"OrganizationsProvider", "NAMESPACE", "ACCOUNTS_KEY"}`, by AST.                                                                                                                                                                                                                                                               |
| 16  | NIT      | `scan_region` brittle against the suite's session stand-ins                                     | **Addressed.** `getattr(ctx.session, "region_name", None)`; the failure-modes row is replaced by the (unreachable) dead-weakref row that the new provider shape introduces.                                                                                                                                                                                                                                                                                            |
| 17  | NIT      | `failedAccounts` merge is beyond Requirement 8                                                  | **Addressed by dropping it.** The merge is unchanged from both reference trees; Property 22 and the 101-ID test lose the clause; recorded as Open Question 10 for a future Inspector check that wants it. The owner was not asked, because the requirement already settles the scope.                                                                                                                                                                                  |
| 18  | NIT      | Small test-plumbing omissions                                                                   | **Addressed.** `tests/unit/core/test_scan_context.py` is marked new; the `_concrete` import is named; the client-contract ID format becomes `f"{path.parent.name}/{path.name}"` and the six hard-coded messages follow.                                                                                                                                                                                                                                                |
| 19  | NIT      | Property 6 should carry both halves of the `None` case                                          | **Addressed.** Property 6 states that `ctx.get_client` receives `None` while `AWSClient.__init__` receives `GLOBAL_REGION`, and that the log field is never `None`.                                                                                                                                                                                                                                                                                                    |

Two review observations that were not findings are also reflected: the `MagicMock(spec=ScanContext)` note on weak-referenceability in the `ScanContext.organization` section, and the explicit statement in Property 8 of why `.list_accounts_for_parent(` in `services/organizations/base.py` does not match the forbidden spelling.

Revision 3 re-verified every file:line reference revision 2 introduced (`services/organizations/client.py` carries only the paginator spelling; `core/` has no `sraverify.services` string constant and `check.py:375` is a comment; `test_generate_iam_policy.py:36`; `inspector/client.py:9–10`; `creating_checks_best_practices.md:545`; `structure.md:486`, `613`, `627`, `657`; `test_check_registration.py:193`, `873`, `899`; the eight `/client.py` sites in `test_client_contract_property.py`; template lines `51–54`, `79–82`, `145–150`; `securityhub/base.py:925–927` and `948`; `iam/client.py:12` and `38`; 30 property modules; `ScanContext` declares no `__slots__`, so it is weak-referenceable). Two items came out of that pass and are new in this revision: Open Question 12, because `SecurityHubCheck.get_organization()` reads the `organizations` namespace by key in Phase 1 and Requirement 5.2's wording does not allow for it while Requirement 6.5 requires it; and the clause in Property 28's test that `accounts()` is called directly on `ctx.organization`, since a check instance built over the context would hold a second strong reference and the refcount-only `del` would not release it.
