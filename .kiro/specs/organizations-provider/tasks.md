# Implementation Plan: Organizations Provider

## Overview

Two phases, each its own MR, with an explicit gate between them. Phase 1 replaces GitLab MR !54 (`refactor/shared-org-accounts-accessor`, 986bced on main c55893a) with the provider the approved design describes, and must be **verdict-stable** against both reference trees. Phase 2 moves the rest of the Organizations surface behind the same seam and may move verdicts, each with A/B evidence. Implementation language is Python 3.11; stack as locked in `design.md` (boto3/botocore ≥ 1.43.96, `pytest` + `hypothesis`, `ast` + `pyyaml` + botocore's bundled service list for the generator). No new dependency, no new lock entry, no new top-level package.

Paths use the repository's tripled directory name. The repo root is `sra-verify/` (the directory holding `1-sraverify-member-roles.yaml`, `util/`, `docs/`, `.kiro/`); the pip project root is `sra-verify/sraverify/` (holds `pyproject.toml` and `.venv`); the package is `sra-verify/sraverify/sraverify/`. Below, a package-relative path such as `core/organization.py` means `sraverify/sraverify/core/organization.py` from the repo root, and `tests/...` means `sraverify/sraverify/tests/...`. Line numbers are the !54 branch at 986bced unless marked `main`.

### Phase 1 is one MR, and it must not move a verdict

Phase 1 **branches from 986bced, not from `main`**. The !54 branch already carries the fifteen call-site edits in a one-token-from-final form, the six base-class de-duplications, the 24 tests this plan adapts, the test-table deletions, and the A/B scripts under `.tmp/sratester/org-accounts/`. Starting there makes the Phase 1 diff against !54 the provider itself and nothing !54 already did. The !54 developer's A/B report is `sratester/org-accounts-refactor-test-report.md`; the strategic review and probes are under `.tmp/review/`.

The only admitted differences against the reference trees are (a) order-only cells built from a `set` in `sra_inspector_07`, `sra_securityhub_08` and `sra_macie_07`, which already vary between two runs of `main`, and (b) against `main` only, the Inspector first-page effect in an organization of more than 20 accounts, which the 13-account test organization cannot exercise and which therefore contributes **zero** rows to the gate. Anything else is fixed in code and re-scanned on all three trees.

### Order matters in three places

- **Tasks 2–6 land before anything under `services/` changes**, and the suite is green after task 7 with the provider table empty, so a later failure is attributable to the relocation and not to the provider.
- **Three test modules fail between task 8 and task 12, and each is expected.** (1) The client-contract harness, from 8.2 until 12.4: deleting `services/organizations/client.py` removes the module it enumerates by path, and the remap in 12.4 restores it from `core/organizations_client.py`. (2) `tests/property/test_organization_accounts_property.py`, from 8.2 until 12.1: it fails at **collection**, because its lines 38–42 import `ORGANIZATION_ACCOUNTS_KEY`, `ORGANIZATION_ACCOUNTS_NAMESPACE` and `OrganizationAccountsMixin` from the deleted module; 12.1 renames and adapts it. (3) `tests/property/test_check_classification_property.py` on the fifteen consumer checks, from 8.3 until 9.1 + 12.2: `_accessor_names` adds `get_organization_accounts` only `if hasattr(_base_class(service), name)` (line 121), which is `False` once the mixin is gone, so between 8.3 and 9.1 `execute()` raises `AttributeError` on `self.get_organization_accounts()`, and between 9.1 and 12.2 it reads an auto-specced `ctx.organization` `MagicMock` — the "empty success" that property exists to rule out; 9.1 moves the call sites and 12.2 deletes `_SHARED_ACCESSORS` and stubs `ctx.organization`. Do not "fix" any of the three failures any other way; the suite is green again at 12.10.
- **The member-role template deploys before the CodeBuild run (task 17 before task 18)**, per `tech.md`'s deploy-roles-first rule. Expect zero visible rows from the deploy, because the buildspec passes `--regions` and never reaches `ec2:DescribeRegions`.

### Test scope resolved

No test task is optional. The property suite is how the next provider accessor gets tested the day it is written (Requirement 10), and `PROVIDER_ADAPTERS` is the single table the catalog harness stubs from, so an unlisted accessor fails one named test rather than running unpatched.

### Conventions used below

- Every command runs from the repo root unless it starts with `cd`. The suite is `cd sraverify && uv run pytest -q -p no:logging`. The console script is `sraverify/.venv/bin/sraverify`.
- If the shell runs under Rosetta, wrap git in `arch -arm64 /bin/zsh -lc '<cmd>'`. Redirect long output to files under `.tmp/sratester/organizations-provider/` and read them back; `.tmp/` and `sratester/` are gitignored.
- Account IDs and profile names live only in `sratester/accounts.md` (gitignored). Resolve IDs at run time with `aws sts get-caller-identity --profile <profile> --query Account --output text`. Never write either into a tracked file, including this one.
- Do not commit. When Phase 1 is complete, hand the owner a one-line commit message and the MR description (task 20); the owner reviews and commits.
- "Property N" refers to the numbered Correctness Properties in `design.md`; "Requirement X.Y" to `requirements.md`.

---

## Tasks

## Phase 1 — replaces MR !54

- [x] 1. Branch, baseline, and reference trees
  - [x] 1.1 Create the Phase 1 branch from the !54 commit: `git checkout -b feature/organizations-provider 986bced` (branch name is the implementer's choice; the MR description will say it supersedes !54). Confirm `git status --short` is clean apart from the untracked `.kiro/specs/organizations-provider/` directory
    - _Requirements: 1.1, 6.1_

  - [x] 1.2 Baseline the suite before the first edit: `cd sraverify && uv run pytest -q -p no:logging 2>&1 | tail -3 > ../.tmp/sratester/organizations-provider/baseline-pytest.txt`. Expected on 986bced: **8865 passed, 597 skipped**, 9462 collected, no xfail. Record it; every later count is measured against this
    - _Requirements: 10.8_

  - [x] 1.3 Create the two reference worktrees the live A/B needs, outside the tracked tree: `git worktree add .tmp/sratester/organizations-provider/main-wt c55893a` and `git worktree add .tmp/sratester/organizations-provider/mr54-wt 986bced`. Both are read-only inputs; nothing is edited in them. (`git worktree list` also shows an unrelated earlier worktree at 618d277 at the **workspace** root, `/Users/schiefj/code/wwps-security-developer/sraverify/.tmp/premigration` — `../.tmp/premigration` relative to this repo, not the repo's own `.tmp/`; leave it)
    - _Requirements: 12.1_

  - [x] 1.4 Confirm the generator's starting state: `cd sraverify && uv run python ../util/generate_iam_policy.py --base-dir . --out-json ../.tmp/sratester/organizations-provider/pre-policy.json --out-yaml ../.tmp/sratester/organizations-provider/pre-policy.yaml --quiet`, then `cmp ../.tmp/sratester/organizations-provider/pre-policy.json ../generated_sraverify_iam_policy.json` and the same for the YAML. Expected: byte-identical (the !54 report says so). Keep the stderr: the three "unknown" warnings it emits come from `client.py` files under `.venv`, which task 13.1 stops walking
    - _Requirements: 9.3_

- [x] 2. `core/organizations_client.py` — the relocated, partition-aware client
  - [x] 2.1 Create `core/organizations_client.py` from `services/organizations/client.py` (copy the file, then edit; the seven methods `describe_organization`, `list_roots`, `list_organizational_units_for_parent`, `list_policies`, `list_accounts`, `describe_effective_policy`, `list_accounts_for_parent` are **byte-identical** to the source — every paginator loop inside its `try`, every handler exactly `except AWS_EXCEPTIONS as e: return self.aws_error(e)`). Change only the module docstring, the imports and the constructor:

    ```python
    from __future__ import annotations

    from typing import TYPE_CHECKING, Any, Mapping, Optional

    from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
    from sraverify.core.finding import GLOBAL_REGION

    if TYPE_CHECKING:
        from sraverify.core.scan_context import ScanContext


    def scan_region(ctx: ScanContext) -> Optional[str]:
        """First explicit --regions value, else the session's Region, else None.
        Reads ctx.regions (the explicit list or []), never ctx.get_enabled_regions()."""
        regions = ctx.regions
        if regions:
            return regions[0]
        return getattr(ctx.session, "region_name", None)


    class OrganizationsClient(AWSClient):
        def __init__(self, ctx: ScanContext) -> None:
            region = scan_region(ctx)
            super().__init__(region if region is not None else GLOBAL_REGION, ctx)
            self.client = ctx.get_client("organizations", region=region)
    ```

    The module docstring says Organizations is partition-global (one endpoint per partition) and that the Region is derived from the scan rather than pinned to `us-east-1`, which is correct only in the `aws` partition. `scan_region` is module-level so `services/iam/client.py` can use it in task 8.4. No `ctx.get_enabled_regions()` anywhere in the module
    - _Requirements: 2.1, 2.2, 2.3, 2.6, 2.7_

  - [x] 2.2 In `core/aws_client.py`, move `from sraverify.core.scan_context import ScanContext` (line 56) under `if TYPE_CHECKING:` (the module already has `from __future__ import annotations`, line 47, and uses `ScanContext` only in the `__init__` annotation). This breaks the run-time edge `aws_client → scan_context` so that `scan_context → organization → organizations_client → aws_client` is acyclic at import. Run `cd sraverify && uv run python -c "import sraverify.core.aws_client, sraverify.core.organizations_client"` to confirm both import cleanly
    - _Requirements: 4.1_

- [x] 3. `core/aws_errors.py` — table precedence
  - [x] 3.1 Add two functions beside the existing `is_not_configured(table, error)` and make it delegate, so its existing callers and tests are unchanged:

    ```python
    def declared_fact(table: NotConfiguredTable, error: Mapping[str, str]) -> NotConfigured | None:
        by_code = table.get(error.get("Operation", ""))
        return by_code.get(error.get("Code", "")) if by_code else None


    def is_not_configured_in(tables: Sequence[NotConfiguredTable], error: Mapping[str, str]) -> bool:
        """First table to *declare* (Operation, Code) decides, message needle included."""
        for table in tables:
            fact = declared_fact(table, error)
            if fact is not None:
                if fact.message is None:
                    return True
                return fact.message.lower() in error.get("Message", "").lower()
        return False


    def is_not_configured(table: NotConfiguredTable, error: Mapping[str, str]) -> bool:
        return is_not_configured_in((table,), error)
    ```

    Precedence is "first table to declare the pair", not "first table to answer True": a service table that declares a pair with a needle that does not match has classified the pair as *not* semantic, and a later table must not overrule it (Requirement 3.2's last clause). Add `Sequence` to the `typing` import
    - _Requirements: 3.2, 3.4_

- [x] 4. `core/organization.py` — `OrganizationsProvider`
  - [x] 4.1 Create `core/organization.py`. Module-level public names are exactly `OrganizationsProvider`, `NAMESPACE = "organizations"` and `ACCOUNTS_KEY = "all_accounts"` (Property 4 asserts the set by AST). The class holds the context **weakly** and builds its client **per call**:

    ```python
    from __future__ import annotations

    import weakref
    from typing import TYPE_CHECKING, Any, ClassVar, Mapping

    from sraverify.core.aws_errors import NotConfiguredTable, is_error
    from sraverify.core.logging import logger
    from sraverify.core.organizations_client import OrganizationsClient

    if TYPE_CHECKING:
        from sraverify.core.scan_context import ScanContext

    NAMESPACE: str = "organizations"
    ACCOUNTS_KEY: str = "all_accounts"


    class OrganizationsProvider:
        NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {}   # empty in Phase 1 on purpose

        def __init__(self, ctx: ScanContext) -> None:
            self._ctx_ref: weakref.ReferenceType[ScanContext] = weakref.ref(ctx)

        @property
        def _ctx(self) -> ScanContext:
            ctx = self._ctx_ref()
            if ctx is None:
                raise RuntimeError("OrganizationsProvider outlived its ScanContext")
            return ctx

        def accounts(self) -> Mapping[str, Any]:
            ctx = self._ctx
            if ctx._has(NAMESPACE, ACCOUNTS_KEY):
                logger.debug("Organizations: Using cached organization accounts")
                return ctx._get(NAMESPACE, ACCOUNTS_KEY)
            logger.debug("Organizations: Fetching organization accounts")
            response = OrganizationsClient(ctx).list_accounts()
            if is_error(response):
                return response          # never cached; the next caller re-issues
            ctx._set(NAMESPACE, ACCOUNTS_KEY, response)
            logger.debug(f"Organizations: Cached {len(response.get('Accounts', []))} organization accounts")
            return response
    ```

    The module docstring records the four embedded decisions from `design.md` ("`core/organization.py`"): weakref so `ctx → provider → ctx` is not a cycle and `del ctx` frees everything by refcount; wrapper per call because memoising it would store `wrapper.ctx` on the provider; **no no-client path**, because `ScanContext.get_client` always constructs and the client binds in `__init__`, so the `no_client_result(service="Organizations", region="global")` branch `OrganizationsCheck.get_accounts` carried on `main` was dead code; no `active_account_ids()` helper in Phase 1. The table's comment says it is empty because no service declares `ListAccounts` and `AWSOrganizationsNotInUseException` from it stays ERROR until Phase 2 produces A/B evidence. No second lock. No `print`, no handler, no `warnings.warn`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.10, 3.1, 3.3, 3.4, 4.1, 10.7_

- [x] 5. `core/scan_context.py` — the `organization` property
  - [x] 5.1 Add `from sraverify.core.organization import OrganizationsProvider` at module top. As the **last** statement of `ScanContext.__init__` (after `self._lock` is assigned), add `self._organization: OrganizationsProvider = OrganizationsProvider(self)` with a comment that constructing it issues no AWS call and binds no boto3 client. Add a read-only property:

    ```python
    @property
    def organization(self) -> OrganizationsProvider:
        """The Organizations provider for this scan. Read-only; no setter."""
        return self._organization
    ```

    Nothing else in the module changes in Phase 1: `get_account_info`, `get_management_account_id` and `get_enabled_regions` keep their `raise` and their `us-east-1` pin (line 519) until Phase 2. Confirm `cd sraverify && uv run python -c "import sraverify.core.scan_context"` succeeds — an `ImportError` here means the `TYPE_CHECKING` move in 2.2 was incomplete
    - _Requirements: 1.1, 1.6, 1.9, 1.10_

- [x] 6. `core/check.py` — `organization`, the shadow rule, the two-table discriminator
  - [x] 6.1 Add `from sraverify.core.organization import OrganizationsProvider` and the eighth context-delegating property on `SecurityCheck`, beside the other seven:

    ```python
    @property
    def organization(self) -> OrganizationsProvider:
        return self._require_ctx("organization").organization
    ```

    A read before `initialize(ctx)` raises `RuntimeError` naming `<CHECK-ID>.organization`; assignment raises `AttributeError` because there is no setter
    - _Requirements: 5.1_

  - [x] 6.2 Add `_SHADOWED_CONTEXT_NAMES: Final = ("organization",)` next to `_SHADOWED_META_NAMES`, and extend the existing `__init_subclass__` MRO walk (every class from `cls` down to but excluding `SecurityCheck`) to raise `CheckIdentityError` when any of those names is in `vars(klass)`, with a message that names the class and the attribute and says "context property" rather than "metadata field". The tuple holds `organization` only; widening it to the seven older names is a separate change (design Open Question 7). `_SERVICE_ONLY_NAMES` is unchanged
    - _Requirements: 5.3_

  - [x] 6.3 Change `is_not_configured` to consult both tables through the class, in this order and always both:

    ```python
    def is_not_configured(self, error: Mapping[str, str]) -> bool:
        return is_not_configured_in(
            (type(self).NOT_CONFIGURED_ERRORS, OrganizationsProvider.NOT_CONFIGURED_ERRORS), error
        )
    ```

    Import `is_not_configured_in` from `core/aws_errors.py`. Reading through `type(self)` and the class, never an instance, keeps classification a class-level fact that does not depend on `initialize(ctx)`
    - _Requirements: 3.2, 3.4, 3.7_

- [x] 7. Checkpoint — the provider exists and nothing has moved
  - Run `cd sraverify && uv run pytest -q -p no:logging`. Expected: green at the 1.2 counts (8865 passed, 597 skipped). The provider table is empty, so no verdict can have moved, and nothing imports the new modules yet except `scan_context.py` and `check.py`
  - Run `sraverify/.venv/bin/sraverify --list-checks > .tmp/sratester/organizations-provider/list-checks-7.txt && cmp .tmp/sratester/organizations-provider/list-checks-7.txt docs/checks.txt` — identical, and stderr empty
  - `git diff --stat -- sraverify/sraverify/services/` touches nothing
  - _Requirements: 10.8, 10.9_

- [x] 8. Relocate the client and delete the mixin
  - [x] 8.1 `services/organizations/base.py`: replace `from sraverify.services.organizations.client import OrganizationsClient` (line 25) with `from sraverify.core.organizations_client import OrganizationsClient`; delete `from sraverify.services.organizations.accounts import OrganizationAccountsMixin` (line 24); change `class OrganizationsCheck(OrganizationAccountsMixin, SecurityCheck):` (line 28) to `class OrganizationsCheck(SecurityCheck):`. `_setup_clients` keeps `self._org_client = OrganizationsClient(ctx=self._ctx)` and `self._clients.clear()`; its comment and the module and class docstrings stop saying "pinned to `us-east-1`" and say partition-global with the Region derived from the scan. `get_accounts` is **not** reintroduced; the six other accessors and `guardrail_identifiers_of` are untouched
    - _Requirements: 2.6, 4.3, 6.3_

  - [x] 8.2 `git rm sraverify/sraverify/services/organizations/client.py sraverify/sraverify/services/organizations/accounts.py`. No re-export shim: a `client.py` left under `services/organizations/` would be a second import path for one class and a second module for the harness and the generator to walk
    - _Requirements: 4.3, 4.4_

  - [x] 8.3 Drop the mixin from the other five bases — in each, delete the `from sraverify.services.organizations.accounts import ...` statement and remove `OrganizationAccountsMixin, ` from the class bases: `services/inspector/base.py` (lines 32, 35), `services/macie/base.py` (28, 54), `services/securityhub/base.py` (31, 56), `services/securityincidentresponse/base.py` (29, 49), `services/securitylake/base.py` (the multi-line import at 38–41 and the class at 57; keep any other name that import brought in only if something still uses it — after task 10 nothing does, so the whole statement goes). In `services/inspector/base.py` `_setup_clients` docstring (lines 70–71), delete the sentence saying each wrapper obtains an `organizations` client; `InspectorClient` no longer binds one
    - _Requirements: 4.4, 4.5, 6.3_

  - [x] 8.4 `services/iam/client.py`: add `from sraverify.core.organizations_client import scan_region`; change line 38 from `self.org_client = ctx.get_client('organizations', region='us-east-1')` to `self.org_client = ctx.get_client('organizations', region=scan_region(ctx))` — the first argument stays the literal `'organizations'`, which the generator attributes on. Line 12 of the module docstring ("is pinned to `us-east-1` like `OrganizationsClient`") becomes "derives its Region from the scan through `scan_region`, like `OrganizationsClient`". `IAM_Client`'s own `super().__init__("us-east-1", ctx)` (line 34) is an IAM Region label, not an Organizations binding, and is untouched. After this task the only remaining `us-east-1` pins on Organizations or Organizations-adjacent calls are `services/securityhub/base.py:948` and `core/scan_context.py:519`, both Phase 2
    - _Requirements: 2.5_

  - [x] 8.5 `services/inspector/client.py` module docstring (lines 9–10): "reads them through the shared, paginated `OrganizationAccountsMixin.get_organization_accounts`" becomes "reads them through `self.organization.accounts()`". The old wording names the mixin and would fail Property 12
    - _Requirements: 4.4_

  - [x] 8.6 `services/securityhub/base.py` `get_organization()` docstring (lines 925–928): replace "pinned to `us-east-1` to match `OrganizationsClient` and populate the shared slot with a value from the same boto3 instance" with "still pinned to `us-east-1` in Phase 1; `OrganizationsClient` now derives its Region from the scan, so in a non-`aws` partition this binding and the relocated client no longer share a boto3 instance — retired in Phase 2 (Requirement 13.2)". The method body (the raw call at line 948, `_ORGANIZATIONS_NAMESPACE` / `_ORGANIZATION_CACHE_KEY` at 211–212) is **untouched**
    - _Requirements: 6.5_

  - From here until task 12 three test modules fail, and each is expected (see "Order matters in three places"): the client-contract harness on `organizations` (it imports `sraverify.services.organizations.client`; cleared by 12.4); `test_organization_accounts_property.py`, which fails at collection on its imports from the deleted `services/organizations/accounts.py` (cleared by 12.1); and `test_check_classification_property.py` on the fifteen consumer checks, whose `execute()` raises `AttributeError` on `self.get_organization_accounts()` until 9.1 and then reads an auto-specced `ctx.organization` until 12.2 (cleared by 9.1 + 12.2). The rest of the suite should still pass; do not "fix" any of the three any other way, and expect green again at 12.10. Confirm `grep -rn "OrganizationAccountsMixin\|organizations.accounts import\|organizations.client import" sraverify/sraverify/services/` returns nothing

- [x] 9. The fifteen call sites — one token each
  - [x] 9.1 In each of the fifteen consumer modules replace the single occurrence of `self.get_organization_accounts()` with `self.organization.accounts()` and change nothing else: `services/inspector/checks/sra_inspector_07.py`, `services/macie/checks/sra_macie_07.py`, `services/organizations/checks/sra_organizations_12.py`, `services/securityhub/checks/sra_securityhub_08.py`, `services/securityhub/checks/sra_securityhub_17.py`, `services/securityincidentresponse/checks/sra_securityincidentresponse_04.py`, `services/securitylake/checks/sra_securitylake_01.py`, and `services/securitylake/checks/sra_securitylake_06.py` through `sra_securitylake_13.py`. The call stays where it is — inside the Region loop in the twelve regional consumers (`inspector_07`, `macie_07`, `securityhub_08`, `securitylake_01`, `securitylake_06`–`_13`), above it in the three global ones (`organizations_12`, `securityhub_17`, `securityincidentresponse_04`); every `continue`/`return`, every `"Error" in` test, every `is_not_configured` arm and every filter stays. No docstring, no `check_logic`, no `CheckMeta` text changes. Do not leave a `# was self.get_organization_accounts()` comment: the name failing Properties 12 and 30 is the point
    - Verify: `grep -rc "self.organization.accounts()" sraverify/sraverify/services/*/checks/ | grep -v ":0$"` lists exactly those fifteen files with count 1, and `grep -rn "get_organization_accounts" sraverify/sraverify/services/*/checks/` returns nothing
    - _Requirements: 6.1, 6.2, 6.6_

- [x] 10. The Security Lake primer reads the provider
  - [x] 10.1 In `services/securitylake/base.py` `_prime_region_log_sources` (from line 441): delete the three-line comment at 474–476 ("Read the shared slot, not re-issue the sweep: every caller has already called get_organization_accounts() and guarded its error result …") and the `org_accounts = (self._ctx._get(ORGANIZATION_ACCOUNTS_NAMESPACE, ORGANIZATION_ACCOUNTS_KEY) or {})` read at 477–480. Replace with a guarded provider call, placed after the existing `get_log_sources` error guard:

    ```python
    org_accounts = self.organization.accounts()
    if is_error(org_accounts):
        logger.debug(
            f"SecurityLake: could not list organization accounts to prime "
            f"{region}; seeding nothing ({org_accounts['Error']['Code']})"
        )
        return
    ```

    The `account_ids` list comprehension, the `if self.account_id and self.account_id not in account_ids: account_ids.append(self.account_id)` line (kept — it runs only after a *successful* read), the per-account bucketing and the `_set` loop are unchanged. On the guarded path (every one of the eight log-source checks has already called and guarded `accounts()` at the top of its Region loop) this is a `_has` hit and issues nothing. On the unguarded path an error result seeds **nothing** — not `[]` per account, not the scanned account alone. Import `is_error` from `core/aws_errors.py` if the module does not already
    - _Requirements: 7.1, 7.2, 7.3, 7.5_

- [x] 11. Inspector: the cap constant and the docstring, nothing else
  - [x] 11.1 In `services/inspector/base.py` add two module-level constants above the class with the comment that `BatchGetAccountStatus` accepts up to 100 IDs per request and that 10 is kept because it is what both reference trees issue and changing it would move the per-scan `aws_call_failed` count the gate compares: `BATCH_GET_ACCOUNT_STATUS_CAP: Final = 100` and `BATCH_GET_ACCOUNT_STATUS_BATCH: Final = 10`. Change line 284 from `range(0, len(account_ids), 10)` to `range(0, len(account_ids), BATCH_GET_ACCOUNT_STATUS_BATCH)` and the slice to match; change the docstring at 254 ("accepts at most 10 accounts") to state the 100 cap and the chosen batch of 10. The multi-batch merge (`accounts` only) and the failing-batch behaviour (error result returned, nothing cached) are unchanged; `failedAccounts` is **not** carried through (design Open Question 10)
    - _Requirements: 8.1, 8.3, 8.4, 8.5_

- [x] 12. Tests — adapt the 24, add the rest
  - [x] 12.1 `git mv sraverify/sraverify/tests/property/test_organization_accounts_property.py sraverify/sraverify/tests/property/test_organization_provider_property.py` and adapt it per the design's disposition table. Imports: `OrganizationsProvider`, `NAMESPACE`, `ACCOUNTS_KEY` from `sraverify.core.organization` replace the three mixin imports (lines 38–43); keep the six base imports, `_Session`, `_arm_pages`, `_arm_failure`, `_sweeps`, `_scan`, `_check`, `_concrete`. Module docstring: the provider replaced **three** regional copies (Macie, Security Hub, Security Lake), one uncached copy and one first-page copy; it must not name the mixin. Then:
    - **Delete** `test_every_base_reads_accounts_through_the_mixin` (×6) — replaced by Properties 11 and 15 in 12.8
    - **Delete** `test_only_the_organizations_client_issues_list_accounts` here — rewritten as Property 8 in 12.8
    - **Keep** `test_every_page_is_merged` (×6) driving `_check(base, ctx).organization.accounts()` (Property 2); `test_one_sweep_serves_every_service_and_region_in_the_scan`, adding the assertion that no `(organizations, <region>)` mock for a Region other than the derived one was called (Property 1); `test_the_slot_is_the_one_organizations_checks_use` as "a value cached through one base is what another base's check reads", asserting `ctx._get(NAMESPACE, ACCOUNTS_KEY) is results[0]` and `NAMESPACE == OrganizationsCheck.NAMESPACE` (Property 1); `test_a_failure_is_returned_unchanged_and_not_cached` (×6) and `test_a_failure_is_re_issued_and_a_later_success_is_cached` (Property 3, both `ClientError` → `Operation == "ListAccounts"` and `BotoCoreError` → `Operation == "Request"`); `test_security_lake_primes_log_sources_for_every_member_account` with `ctx._account_info = {...}` replaced by a `get_account_info` stub (Property 20); `test_reading_before_initialize_names_the_accessor` reading `.organization` and matching `"organization"` (Property 13)
    - **Add** the primer complement (Property 21): arm the sweep to fail and `ListLogSources` to succeed, call `check._prime_region_log_sources("us-east-1")` directly, assert no `list_log_sources:*:us-east-1` key exists in the `securitylake` namespace, the method returned `None`, and one `debug` record names the code
    - **Add** guarded-primer-issues-no-sweep (Property 19): `accounts()` then `check_log_source_configured("us-east-1", "ROUTE53", <member>, "2.0")`; `_sweeps(org) == 1`; one `list_log_sources:<account>:us-east-1` slot per organization account
    - **Add** identity (Property 4): `accounts() is org_response`; `{n for n, o in vars(OrganizationsProvider).items() if not n.startswith("_") and inspect.isfunction(o)} == {"accounts"}`; module-level public names of `core/organization.py` by AST `== {"OrganizationsProvider", "NAMESPACE", "ACCOUNTS_KEY"}`. (Property 5, construction is silent, is **not** added here; it lives in `tests/unit/core/test_scan_context.py`, task 12.7)
    - **Add** log shape (Property 29): one `Fetching organization accounts`, one `Cached <N> organization accounts`, n `Using cached organization accounts`, zero `aws_call_failed` on success; on failure exactly one `aws_call_failed` with `funcName == "aws_error"`, `operation=ListAccounts` for a `ClientError` and `operation=Request` for a `BotoCoreError`
    - **Add** collectible deterministically (Property 28): `ctx = ScanContext(session=_Session(...), regions=["us-east-1"])`; call `ctx.organization.accounts()` **directly on the context** (not through a `_check` instance, whose `_ctx` would be a second strong reference); `ref = weakref.ref(ctx.organization)`; `assert ctx.organization._ctx_ref() is ctx`; then inside `gc.disable()` / `gc.enable()` with **no** `gc.collect()`: `del ctx; assert ref() is None`
    - **Add** the adapter table and the shared stub, exported for the three harnesses:

      ```python
      @dataclass(frozen=True)
      class ProviderAdapter:
          method: str
          operation: str
          args: tuple = ()

      PROVIDER_ADAPTERS: tuple[ProviderAdapter, ...] = (ProviderAdapter("accounts", "ListAccounts"),)

      def test_the_provider_adapter_table_is_complete_and_exact() -> None:
          public = {n for n, o in vars(OrganizationsProvider).items()
                    if not n.startswith("_") and inspect.isfunction(o)}
          assert public == {a.method for a in PROVIDER_ADAPTERS}

      def stub_organization(ctx: MagicMock, *, returns: Any = None,
                            record: list[str] | None = None) -> MagicMock:
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

      (Property 26)
    - _Requirements: 1.2, 1.3, 1.4, 1.6, 1.7, 1.8, 1.9, 5.1, 7.3, 7.4, 10.3, 10.6_

  - [x] 12.2 `tests/property/test_check_classification_property.py`: delete `_SHARED_ACCESSORS` (line 67 and its comment at 63–66), the inherited-name branch of `_accessor_names` (lines ~116–122, the `hasattr(_base_class(service), name)` comprehension), the second half of the `_OPERATION_OF_ACCESSOR` union (lines ~422–427), and the `_base_class` import if nothing else in the module uses it. Import `PROVIDER_ADAPTERS` and `stub_organization` from `sraverify.tests.property.test_organization_provider_property` (the direction `_ADAPTERS` is already imported from `test_accessor_cache_property`). `_make_context()` calls `stub_organization(ctx)`; `_prepare(cls, returns=..., record=...)` calls `stub_organization(ctx, returns=returns, record=record)` so the semantic-pair drive reaches the provider accessor with the same `returns` the service accessors get. Add `_PROVIDER_OPERATIONS = {f"organization.{a.method}": a.operation for a in PROVIDER_ADAPTERS}` and `def _operation_of(service, name): return _PROVIDER_OPERATIONS.get(name) or _OPERATION_OF_ACCESSOR.get((service, name))`, used wherever the union was. The existing Property 14 ("every check yields only ERROR when every accessor fails") now runs with the stub in place and is Property 18: every row from a consumer has `Status.ERROR`, `ActualValue` matching `^ListAccounts failed: TestDenied: ` where it came from that result, non-blank `Remediation`, no PASS or FAIL
    - _Requirements: 3.6, 10.1, 10.6_

  - [x] 12.3 `tests/property/test_absent_resource_verdict_property.py` and `tests/property/test_service_migration_property.py`: wherever each builds a `MagicMock(spec=ScanContext)`, call `stub_organization(ctx)` immediately after. Neither reaches `ctx.organization` today (the first drives GuardDuty checks only, the second one canonical base accessor per service), so no outcome changes; the stub is there so a case added later cannot run against an auto-specced `organization` that returns a truthy, iterable, non-error `MagicMock`. The two `_organization_accounts_cache` strings in the migration module's attribute lists (lines ~530, ~634) are historical cache-attribute names asserted absent and stay as they are
    - _Requirements: 10.1_

  - [x] 12.4 `tests/property/test_client_contract_property.py`: replace the by-path enumeration with a `_CLIENT_MODULES: dict[str, str]` map built as `{svc: f"sraverify.services.{svc}.client" for svc in _service_names() if (services_dir / svc / "client.py").exists()} | {"organizations": "sraverify.core.organizations_client"}`; `_client_classes(key)` (line ~107) imports `_CLIENT_MODULES[key]`; `_client_module_paths()` derives from the imported modules' `__file__` so the AST rules scan `core/organizations_client.py`. Change the parametrize ID format at the two sites (lines ~1790, ~1808) from `f"{path.parent.name}/client.py"` to `f"{path.parent.name}/{path.name}"` and the six failure messages that hard-code `/client.py` (lines ~1863, 1918, 1957, 1996, 2053, 2078) to interpolate `path.name`. The `_ORGANIZATIONS` adapter table is unchanged in content (seven methods). In `_build_wrapper`, set `ctx.regions = [_TEST_REGION]` and `ctx.session.region_name = _TEST_REGION` so `scan_region` is deterministic over the mock. `test_the_adapter_table_is_complete_and_exact` must hold for the relocated class, enumerated exactly once (Property 9)
    - _Requirements: 2.1, 4.3, 6.4, 10.2_

  - [x] 12.5 `tests/property/test_discriminator_property.py`: the table enumeration gains `OrganizationsProvider.NOT_CONFIGURED_ERRORS` alongside the eighteen service tables (shape, non-blank evidence, no placeholder, conservative on undeclared pairs — Property 17; in Phase 1 the table is `{}` and declares nothing for `ListAccounts`). Add the precedence test (Property 16) using `patch.object(OrganizationsProvider, "NOT_CONFIGURED_ERRORS", {...})` with a **synthetic** entry for the test's duration: service table declares the pair (with and without a needle) → service verdict wins whatever the provider says; only the provider declares → provider verdict; neither → `False`. Nothing synthetic is committed to the real table
    - _Requirements: 3.1, 3.2, 3.3, 3.4_

  - [x] 12.6 `tests/unit/core/test_check_registration.py`: add two cases on the `synthetic_service` fixture (line ~193), written exactly like `test_a_class_attribute_shadowing_a_metadata_property_raises` (line ~873) and its intermediate-base sibling (line ~899): a well-formed `sra_guardduty_01.py` source with a **valid `meta`** plus `organization = None` in the class body raises `CheckIdentityError` naming the class and `organization`, leaving the registry unchanged; and the same attribute on an intermediate base declared in `base.py`. The valid `meta` is required because identity rule 2 runs before the shadow rule (Property 14)
    - _Requirements: 5.3_

  - [x] 12.7 **New** `tests/unit/core/test_scan_context.py` (does not exist today): Property 5 (constructing a `ScanContext` over a mock session calls `session.client` zero times; `ctx.organization` is an `OrganizationsProvider`); the four Region-derivation cases of Property 6 — `regions=["us-gov-west-1"]` → `get_client("organizations", region="us-gov-west-1")`; `regions=["eu-west-1"]` → `"eu-west-1"`; no explicit Regions over a session with `region_name="us-gov-west-1"` → that; no explicit Regions and `region_name=None` **and** a session stand-in with no `region_name` attribute → `None`, with `AWSClient.__init__` receiving `GLOBAL_REGION` in that case and the string otherwise, and `ctx.get_enabled_regions` never called; and Property 7 — constructing `IAM_Client(ctx)` requests `ctx.get_client("organizations", region=scan_region(ctx))`, plus a source assertion that `services/iam/client.py` contains no `region='us-east-1'` on an `organizations` binding
    - _Requirements: 2.2, 2.3, 2.4, 2.5, 1.6_

  - [x] 12.8 **New** `tests/property/test_layering_property.py`, with `_REPO_ROOT = Path(sraverify.__file__).resolve().parent.parent.parent` exactly as `tests/unit/util/test_generate_iam_policy.py:36` derives it:
    - Property 10 — AST over every module under `core/`: no `Import` alias and no `ImportFrom.module` equal to or starting with `sraverify.services` (and no relative import resolving into it); no `ast.Constant` `str` equal to or starting with `sraverify.services`. No exemption for `core/discovery.py`
    - Property 11 — for every `<Service>Check` in a `services/<svc>/base.py` (found with `_base_class` from `test_accessor_cache_property`), the MRO strictly between it and `SecurityCheck` (ignoring `ABC` and `object`) is empty
    - Property 12 — for every `.py` under the package directory **including `tests/`**, every `.md` under `_REPO_ROOT / ".kiro" / "steering"`, and the developer guide `_REPO_ROOT / "sraverify" / "README.md"` (a Steering_Doc per the requirements Glossary), excluding `Path(__file__).resolve()` itself, none of `OrganizationAccountsMixin`, `ORGANIZATION_ACCOUNTS_NAMESPACE`, `ORGANIZATION_ACCOUNTS_KEY`, `get_organization_accounts` appears; and `services/organizations/accounts.py` does not exist
    - Property 15 — no `services/*/base.py` other than `services/organizations/base.py` imports `OrganizationsClient` or contains `OrganizationsClient(`; no `sra_*` module contains `ctx.organization`, `_ctx.organization`, `_has(`, `_get(`, `_set(` or `OrganizationsClient`
    - Property 8 — the `get_paginator("list_accounts")` spelling (both quote styles) appears in no module under `core/` or `services/` except `core/organizations_client.py`, where it **does** appear; the `.list_accounts(` spelling appears in no such module except `core/organization.py`, where it appears exactly once and the module contains neither `get_paginator(` nor the receiver text `.client.`
    - Property 30 — each of the fifteen consumer modules contains `self.organization.accounts()` exactly once and `get_organization_accounts` zero times
    - _Requirements: 2.7, 4.1, 4.2, 4.4, 4.5, 5.2, 6.1, 10.4, 10.5_

  - [x] 12.9 **New** `tests/unit/services/test_inspector_batching.py` (`tests/unit/services/` exists with only `__init__.py`), Property 22: drive `InspectorCheck.batch_get_account_status("us-east-1", ids)` with 101 distinct IDs over a `MagicMock` client whose `batch_get_account_status.side_effect` echoes its batch as `{"accounts": [...]}`; assert every call received ≤ 100 IDs (assert against the cap, not the batch constant), the calls partition the 101 without loss or duplication, and the merged `accounts` holds 101 entries in input order. Second test: arm the second batch to return an error result; assert the accessor returns that error result, `ctx._has("inspector", "batch_status:us-east-1")` is `False`, and no `accounts` key is present. Build the check with `_concrete(InspectorCheck)()` from `test_accessor_cache_property` and a real `ScanContext(session=MagicMock(), regions=["us-east-1"])`, with the client placed in `check._clients["us-east-1"]`
    - _Requirements: 8.2, 8.4_

  - [x] 12.10 Run `cd sraverify && uv run pytest -q -p no:logging 2>&1 | tail -3 | tee ../.tmp/sratester/organizations-provider/pytest-12.txt`. Expected: green, no xfail, no xpass; `tests/property/` holds 31 `test_*.py` modules (`ls sraverify/sraverify/tests/property/test_*.py | wc -l`). Record collected/passed/skipped for task 14. `test_every_public_base_method_is_classified` in `test_accessor_cache_property.py` holds with **no** table change (Property 31); `test_stdout_contract_property.py` and `test_context_isolation_property.py` pass unedited
    - _Requirements: 10.6, 10.7, 10.8_

- [x] 13. The IAM policy generator sees `core/`
  - [x] 13.1 Rewrite the walk in `util/generate_iam_policy.py`. Replace `find_client_files` (line 115) with `find_python_modules(base_dir="./sraverify")`: every `.py` under the package directory (the child of `base_dir` named `sraverify` that holds `__init__.py`), pruning by directory name at any depth `PRUNED_DIRS = frozenset({"tests", "__pycache__", "build", "dist"})`, any directory whose name starts with `.` (`.venv`, `.pytest_cache`, `.hypothesis`) and any `*.egg-info`, minus `EXCLUDED_MODULES`, sorted. `EXCLUDED_MODULES: Dict[str, str]` is keyed by **package-relative POSIX path** and holds one entry: `"core/session.py"` with the reason that its one call, `sts:AssumeRole`, is issued by the operator's principal to *become* the member role and is granted by the trust policy, never by the member role. Add `known_service_ids()` (`functools.lru_cache(maxsize=1)`, `frozenset(botocore.session.get_session().get_available_services())`, offline) and require in `bind_clients` that the literal first argument of `get_client(...)` / `.client(...)` is in it — this is what stops `client = self.get_client('us-east-1')` in `services/firewallmanager/base.py:105` and `services/waf/base.py:115` from binding a `Us-east-1Permissions` statement. Keep local-variable bindings (`ScanContext`'s `sts_client`, `account_client`, `org_client`, `ec2_client` are locals). Narrow the per-module warning to a module that declares a class whose base list names `AWSClient` and binds nothing; replace `extract_service_name` (line 134) with the package-relative path in warning text. `--base-dir` help text: "project root to walk (default: ./sraverify)". Output format unchanged: one statement per service, Sid `f"{service.capitalize()}Permissions"`, actions sorted; no acronym normalisation; no trailing newline on the JSON
    - _Requirements: 9.1, 9.2, 9.5_

  - [x] 13.2 Update `tests/unit/util/test_generate_iam_policy.py` (18 tests today): `test_every_client_module_binds_at_least_one_boto3_client` enumerates modules declaring an `AWSClient` subclass by AST over the walked set (picks up `core/organizations_client.py`, drops the deleted `services/organizations/client.py`); `test_the_generator_attributes_the_whole_tree` adds `ec2` and `account` to its expected set; `test_the_generated_policy_reproduces_the_committed_artefact` holds against the regenerated files (Property 25). New: `test_the_relocated_organizations_client_is_attributed_from_core` (seven operations → `organizations`, none from under `services/`); `test_a_region_literal_does_not_bind` (Property 24: `client = self.get_client('us-east-1')` followed by `client.get_admin_account()` binds nothing; the same shape with a known service id binds; `firewallmanager/base.py` and `waf/base.py` walked for real contribute nothing); `test_the_session_builder_is_excluded_and_assume_role_is_not_an_action`; `test_tests_are_not_walked` (a fixture under `tests/` binding `session.client("securitylake", ...)` contributes nothing). `test_waf_client_attributes_nine_services_exactly` and `test_shield_client_attributes_five_services_exactly` hold unchanged (Property 23)
    - _Requirements: 9.1, 9.3, 9.5_

  - [x] 13.3 Regenerate and diff: `cd sraverify && uv run python ../util/generate_iam_policy.py --base-dir . --out-json ../generated_sraverify_iam_policy.json --out-yaml ../generated_sraverify_cf_policy.yaml --quiet`, then, from the repo root, `git diff -- generated_sraverify_iam_policy.json generated_sraverify_cf_policy.yaml > .tmp/sratester/organizations-provider/artefact-diff.patch`. Expected: exactly two added actions and nothing removed — `account:GetAccountInformation` joins the existing `AccountPermissions` statement (from `core/scan_context.py` `get_account_info`) and `ec2:DescribeRegions` joins `Ec2Permissions` (from `get_enabled_regions`). `organizations:ListAccounts`, `organizations:DescribeOrganization` and `sts:GetCallerIdentity` are present as before (now additionally attributed from `core/`); `sts:AssumeRole` is absent. Zero warnings on stderr (the `.venv` ones are gone with the dot-prefix prune). Any other difference is investigated, not committed
    - _Requirements: 9.3_

  - [x] 13.4 Edit `1-sraverify-member-roles.yaml` in exactly two statements, both inside the `SRAVerifyLeastPrivilege` managed policy (the hand-maintained mirror of `generated_sraverify_cf_policy.yaml`, from line 66): add `- account:GetAccountInformation` to its `AccountPermissions` statement (lines 79–82, today `account:GetAlternateContact` only) and `- ec2:DescribeRegions` to its `Ec2Permissions` statement (lines 145–150), keeping each action list sorted. Leave the hand-written `SRAVerifyCheckPermissions` policy's `account:GetAccountInformation` grant (lines 51–54) as it is — the action then appears once per policy, which design Open Question 6 records. Confirm the two documents agree: extract the `SRAVerifyLeastPrivilege` `PolicyDocument` action set and `generated_sraverify_cf_policy.yaml`'s and diff them (a small PyYAML script with a `SafeLoader` that maps `!Ref`/`!Sub`/`!GetAtt` to their raw string is enough; the template carries seven intrinsics, none inside the two edited statements). Then `aws cloudformation validate-template --template-body file://1-sraverify-member-roles.yaml --profile <any profile from accounts.md> > .tmp/sratester/organizations-provider/validate-template.json`. checkov and cfn-nag run as part of ASH in task 15.3
    - _Requirements: 9.4_

- [x] 14. Steering and the developer guide
  - [x] 14.1 `.kiro/steering/structure.md` — eleven amendments, each findable by the quoted text: (a) add `OrganizationsProvider` beside `ScanContext` in the architecture diagram and `core/organization.py` and `core/organizations_client.py` to the layout tree; (b) annotate `services/<svc>/client.py` in the layout tree as "every service except `organizations`, whose client is `core/organizations_client.py`", and add the same qualification to "Adding a new check" steps 2 and 3; (c) change "`_has` / `_get` / `_set` are for **service base classes only**" (line 411) to "**service base classes and providers**"; (d) **remove** the paragraph at line 625 beginning "The accessor tables enumerate `vars(base)`, so a method a base class" through its end, and replace it with a paragraph on the provider and `self.organization` that says no base class inherits anything between itself and `SecurityCheck` and that organization data is reached through the context — it must **not** name the mixin, its constants or `get_organization_accounts` even as history, because Property 12 walks `.kiro/steering/`; (e) list `organization` as the eighth context property wherever the seven are enumerated; (f) in Caching, note that the `all_accounts` slot of the `organizations` namespace is written by the provider and read by no base class by key (scoped to the slot in Phase 1; the rest of the namespace is still `OrganizationsCheck`'s until Phase 2); (g) in "Error handling: three tiers", tier 2, change "which reads the service's declared `NOT_CONFIGURED_ERRORS` table" (line 486) to "which reads the service's declared table and then the provider's"; (h) in the test-module table, rename the `test_organization_accounts_property.py` row (line 613) to `test_organization_provider_property.py` and rewrite its cell for the provider contract and "only the provider's client issues `ListAccounts`" without naming the mixin, add a `test_layering_property.py` row, and change "AST rules over all 18 `client.py` files" (line 606) to "over the 17 `services/*/client.py` files and `core/organizations_client.py`"; (i) update the global-service example in "Canonical code shapes" to say partition-global with the Region derived from the scan; (j) update the client-method count (108, relocated not changed), the property-module count (31) and the collected/passed/skipped counts from 12.10; (k) in "Known structural oddities", change "three of its accessors pin `self.regions[0]`" for `securityincidentresponse` to "two" (`get_delegated_administrators()` and `get_role()`)
    - _Requirements: 2.6, 5.4, 11.1_

  - [x] 14.2 `.kiro/steering/tech.md`: update the counts (line 73) and "~26 hypothesis and reflection modules" to the measured count (31 expected; the measured count wins); in "IAM policy generation", say the generator walks every module in the package rather than `client.py` files, prunes `tests/` and dot-prefixed directories, keys exclusions by package-relative path, and that `ec2:DescribeRegions` and `account:GetAccountInformation` are now in the artefacts; extend the Deployment section's deploy-roles-first rule with this change as the example of a `core/`-issued call becoming visible to the generator
    - _Requirements: 11.2_

  - [x] 14.3 `.kiro/steering/creating_checks_best_practices.md`: add an "Organizations data" section — a check reads `self.organization.accounts()` and filters with `is_active_account`; never add an `org_client` to a service client or an Organizations accessor to a service base; the error branch is the standard two-arm shape; `is_not_configured` consults the service table then the provider's table — and cross-reference it from the Account-lists section; amend "`_has` / `_get` / `_set` are for **service base classes only**" (line 333) to "**service base classes and providers**"; rewrite the known-defect entry at line 545 so it names only the two surviving accessors, `get_delegated_administrators()` and `get_role()` (the third was deleted by !54 and its name fails Property 12)
    - _Requirements: 5.4, 11.3_

  - [x] 14.4 `sraverify/README.md`: follow the steering in Architecture (the provider beside `ScanContext`), "Initialization and the delegating properties" (adds `organization`), "Service base class", "Client method" (the one client under `core/`), Caching, and Tests. Where it disagrees with a steering file, the steering file wins
    - _Requirements: 11.4_

  - [x] 14.5 Confirm `.kiro/steering/product.md` is untouched (`git diff --quiet -- .kiro/steering/product.md`) and that `grep -rn "OrganizationAccountsMixin\|ORGANIZATION_ACCOUNTS_\|get_organization_accounts" .kiro/steering/ sraverify/README.md` returns nothing
    - _Requirements: 4.4, 11.5_

- [x] 15. Offline verification
  - [x] 15.1 `cd sraverify && uv run pytest -q -p no:logging 2>&1 | tail -3 | tee ../.tmp/sratester/organizations-provider/pytest-final.txt` — green, no xfail, no xpass. If the counts differ from 12.10, update 14.1(j) and 14.2
    - _Requirements: 10.8, 12.6_

  - [x] 15.2 `sraverify/.venv/bin/sraverify --list-checks > .tmp/sratester/organizations-provider/list-checks.txt 2> .tmp/sratester/organizations-provider/list-checks.err && cmp .tmp/sratester/organizations-provider/list-checks.txt docs/checks.txt && test ! -s .tmp/sratester/organizations-provider/list-checks.err` — identical and a 0-byte stderr. Nothing in this feature touches a `CheckMeta`, so `docs/checks.txt` is **not** regenerated
    - _Requirements: 6.6, 10.9, 12.6_

  - [x] 15.3 ASH per `.kiro/steering/security_scanning.md`: `uv tool run --from automated-security-helper==3.7.0 ash --source-dir . --mode local`, then read `.ash/ash_output/reports/ash.summary.md`. Clean means every enabled scanner (bandit, checkov, cfn-nag, detect-secrets, grype, opengrep) PASSED with 0 actionable findings at MEDIUM, none ERROR or MISSING, and only cdk-nag, npm-audit, semgrep and syft SKIPPED. The template edit of 13.4 is covered by checkov and cfn-nag here. Fix code first; a suppression covers one line or one resource with its reason beside it. Copy the summary to `.tmp/sratester/organizations-provider/ash.summary.md`
    - _Requirements: 9.4, 12.6_

  - [x] 15.4 Grep sweep over the package (expected output in brackets): `grep -rn "OrganizationAccountsMixin\|ORGANIZATION_ACCOUNTS_\|get_organization_accounts" sraverify/sraverify/ .kiro/steering/` [only the asserting module `test_layering_property.py`]; `grep -rn "region='us-east-1'\|region=\"us-east-1\"" sraverify/sraverify/core/ sraverify/sraverify/services/*/client.py sraverify/sraverify/services/*/base.py` [after the !55 rework: **no** Organizations binding and nothing under `core/`; the only hits are the out-of-scope `us-east-1`-only control planes — the CloudFront bindings in `services/shield/client.py` and `services/waf/client.py`, and the `no_client_result` labels in `services/firewallmanager/base.py` and `services/waf/base.py`]; `grep -rn "list_accounts" sraverify/sraverify/core/ sraverify/sraverify/services/` [`core/organizations_client.py` (definition and paginator), `core/organization.py` (the wrapper call), and `services/organizations/base.py`'s `list_accounts_for_parent` only]; `ls sraverify/sraverify/services/organizations/` [no `client.py`, no `accounts.py`]
    - _Requirements: 2.5, 2.7, 4.4, 5.2_

- [x] 16. Live A/B against both reference trees (`.kiro/steering/testing_checks.md`)
  - [x] 16.1 Read `sratester/accounts.md` first. It names the management, audit, log-archive and application profiles and what may be changed. This gate is a refactor: no resource is mutated, no snapshot is needed, and nothing on the do-not-mutate list is touched. Scratch goes to `.tmp/sratester/organizations-provider/`; create it with a `.gitignore` containing `*`
    - _Requirements: 11.6, 12.9_

  - [x] 16.2 Write `.tmp/sratester/organizations-provider/run_ab.sh` from `.tmp/sratester/org-accounts/run_diff.sh`, extended to **three** trees and **seven** services. Trees: `candidate` is the editable install (`sraverify/.venv/bin/python -m sraverify`); `main` and `mr54` run the same interpreter with `PYTHONPATH=.tmp/sratester/organizations-provider/main-wt/sraverify` and `PYTHONPATH=.tmp/sratester/organizations-provider/mr54-wt/sraverify` respectively (the worktrees from 1.3). Profiles: the management and audit profiles from `accounts.md`. Services: `--service Inspector`, `Macie`, `Organizations`, `SecurityHub`, `SecurityIncidentResponse`, `SecurityLake`, `IAM` (IAM is new against !54's script: its `org_client` Region changes under 8.4). Every invocation passes identical `--regions`, `--audit-account`, `--log-archive-account` and `--debug`, writes `--output .tmp/sratester/organizations-provider/<tree>/<profile>_<service>.csv` and redirects stderr to the matching `.err`. **Run strictly sequentially, in one window**, so the three trees see the same organization state. Resolve the two account IDs at the top with `aws sts get-caller-identity` as the !54 script does
    - _Requirements: 12.1_

  - [x] 16.3 Write `compare3.py` from `.tmp/sratester/org-accounts/compare.py`: join on `(CheckId, Region, ResourceId)`, compare `Status`, `ActualValue`, `Remediation` for candidate-vs-main and candidate-vs-mr54, and emit every differing cell with an `order_only` flag — `True` when the two cells tokenise to the same multiset of 12-digit account IDs in a different order (reuse `.tmp/sratester/org-accounts/order_check.py`). Also report rows present in one tree only. Write the output to `compare3.txt` and a per-check summary to `compare3-summary.txt`
    - _Requirements: 3.5, 12.1_

  - [x] 16.4 Run `run_ab.sh`, then `compare3.py`. Admit only: `order_only == True` cells in `SRA-INSPECTOR-07`, `SRA-SECURITYHUB-08` and `SRA-MACIE-07`; and (against `main` only) `SRA-INSPECTOR-07` rows attributable to the first-page effect, which in the 13-account organization must be **zero** — confirm with `aws organizations list-accounts --query 'length(Accounts)'` on the management profile and record the number. Every other difference is a rejection: find the cause in the candidate, fix it in code, re-run the suite, and **re-scan the affected checks on all three trees**; never patch the comparison. Disposition every difference in the report
    - _Requirements: 3.5, 3.6, 12.2_

  - [x] 16.5 Per-scan gates over every candidate `.err` and `.csv`, scripted and the script kept: 0 synthetic rows (no `ActualValue` matching `^[A-Za-z_]+(Error|Exception): `); 0 ` - ERROR - ` log records; 0 `No client available`; `grep -c aws_call_failed` per scan equal to the `mr54` scan's and explainable against `main`'s; `grep -c "Fetching organization accounts"` **exactly 1** per scan that runs a consumer check, and `Using cached organization accounts` on every later read (count ≥ the number of consumer rows minus one). Record all counts in a table
    - _Requirements: 12.3_

  - [x] 16.6 The negative run: from the application-account profile named in `accounts.md` (a member account that is neither the management account nor a delegated administrator, so it cannot call `organizations:ListAccounts`), run `sraverify/.venv/bin/sraverify --profile <that profile> --regions <same list> --check SRA-INSPECTOR-07 --debug --output .tmp/sratester/organizations-provider/negative/inspector07.csv 2> .tmp/sratester/organizations-provider/negative/inspector07.err`. Expected: one row per scanned Region, every row `ERROR`, `ActualValue` beginning `ListAccounts failed: AccessDeniedException:`, and `grep -c aws_call_failed` equal to the Region count (the failure is re-issued per Region, not cached). Record the observed code and message **verbatim**: it is the evidence any Phase 2 `ListAccounts` table entry would cite
    - _Requirements: 1.4, 3.6, 12.4_

  - [x] 16.7 Partition derivation is verified offline only (12.7's tests). The report states three things: the test organization and the CodeBuild deployment are commercial; the GovCloud and China behaviour is derived from botocore's bundled endpoint data (`.tmp/review/endpoint_probe.txt`, `endpoint_probe2.txt`); and the specific error a cross-partition call would return is inferred, not observed
    - _Requirements: 2.4, 12.5_

- [x] 17. IAM simulation and the member-role deploy
  - [x] 17.1 **Before** the deploy, from a member-account admin profile in `accounts.md`: `aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::<member account id>:role/SRAMemberRole --action-names ec2:DescribeRegions account:GetAccountInformation organizations:ListAccounts --profile <profile> > .tmp/sratester/organizations-provider/iam/principal-before.json`. Expected: `implicitDeny` for `ec2:DescribeRegions`, `allowed` for `account:GetAccountInformation` (via `SRAVerifyCheckPermissions`), `allowed` for `organizations:ListAccounts`
    - _Requirements: 9.7_

  - [x] 17.2 `simulate-custom-policy` on **both** edited-template documents, extracted separately to JSON (the same extraction as 13.4): `aws iam simulate-custom-policy --policy-input-list file://.tmp/sratester/organizations-provider/iam/least-privilege.json --action-names ec2:DescribeRegions account:GetAccountInformation organizations:ListAccounts` → all three `allowed` (the first two newly); the same against `check-permissions.json` → `account:GetAccountInformation` `allowed`, the other two `implicitDeny`, unchanged. Save both outputs; together they show which policy grants what and that the generated-mirror policy alone is now sufficient for the three actions
    - _Requirements: 9.7_

  - [x] 17.3 Deploy `1-sraverify-member-roles.yaml`: the service-managed StackSet across the organization **and** the separate management-account stack (StackSets do not target the management account), both named in `accounts.md`, with `aws cloudformation update-stack-set --stack-set-name <name> --template-body file://1-sraverify-member-roles.yaml --capabilities CAPABILITY_NAMED_IAM ...` and `aws cloudformation update-stack --stack-name <name> --template-body file://1-sraverify-member-roles.yaml --capabilities CAPABILITY_NAMED_IAM ...` from the profiles `accounts.md` names. **This modifies an IAM role in every account of the organization and needs the owner's explicit sign-off before the write**; state the change (two actions added to `SRAVerifyLeastPrivilege`) and wait. Wait for the StackSet operation to reach `SUCCEEDED` and say how long it took
    - _Requirements: 9.6, 12.7_

  - [x] 17.4 **After** the deploy, repeat 17.1 to `principal-after.json`. Expected: all three `allowed`
    - _Requirements: 9.7_

- [x] 18. CodeBuild end to end, without editing the project
  - [x] 18.1 From the repo root, tar the two paths the buildspec uses: `tar --exclude='.venv' --exclude='build' --exclude='dist' --exclude='*.egg-info' --exclude='__pycache__' --exclude='.hypothesis' --exclude='.pytest_cache' -czf .tmp/sratester/organizations-provider/candidate.tgz sraverify sra-verify-dashboard.html` (omitting the dashboard makes POST_BUILD fail after a successful scan). Upload to the findings bucket named in `accounts.md` under a scratch key, e.g. `aws s3 cp .tmp/sratester/organizations-provider/candidate.tgz s3://<bucket>/gate/organizations-provider/candidate.tgz --profile <deployment profile>`
    - _Requirements: 12.7_

  - [x] 18.2 Fetch the project's inline buildspec — `aws codebuild batch-get-projects --names SRAVerify-Security-Assessment --query 'projects[0].source.buildspec' --output text --region <project Region from accounts.md> --profile <deployment profile> > .tmp/sratester/organizations-provider/buildspec.yml` — and make **one** change: replace the line `git clone -b $GIT_BRANCH https://github.com/awslabs/sra-verify.git` with `mkdir sra-verify && aws s3 cp s3://<bucket>/gate/organizations-provider/candidate.tgz . && tar -xzf candidate.tgz -C sra-verify` so that `pip install ./sra-verify/sraverify` and the POST_BUILD copy of `sra-verify/sra-verify-dashboard.html` resolve as before. Start one build: `aws codebuild start-build --project-name SRAVerify-Security-Assessment --buildspec-override file://.tmp/sratester/organizations-provider/buildspec.yml --region <Region> --profile <deployment profile>`; record the build id. Starting a build is a write to the deployment account; mention it before running
    - _Requirements: 12.7_

  - [x] 18.3 Judge from the consolidated CSV, not the build status: download the new `sraverify/reports/consolidated/*.csv` and the previous one from the bucket; compare per-account row counts for the fifteen consumer checks and the twelve Organizations checks (equal to the previous report's), count ERROR rows from those checks (expected 0), and explain any change in the total ERROR count. The role deploy's visible effect is zero rows, because the buildspec passes `--regions`. Then delete the tarball: `aws s3 rm s3://<bucket>/gate/organizations-provider/candidate.tgz --profile <deployment profile>`
    - _Requirements: 12.7_

- [x] 19. The test report
  - [x] 19.1 Write `sratester/organizations-provider-test-report.md` (gitignored; may name real account IDs and resources). Contents, per `testing_checks.md` and Requirement 12.8: a status table per affected check — the fifteen consumers, the twelve Organizations checks and the six IAM checks — with ✅ TESTED where both reference trees agree with the candidate and (for the consumers) the negative run reached the ERROR arm, 🔄 ATTEMPTED with the reason where an arm could not be reached, ❌ BLOCKED only for an actual IAM or SCP denial; the three-way comparison summary with every difference listed and dispositioned (`order_only` cells admitted; Inspector first-page effect: zero rows, covered by the pagination unit test alone); the per-scan gate table from 16.5; the negative-run evidence from 16.6 verbatim; the partition statement from 16.7; the IAM simulation results from 17.1, 17.2 and 17.4; the CodeBuild comparison from 18.3 with the build id; every defect found during the gate, including ones fixed, with the AWS behaviour that exposed it; the statement that no resource was mutated and that the five-phase mutate-detect-fix-validate cycle does not apply to a refactor; and paths to every script, CSV and stderr under `.tmp/sratester/organizations-provider/`
    - _Requirements: 3.5, 11.6, 12.8, 12.9_

- [ ] 20. Hand-off for the owner's review
  - [x] 20.1 Do not commit. Write `.tmp/sratester/organizations-provider/mr_description.md` with: the one-line commit message (proposal: `Add the Organizations provider: one partition-aware ListAccounts sweep per scan, reached as self.organization`); a summary that this MR **supersedes !54** and that !54 is closed unmerged when this merges; what changed (the provider, the relocated client, the two-table discriminator, the fifteen one-token call sites, the primer, the generator walk, the two template statements, the steering); what was tested (the final pytest counts, the `cmp`, ASH, the three-way A/B result, the negative run, the IAM simulations, the CodeBuild build id); and what was not verified live (partition correctness; the Inspector first-page effect). Then `git status --short` and `git diff --stat` into the same directory and tell the owner the branch is ready to review. Remove the two reference worktrees only after the owner has accepted the report (`git worktree remove .tmp/sratester/organizations-provider/main-wt` and `mr54-wt`)
    - _Requirements: 6.1, 12.8_
  - Owner decisions for the MR !55 rework (2026-10-02): fail fast when the scan Region cannot be determined (`--regions[0]`, else the session Region, else exit 2, no file, no AWS call); Shield, WAF for CloudFront, Firewall Manager's admin API and CloudFront stay `us-east-1`-only and out of scope; the branch history is rebuilt to drop 986bced (a later step); the generator's unbindable-site allowlist is by shape, not by file. Mechanism: `.tmp/sratester/organizations-provider/failfast-design.md`; plan: `rework-plan.md` beside it.
  - [x] 20.2 `core/regions.py::resolve_scan_region` and `PartitionUndeterminedError` (with `_UNSET`) in `core/errors.py`; `tests/unit/core/test_scan_region.py`
    - _Requirements: 2.2, 2.4_
  - [x] 20.3 `ScanContext` copies `regions`, computes and exposes `scan_region` before the lock/caches/provider, `get_client(region=None)` means the scan Region (`"__global__"` deleted), and `sts` / `account` / `organizations` / `ec2` bind it explicitly; `scan_region(ctx) -> str` with the `GLOBAL_REGION` branch removed; the two IAM-client comments; `tests/unit/core/test_scan_context.py` rewritten
    - _Requirements: 2.2, 2.3, 2.4, 2.5, 2.9_
  - [x] 20.4 `get_session` in the two-wrapper shape (STS and the assumed session on the scan Region, the error unwrapped before STS); `SRAVerify` passes `regions[0]`, gains `resolve_scan_region()`, and calls it first in `run_checks`; `test_session_region.py`, `test_partition_failfast.py`
    - _Requirements: 2.2, 2.8_
  - [x] 20.5 CLI: `SRAVerify(...)` guarded, the exit-2 handler widened, `resolve_scan_region()` ahead of the banner, the banner's STS bound to the scan Region, new `--regions` help; tests 19–23a in `test_exit_codes.py`
    - _Requirements: 2.8_
  - [x] 20.6 Property 34 in `test_layering_property.py`: no Region-less or literal binding in `core/`, `scanner.py`, `cli.py`, `utils/`, empty allowlist, four-plus-four fixture, and a recorded mutation check
    - _Requirements: 2.9_
  - [x] 20.7 `SecurityHubCheck.get_organization()` binds `scan_region(self._ctx)` (no production caller; survey recorded in `progress.md`); `tests/unit/services/test_securityhub_organization.py`
    - _Requirements: 2.5, 6.5_
  - [x] 20.8 Properties 12 and 15 become AST rules over package code (retired names in code, not prose; cache primitives and `organization` matched on the receiver), `_REPO_ROOT` deleted, non-vacuity fixtures added; the suite passes from an installed wheel
    - _Requirements: 4.4, 5.2, 10.10_
  - [x] 20.9 The generator warns on an unbindable `get_client` / `.client` site anywhere in the package, exempting the wrapper lookup and the factory by shape; four new tests, zero warnings on the real tree; artefacts not regenerated here
    - _Requirements: 9.5, 9.8_
  - [x] 20.10 Property 13 catalog-wide (`organization` in the context properties, no setter, identity after `initialize`) and Property 28's walk forbids `OrganizationsProvider`
    - _Requirements: 1.9, 5.1_
  - [x] 20.11 One sweep per scan is stated as a sequential guarantee in `core/organization.py` and the Property 1 test; no lock added
    - _Requirements: 1.3, 1.10, 13.7_

---

## Gate between the phases

- [x] 21. **Phase 1 merged and its test report accepted**
  - Phase 2 does not start until the Phase 1 MR has merged to `main`, `sratester/organizations-provider-test-report.md` has been accepted by the owner, and !54 is closed. Record the merge commit here; it is Phase 2's reference tree. Phase 2 branches from that commit, not from the Phase 1 branch
  - _Requirements: 13.1_
  - **Recorded 2026-10-02:** Phase 2's reference tree is merge commit `f517024`. The owner merged !55, closed !54 and accepted the Phase 1 report.

---

## Phase 2 — remaining Organizations surface

Every task here is a Phase 2 obligation and none is a Phase 1 gate. Phase 2 is its own MR with its own design revision against `design.md`, its own live A/B against the merged Phase 1, and its own report. Verdicts may move here, each with per-row evidence. Tasks are stated at the granularity the approved design fixes; the Phase 2 design revision (task 22) refines them before any code is written.

- [x] 22. Phase 2 design revision
  - [x] 22.1 Revise `design.md` (or add `design-phase2.md` beside it) against the merged Phase 1 tree: the exact accessor names and signatures for the ten Phase 2 accessors listed in the provider's comment block, the per-accessor cache keys, which `org_client` call sites become which accessor, how `ScanContext._finding`'s per-row `get_account_info()` read reports a failed `sts:GetCallerIdentity` without a `try`/`except` in any `execute()`, and whether `_remediation_for` should name the operation's service rather than the check's when a provider operation fails (design Open Question 5). Resolve design Open Questions 4, 5 and 12 here. Run it through the same review loop as the Phase 1 design
    - _Requirements: 13.1, 13.3_

- [ ] 23. Grow the client and the provider
  - [x] 23.1 `core/organizations_client.py`: add `list_delegated_administrators(service_principal)`, `list_policies_for_target(target_id, policy_type)` and `describe_policy(policy_id)` in the canonical shape (paginator where botocore has one, whole loop inside the `try`, handler `except AWS_EXCEPTIONS as e: return self.aws_error(e)`). Add their three `ClientAdapter` rows to `_ORGANIZATIONS` in `tests/property/test_client_contract_property.py`; the client-method count moves from 108 to 111 and the steering counts with it
    - _Requirements: 13.1_

  - [x] 23.2 `core/organization.py`: add the accessors — `describe()`, `management_account_id()` (derived from `describe()`), `delegated_administrators(service_principal)` cached per principal, `roots()`, `ous_for_parent(parent_id)`, `policies(policy_type)`, `policies_for_target(target_id, policy_type)`, `describe_policy(policy_id)`, `effective_policy(policy_type, target_id)`, `accounts_for_parent(parent_id)` — each under the `organizations` namespace through `_has`/`_get`/`_set`, each returning an error result unchanged and uncached, no no-client path. Add one `ProviderAdapter` row per accessor to `PROVIDER_ADAPTERS` in `tests/property/test_organization_provider_property.py` (never to the base tables), so `stub_organization` patches each and `test_the_provider_adapter_table_is_complete_and_exact` holds. Update Property 4's public-callable set and the `_PROVIDER_OPERATIONS` resolution in the classification harness
    - _Requirements: 13.1, 10.6_

  - [ ] 23.3 Before concurrent scanning lands, add per-key in-flight coordination to the provider so one sweep per scan holds under concurrency; and before deciding on any non-retryable failure marker, measure the denied-`ListAccounts` path at full breadth (every consumer, every Region) and record the call count
    - _Requirements: 1.10, 13.7_
    - **Note (2026-10-02, design-phase2.md):** the measurement clause is satisfied by the Phase 1 live validation — 207 denied `ListAccounts` calls over 17 Regions from an application account running every check of the seven consuming services, 0 under a real `--account-type application` scan. The concurrency clause stays **open and deferred** while `run_checks` is sequential; the guarantee is "one fetch per accessor per key per scan, under sequential execution". The non-retryable marker is recorded as a proposal only and is not implemented in Phase 2.

- [x] 24. Retire every `org_client` binding
  - [x] 24.1 Remove the `org_client` binding and its `ListDelegatedAdministrators` / `DescribeOrganization` methods from the eight service clients — `services/accessanalyzer/client.py`, `services/cloudtrail/client.py`, `services/config/client.py`, `services/iam/client.py`, `services/macie/client.py`, `services/securityhub/client.py` (two call sites), `services/securityincidentresponse/client.py`, `services/securitylake/client.py` (two call sites) — and point each base accessor that wrapped them at `self.organization.<accessor>()`. Remove the corresponding `ClientAdapter` rows and reclassify the base accessors in `test_accessor_cache_property.py` (a base method that now delegates to the provider is `derived`, not `accessor`). `services/iam/client.py` drops its `scan_region` import with the binding
    - _Requirements: 13.2_
    - **Note (2026-10-03, design-phase2.md rev 5):** `ConfigCheck.get_delegated_administrators` keeps its argument path: `principals = [service_principal] if service_principal else list(self.CONFIG_SERVICE_PRINCIPALS)`, each through `self.organization.delegated_administrators(p)`, first failure returned unchanged. In `test_accessor_cache_property.py` the `config` and SIR `get_delegated_administrators` rows drop `error_bearing=True`; the other five SIR rows keep theirs (four `True`, `discover_sir_region` `False`), and the SIR table comment "All six of these … are error-bearing" is rewritten to say four of the remaining five are and that `get_delegated_administrators` now delegates and runs unpatched

  - [x] 24.2 `services/securityhub/base.py` `get_organization()` (lines 909–980 on 986bced): replace the raw `self._ctx.get_client('organizations', region='us-east-1')` call, the inline error-result construction and the `_ORGANIZATIONS_NAMESPACE` / `_ORGANIZATION_CACHE_KEY` by-key read with `self.organization.describe()`. `services/iam/base.py` `IAMCheck.get_organization()` likewise. `services/organizations/base.py`: `OrganizationsCheck`'s six remaining accessors (`get_organization`, `get_roots`, `get_ous_for_parent`, `list_policies`, `get_accounts_for_parent`, `get_effective_policy`) delegate to the provider or are replaced by it; `_setup_clients` stops building `self._org_client`, and `get_org_client` goes with it. After this task no `base.py` imports or constructs `OrganizationsClient` and no module outside `core/` binds an `organizations` client
    - _Requirements: 13.2, 6.5_
    - **Note (2026-10-03, design-phase2.md rev 3):** `IAMCheck.get_organization()`'s docstring (`iam/base.py:224`, "Used instead of `get_management_accountId()`, which raises on failure") goes stale with 25.1; rewrite it to say it delegates to `self.organization.describe()`. `IAM_SERVICE_PRINCIPAL` moves from `iam/client.py` to `iam/base.py` beside the delegator. `IAMCheck._cached_call` keeps its three IAM calls

  - [x] 24.3 Widen the AST guards in `tests/property/test_layering_property.py`: Property 8 to every `organizations` operation, keeping its two-set shape — the boto3 spellings (`get_paginator('<op>')` and `.client.<op>(`) permitted in `core/organizations_client.py` only, the wrapper-method spellings (`.<method>(` for each client method) in `core/organization.py` only; Property 15 to "no `base.py` imports or constructs `OrganizationsClient`" with no exemption, and "no `base.py` reads the `organizations` namespace by key" (the Requirement 5.2 clause design Open Question 12 deferred). Re-scope 14.1(f)'s Caching sentence from the `all_accounts` slot to the whole `organizations` namespace
    - _Requirements: 13.2, 5.2, 11.1_

- [x] 25. `ScanContext`'s three raising accessors
  - [x] 25.1 Move `get_account_info`, `get_management_account_id` and `get_enabled_regions` in `core/scan_context.py` to the error-result model: an error result returned and never cached, no `raise Exception(...)`, no `logger.error` for a failed call. `get_management_account_id` reads through `self.organization.management_account_id()`. (`get_enabled_regions` already binds `ec2` to the scan Region since the !55 rework.) `SecurityCheck.get_management_accountId`'s one caller, `services/securityincidentresponse/checks/sra_securityincidentresponse_05.py`, consumes an error result. `_finding` reports a failed `sts:GetCallerIdentity` the way 22.1 decided. Extend `tests/unit/core/test_scan_context.py` for the three accessors
    - _Requirements: 13.3_
    - **Note (2026-10-02, design-phase2.md rev 2):** decided as lazy and per check — `SecurityCheck`'s identity properties, `_finding` and `regions` raise `ScanPreconditionError` on an error result, and `run_checks`' per-check guard catches it ahead of `except Exception` and emits one `_precondition_error` row. No up-front `get_enabled_regions()`; the pre-loop identity read keeps its `except Exception`. `_remediation_for` is unchanged (Open Question 5 decided "no")
    - **Note (2026-10-03, design-phase2.md rev 3):** `_precondition_error(check_class, exc, fallback_account, scan_region)`, called with `ctx.scan_region`, and its `append` nested in its own `try / except Exception` with `logger.error(..., exc_info=True)` as the synthetic row's is (10.12). The identity remediation names no permission (`sts:GetCallerIdentity` needs none and ignores an explicit deny): `Confirm the scan's credentials are valid and unexpired (an expired session token, a wrong --profile, or an invalid access key is the usual cause), then re-run the scan`
    - **Note (2026-10-03, design-phase2.md rev 4):** the precondition remediation is chosen by code first: `TRANSPORT_ERROR_CODES` → the endpoint wording per lookup; `_CREDENTIAL_ERROR_CODES = frozenset({"AuthFailure", "InvalidClientTokenId"})` (observed, `review3/ec2-sts-invalid-creds.txt`) → the credentials wording for either lookup; only then `regions` → the grant wording. `test_scan_preconditions.py` pins an `AuthFailure`/`regions` case (no `ec2:DescribeRegions` in the text) and the set's exact contents. The pre-loop identity block's `logger.error` gains `exc_info=True` (stderr only)
    - **Note (2026-10-03, design-phase2.md rev 5):** `_CREDENTIAL_ERROR_CODES = _REJECTED_CREDENTIAL_CODES | {class names of _LOCAL_CREDENTIAL_EXCEPTIONS}`: the two observed server codes plus `NoCredentialsError`, `PartialCredentialsError`, `CredentialRetrievalError`, `UnauthorizedSSOTokenError`, `TokenRetrievalError`, `SSOTokenLoadError`, derived from the botocore classes like `TRANSPORT_ERROR_CODES` (evidence `review4/nocreds-probe.txt`, `cred-raise-sites.txt`, `cred-subclasses.txt`). `test_scan_preconditions.py` adds `regions`/`NoCredentialsError` (no `ec2:DescribeRegions`), the derived set-equality and `BotoCoreError`-subclass test, and an end-to-end `NoCredentialsError` through `aws_error`. The credentials wording becomes `Confirm the scan has valid, unexpired credentials (no credentials found, an expired session token or SSO login, a wrong --profile, or an invalid access key is the usual cause), then re-run the scan`, superseding rev 3's. The Account API call's handler is `except AWS_EXCEPTIONS as e: self._call_failed(e)`, both clients acquired before their `try`; a non-AWS exception propagates. This note supersedes rev 4's two-code set; the set-equality test is the derived form
    - **Note (2026-10-03, design-phase2.md rev 6):** `get_enabled_regions` acquires its EC2 client **before** its `try`, as `get_account_info` acquires STS and Account. The handler is `except AWS_EXCEPTIONS as e: return self._call_failed(e)`. A client-construction failure therefore propagates unchanged. With an access key and no secret, `PartialCredentialsError` reaches the per-check guard raw. The regional checks' synthetic `ActualValue` goes from `Exception: Failed to get enabled regions: <msg>` to `PartialCredentialsError: <msg>`, and no other cell changes (`review5/partial_regions_probe.txt`). Identity rows are unchanged, text for text. `test_scan_context.py` adds two cases: `client("ec2")` raising `PartialCredentialsError` makes `get_enabled_regions()` raise that exception unwrapped, with no error result, no `aws_call_failed` record and nothing cached; and the twin for `client("sts")` and `get_account_info()`

- [x] 26. Unify the `ListDelegatedAdministrators` classification — verdicts move here, with evidence
  - [x] 26.1 Today only `services/iam/base.py:83` declares `AWSOrganizationsNotInUseException` semantic for `ListDelegatedAdministrators`, so the same AWS answer is FAIL through an IAM check and ERROR through seven other services' checks. Decide the unified classification in the provider's `NOT_CONFIGURED_ERRORS`, each entry with `evidence` citing the API reference page or an observed `aws_call_failed` line (16.6's verbatim record is the `ListAccounts` evidence), and remove the per-service duplicates. **Before** committing any entry, list every row it moves by check ID and branch in the Phase 2 A/B (task 28). Apply the same evidence rule to any `ListAccounts` entry and to any `DescribeOrganization` entry beyond what the service tables already declare. `test_discriminator_property.py` already enumerates the provider table from 12.5
    - _Requirements: 13.4, 3.1, 3.3, 13.12_
    - **Note (2026-10-02, design-phase2.md rev 2):** the test organization cannot return `AWSOrganizationsNotInUseException`, so both new entries (`ListDelegatedAdministrators`, `ListAccounts`) are held under Requirement 13.12: the API reference citation, the offline ledger in `tests/unit/core/test_provider_classification.py` (Property 44, with `_PROVIDER_PAIRS_WITHOUT_FAIL_ARM` for `SRA-SECURITYHUB-17` and `SRA-IAM-05`), and a live A/B expected to move zero rows. The test report flags this reading for the owner
    - **Note (2026-10-03, design-phase2.md rev 4):** remove from service tables **only** the five owned-operation entries (`IAMCheck` `ListDelegatedAdministrators`; `ConfigCheck` and `OrganizationsCheck` `DescribeOrganization`; `OrganizationsCheck` and `SecurityHubCheck` `DescribeEffectivePolicy`). `IAMCheck` keeps `ListOrganizationsFeatures` and `GetAccountPasswordPolicy` byte-identical (they back `SRA-IAM-02/-03/-06` FAILs observed in the test organization); its and `ConfigCheck`'s class comments are rewritten for the provider. Property 43 gains a 46-row golden of every non-owned service-table entry as of `f517024`. Ledger-harness delegators stay unpatched (`derived`, default `error_bearing`); no new operation mapping

- [x] 27. IAM artefacts and template — expect no new action
  - [x] 27.1 Regenerate with the 13.3 command and diff. Expected: **no new action** — every retired `org_client` call was already granted — and no removal; a difference other than attribution order is a finding to explain. `1-sraverify-member-roles.yaml` is expected unchanged; if it changes, follow 13.4 and 17.3 again. Confirm in the A/B that the `aws_call_failed region=` record for retired paths moves from the scanned Region to the derived one while no row's `Region` cell moves
    - _Requirements: 13.5_

- [x] 28. Phase 2 live A/B, gates, and report
  - [x] 28.1 Re-run 16.2–16.6 with two trees — the merged Phase 1 commit (worktree) and the Phase 2 candidate — over every service that touched Organizations in 24.1 and 24.2 (the seven from 16.2 plus Access Analyzer, CloudTrail and Config). Every verdict that moves is listed by check ID, Region, account and branch with the `aws_call_failed` or API-reference evidence for the table entry that moved it; a moved row with no entry to explain it is a rejection. Per-scan gates as 16.5, with `Fetching` records now expected once per *accessor* per scan. Repeat 17.1/17.4 only if 27.1 changed the template; repeat 18.1–18.3 for the Phase 2 candidate
    - _Requirements: 13.4, 13.5, 12.3_
    - **Note (2026-10-03, design-phase2.md rev 4):** negative runs per design-phase2.md "Testing Strategy": run 2 (invalid static credentials, `--regions` given) and run 2b (the same credentials, `AWS_DEFAULT_REGION` set, no `--regions`; expected `DescribeRegions failed: AuthFailure` on regional checks with the credentials remediation). Run 3 (Region list denied by policy) stays 🔄, unit-tested only
    - **Note (2026-10-03, design-phase2.md rev 5):** add negative run 2c — no credential source (`env -i`, config and credentials files `/dev/null`, IMDS disabled), `AWS_DEFAULT_REGION=us-east-1`, no `--profile`, no `--regions`, both trees. Read-only: botocore raises `NoCredentialsError` before any request. Expected on the candidate: `Request failed: NoCredentialsError: Unable to locate credentials` with the credentials remediation on every row, none naming `ec2:DescribeRegions`; same row count per check as the merged tree
    - **Note (2026-10-03, design-phase2.md rev 6):** add negative run 2d. It uses the 2c environment plus `AWS_ACCESS_KEY_ID` set to a non-existent value with no secret, no `--regions`, on both trees. It is read-only: botocore raises `PartialCredentialsError` at client construction, before any request. Expected: the same row count per check, with every row synthetic on both trees. For regional checks, `ActualValue` goes from `… Exception: Failed to get enabled regions: Partial credentials …` on the merged tree to `… PartialCredentialsError: Partial credentials …` on the candidate. IAM and Organizations checks show identical text on both trees. `Remediation` and every other cell are equal
    - **Recorded 2026-10-03:** A/B 40 scans (10 services × management + audit × `phase1-wt` and candidate) plus 20 application-account scans: 853 = 853 and 171 = 171 rows, 0 `Status` moves, 8 admitted order-only cells, Region cells identical, all gates OK. Negative runs n1, 2, 2b, 2c, 2d as designed; run 3 🔄. 27.1 confirmed live on SRA-SECURITYHUB-07 us-west-2 (`ListDelegatedAdministrators region=us-west-2` → `us-east-1`, row Region unchanged). Template unchanged, so no redeploy. CodeBuild `4040d7b7-d267-44d9-a19e-714dafb35d03`: 3367 = 3367 rows, ERROR 492 = 492, 0 `Status` changes on an unchanged key, 15 GuardDuty rows moved by an AWS state change (ledger). Evidence: `.tmp/sratester/organizations-provider-phase2/live/`

  - [x] 28.2 Write `sratester/organizations-provider-phase2-test-report.md` in the 19.1 shape, plus the moved-verdict ledger and the confirmation that no Region cell was relabelled and no per-scan call was hoisted above a Region loop (Non-Goals 3 and 6 carried forward)
    - _Requirements: 13.6_

- [x] 29. Phase 2 steering, counts and close
  - [x] 29.1 `structure.md`, `tech.md`, `creating_checks_best_practices.md` and `sraverify/README.md`: the provider's full accessor list, the client-method count (96 at the end of Phase 2: 111 after 23.1, less the fifteen `org_client` methods 24.1 deletes — see design-phase2.md), the retired `org_client` pattern (now a named anti-pattern in the authoring guide), the widened Caching sentence and Property 15 scope from 24.3, the `ScanContext` error-result model from 25.1, and the measured test counts. Carry forward every deferral `structure.md` records that Phase 2 did not explicitly close (Region relabelling, set ordering, Shield pagination). `cmp` of `--list-checks` against `docs/checks.txt`, ASH 3.7.0 clean, pytest green with no xfail; then the owner's hand-off as in 20.1
    - _Requirements: 13.6, 10.8, 10.9_
    - **Note (2026-10-02, design-phase2.md rev 2):** also amend `structure.md`'s "Known structural oddities" SIR sentence: `get_delegated_administrators()` no longer pins `self.regions[0]` after the delegator change; `get_role()` and SIR-01's row label still do, so no Region cell moves. The client-method arithmetic is 101 service-client methods − 15 = 86, plus the relocated client's 10 = 96
    - **Note (2026-10-03, design-phase2.md rev 4):** also correct `creating_checks_best_practices.md`'s empty-table sentence ("`auditmanager`, `config`, `cloudtrail`, `ec2` and `iam` all declare `{}`") and the "`auditmanager`'s … was **omitted**" sentence after it. Both are stale today for four of the five services. After Phase 2 only `ec2` declares `{}`. `auditmanager` (`GetOrganizationAdminAccount`, with a message needle) and `cloudtrail` (`GetEventSelectors`, `GetTrailStatus`) are unchanged. `config` keeps `GetBucketPolicy`. `iam` keeps `ListOrganizationsFeatures` and `GetAccountPasswordPolicy`. Name Property 43's 46-row golden as what holds the non-owned entries. This is a doc correction and moves no row
    - **Note (2026-10-03, design-phase2.md rev 5):** the golden constant is `_NON_OWNED_NOT_CONFIGURED_ENTRIES` in `test_discriminator_property.py`. Add one line to `structure.md`'s "Adding a new check" step 4a and to `creating_checks_best_practices.md`'s "Declaring a `NOT_CONFIGURED_ERRORS` entry": adding, removing or editing a service-table entry for an operation the provider does not own fails that golden until it is updated in the same commit, deliberately
    - **Recorded 2026-10-03:** `structure.md`, `tech.md`, `creating_checks_best_practices.md` and `sraverify/README.md` carry the eleven provider accessors, 96 client methods (counted by reflection: 86 service-client + 10 `OrganizationsClient`), the retired `org_client` anti-pattern, the widened Caching sentence and Property 15 scope, the `ScanContext` error-result / `ScanPreconditionError` model, the corrected empty-table sentence (`accessanalyzer` and `ec2` declare `{}`), the golden line, the SIR `regions[0]` amendment, and the measured counts 10081 passed / 1238 skipped / 0 xfail. The Region relabelling, set ordering and Shield pagination deferrals are carried forward unchanged. `--list-checks` `cmp` `docs/checks.txt` identical; ASH 3.7.0 clean on the committed tree (recorded in the MR). Task 23 stays open for 23.3's deferred concurrency clause

## Notes

- **The approved design is the source of truth for code shape.** Where a task paraphrases a code block, `design.md`'s "Components and Interfaces" section carries the full form with its docstrings and reasoning; the paraphrase here is so Phase 1 can be executed from this file alone.
- **Three writes need explicit owner sign-off before they happen**: deploying the member-role StackSet and the management-account stack (17.3), starting a CodeBuild build with a buildspec override (18.2), and uploading the tarball to the findings bucket (18.1). Everything else in Phase 1 is a read, a local edit, or a local scan.
- **Nothing in Phase 1 requires a version bump.** `SRAVerify` and `run_checks` keep their signatures and the MCP server is unaffected. If the owner bumps `__version__` for the new public property, run `uv sync --reinstall-package sraverify` afterwards.
- **Deliberately not in either phase**, each recorded in `design.md`'s Open Questions: widening `_SHADOWED_CONTEXT_NAMES` to the seven older context properties (its own small change); dropping the hand-written `account:GetAccountInformation` grant from `SRAVerifyCheckPermissions` (a template-only change); carrying `failedAccounts` through the Inspector multi-batch merge (belongs with a check that reads it); `sorted()` at the three set-join sites; pagination for `ShieldClient.list_protections`; Region relabelling in `securityincidentresponse` and `sra_firewallmanager_01`; the dead `if not org_accounts` branch in the eight log-source checks; anything in `sra-verify-mcp`.
- **Residual defects in `requirements.md`**, recorded here so the next reader does not take them for implementation errors — the design's Open Questions 1, 2, 3, 4, 8, 9, 11 and 12, plus one found while writing this plan: Requirement 6.1, Non-Goal 6 and the design all say "the thirteen regional checks", but twelve of the fifteen consumers loop over Regions (`inspector_07`, `macie_07`, `securityhub_08`, `securitylake_01`, `securitylake_06`–`_13`) and three are global (`organizations_12`, `securityhub_17`, `securityincidentresponse_04`). The module list and the total of fifteen are right; only the split is off by one. Task 9.1 uses the measured split. (Status: every item in this paragraph, the split included, has since been applied to `requirements.md` and `design.md` in place, with no criterion added, removed or renumbered — see the dated **Status** note at the head of the design's Open Questions; the wording here is kept for the record.)
