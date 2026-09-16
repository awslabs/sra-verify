# Implementation Plan: Client Error Contract

> **Post-implementation note.** The acceptance gate described throughout this plan
> — `util/gate.py`, `util/local_scan.py`, `tests/unit/util/test_gate.py`, the
> `docs/gate/` digests, and the `check_done` stderr marker `run_checks` emitted at
> `debug` — was development tooling for this migration and was removed once it
> completed. It did its job: it is what caught the Shield `NOT_CONFIGURED_ERRORS`
> omission (ten checks moving FAIL to ERROR) and what held each batch to a
> reconciled CSV comparison. It is recoverable from git history if a future
> verdict-moving change wants it.
>
> References to it below are a record of how the work was done, not a description
> of the current tree. Still current: `aws_call_failed`, which remains at `error`
> on stderr and is the evidence behind every ERROR row.

## Overview

Eight phases, in the order the design's Migration Order section establishes: Phase 0 scaffolding and gate infrastructure, six service batches, then close. Implementation language is Python 3.11.

Paths use the repository's tripled directory name. The pip project root is `sra-verify/sraverify/` and the package is `sra-verify/sraverify/sraverify/`, so `core/aws_errors.py` means `sra-verify/sraverify/sraverify/core/aws_errors.py`. Test paths are under `sra-verify/sraverify/sraverify/tests/`.

### This change is not atomic — plan around that too

The check-contract formalization could not run between its first base-class edit and its last check migration. This change is the opposite: the tree imports and the scanner runs after every task, and every service batch is independently shippable. What makes that possible is the strict-xfail ledger (`_PENDING`, a set of `(service, method)` pairs in each reflection test module). It starts holding every discovered pair, shrinks with every batch, and is deleted in Phase 7. A pair left in the ledger after its method is migrated is a strict XPASS and fails the run, so the ledger cannot outlive the migration.

Three ordering constraints have their own tasks because there is no second chance at any of them:

- **Phase 0 completes before Batch 1.** The gate cannot produce evidence without per-invocation stderr, the `check_done` marker (task 7), and `util/gate.py` (task 11). A batch landed before those exist is a batch that cannot be gated. The stderr comes from `util/local_scan.py`, not from CodeBuild: task 12 was written, validated, and then withdrawn, because a public template should not carry machinery whose only consumer is our own gate.
- **The IAM generator runs against the current tree before any client is edited (task 10).** Its output has been derived from nothing since the scan-context refactor. If the committed policy has already drifted from the code, that has to be known before this change adds more movement.
- **The baseline is archived before anything else (task 1).** The 2026-09-12 CSV is gitignored at the repo root and its log lives only in CloudWatch.

### Test scope resolved

Requirement 7.12: no test task in this plan is optional, and each service's contract tests land in the same task as that service's migration. The two preceding specs left 15 and 17 optional test tasks unchecked; this feature's test surface is larger than either, and the reflection tests are also the mechanism that tracks migration progress, so skipping them would remove the progress signal as well as the coverage.

### Prerequisite outside this repository

`sra-verify-mcp/awslabs/sraverify_mcp_server/server.py:293–295` calls `f.get('Status')` on `Finding` objects and raises `AttributeError` on every `run_check` tool call today. That repair is not part of this plan (Out of Scope 8), but until it lands the MCP path cannot be used to exercise any batch. Nothing here depends on it; the stdout contract is held by this repository's tests alone.

---

## Tasks

### Phase 0 — Scaffolding and gate infrastructure

No client, base, or check module is edited in this phase. Every task here is behaviour-neutral for the CSV. The full existing suite (3026 tests) passes at the end of every task, with the new reflection tests xfailed against unmigrated methods.

- [x] 1. Archive the baseline before anything else
  - [x] 1.1 Archive `sraverify-consolidated-20260912_183733.csv` and the CloudWatch log export for its build (log group `/aws/codebuild/SRAVerify-Security-Assessment`, stream `82c0c298-b731-4042-9edf-30caa152faab`) to the findings bucket under `gate/baseline/`, with SHA-256 digests
    - Use the profile that owns the findings bucket; this is a write to a non-production artefact prefix, but confirm the bucket and prefix with the user before uploading
    - Done. Bucket `sraverify-bucketsraverifyfindings-eadu4ybngb8i`, prefix `gate/baseline/`, three objects. The log group and the CodeBuild project are in **us-west-2**, not us-east-1 as this task assumed
    - _Requirements: 6.13_

  - [x] 1.2 Record the baseline the gate measures against: the object keys, digests, the commit the scan ran from (`bdad609`), and the aggregate counts — 3063 rows, 13 accounts, 4 Regions, 158 check IDs, 112 confessing FAIL rows, 8 Security Lake masked-FAIL rows. Kept with the scan artefacts under `.tmp/`, not committed: the digests refer to CSVs that are not in the repo
    - Every count reproduced from the archived CSV. One correction: the CSV holds **5** distinct `Region` values, not 4 — four AWS Regions plus `global`. The gate groups on the `Region` cell, so 5 is the figure it sees
    - _Requirements: 6.9, 6.11, 6.13_

- [x] 2. `ClientContractError`
  - [x] 2.1 Add `class ClientContractError(SRAVerifyError)` to `core/errors.py` with a docstring stating it is raised by the client guard when a success path returns a non-mapping, and that it is a programming defect, never an AWS outcome
    - The module docstring's "first three / last two" sentence was updated too; it described a two-group hierarchy and there are now three
    - _Requirements: 1.5, 1.9_

- [x] 3. `core/aws_errors.py` — the error result, the guard, the predicate
  - [x] 3.1 Create `core/aws_errors.py` exactly as the design's code block specifies
    - `ErrorDetail` and `ErrorResult` TypedDicts; `_TRANSPORT_EXCEPTIONS` (the three subclasses) and `TRANSPORT_ERROR_CODES` derived from it by `__name__`; `NO_CLIENT_CODE = "NoClient"`
    - `error_result(*, code, message, operation)` rejecting any non-`str` or blank-after-strip value with `ValueError`; `no_client_result(*, service, region, operation)`
    - `is_error(value)` strict in both directions: a `Mapping` whose `Error` is a `Mapping` whose `Code`, `Message`, and `Operation` are each a non-blank `str`. Nothing else is an error result
    - `call_aws(operation, *, region, fn)` catching exactly `ClientError` then `BotoCoreError`, each logging one `error`-level line `aws_call_failed operation=… region=… code=… message=<json.dumps(message)>`, each returning an error result; raising `ClientContractError` from outside the `try` when `fn()` returns a non-`Mapping`; catching nothing else — no `except Exception`, no `BaseException`
    - `NotConfigured` frozen slotted dataclass with required non-blank `evidence: str` and optional `message: str | None`, validated in `__post_init__`; `NotConfiguredTable` alias; `is_not_configured(table, error)` returning `False` for every undeclared operation, code, or missing needle
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.8, 1.9, 2.1, 2.2, 2.3, 2.4, 2.7, 3.7, 4.4, 4.5, 4.6, 4.6a_

  - [x] 3.2 Write `tests/unit/core/test_aws_errors.py` — 144 tests, green
    - `call_aws`: `ClientError` → error result with the response's code, message, and `operation_name`; `NoCredentialsError` and `EndpointConnectionError` → error result with the type name; `RuntimeError` inside `fn` propagates unchanged; `fn` returning `[]` raises `ClientContractError`; `fn` returning a dict returns it untouched; exactly one `error` record per failure whose message matches `^aws_call_failed operation=\S+ region=\S+ code=\S+ message="` and whose `message=` value round-trips through `json.loads`, including for a message containing `\n` and `"`
    - **Property 5: `call_aws` never catches `BaseException`** — `KeyboardInterrupt` inside `fn` propagates
    - **Property 17: the transport constant is single-sourced** — `TRANSPORT_ERROR_CODES == frozenset(t.__name__ for t in _TRANSPORT_EXCEPTIONS)`
    - `is_error`: `True` for a well-formed error result; `False` for a non-mapping, a mapping without `Error`, an `Error` that is not a mapping, and — for each of `Code`, `Message`, `Operation` — the key missing, `""`, `"   "`, and a non-`str`
    - `error_result`: raises `ValueError` for every input `is_error` would reject
    - `is_not_configured`: declared `(op, code)` without needle → `True`; with needle present in message (any case) → `True`; with needle absent → `False`; undeclared op → `False`; declared code under undeclared op → `False`; empty error dict → `False`
    - `NotConfigured(evidence="")` and `NotConfigured(evidence="  ")` raise
    - **Validates: Requirements 1.1, 1.2, 1.3, 1.8, 1.9, 2.2, 2.3, 2.4, 2.7, 4.6, 4.6a**

- [x] 4. `core/availability.py` — the offline lookup
  - [x] 4.1 Create `core/availability.py` with `service_available_in_region(service_id: str, region: str) -> bool`, `lru_cache`d, no session parameter
    - Everything that can raise — including `boto3.Session()` — inside the `try`; unknown service id → `warning` and `True`; empty regional list → `True`; any exception → `debug` and `True`; `False` only when the regional list is non-empty and omits the Region
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.8, 5.11_

  - [x] 4.2 Write `tests/unit/core/test_availability.py`
    - **Property 15: availability lookup is fail-open and partition-aware** — `("no-such-service", "us-east-1")` is `True` with a `warning` record; `("apprunner", "us-west-1")` is `False`; `("apprunner", "us-east-1")` is `True`; `("shield", r)` is `True` for every commercial Region; `("organizations", "us-gov-west-1")` is `True`; `("security-ir", "us-east-1")` is `True`; `("apprunner", "us-gov-west-1")` is `True` with the docstring recording why this differs from `WAFCheck.region_supports_service`; a second identical call does not call `boto3.Session` again (patch and count); `boto3.Session` raising inside the lookup returns `True`
    - **Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.8, 5.11, 7.8**

  - [x] 4.3 Make `WAFCheck.region_supports_service` a one-line delegate to `service_available_in_region`
    - The GovCloud App Runner answer changes from `False` to `True`; `sra_waf_06` is unaffected in the four-Region baseline. No other behaviour changes. `.tmp/verify_waf06.py` asserts the old answer and is not part of the suite; leave it
    - _Requirements: 5.10_

- [x] 5. `core/check.py` — the discriminator hook
  - [ ] 5.1 Add `NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {}`, `is_not_configured(self, error)` delegating to the module function with `type(self).NOT_CONFIGURED_ERRORS`, and `_remediation_for(self, error)` returning scan-environment wording by `Code` class (transport, `NoClient`, access-denied family, other) that names `Operation` and never composes an IAM action string from `meta.service`
    - _Requirements: 4.3, 4.4, 4.8_

  - [x] 5.2 Add the `__init_subclass__` rule: a class created in a `sra_*` module with `"NOT_CONFIGURED_ERRORS" in vars(cls)` raises `CheckIdentityError` before `register()`
    - _Requirements: 4.4_

  - [x] 5.3 Extend `tests/unit/core/test_check_registration.py` with the new rule (a synthetic `sra_*` module declaring the table fails; the registry is untouched afterward) and add `tests/unit/core/test_remediation_for.py` asserting each `Code` class produces wording containing the operation and containing no `:` between a service name and the operation
    - _Requirements: 4.4, 4.8_

- [x] 6. `ScanContext._set` backstop
  - [x] 6.1 Add the four-line guard to `core/scan_context.py`: `if is_error(value): logger.warning(...); return` ahead of the lock. Nothing else in the module changes
    - _Requirements: 3.2_

  - [x] 6.2 Write `tests/unit/core/test_scan_context_backstop.py`
    - **Property 10: `ScanContext._set` refuses an error result** — a real `ScanContext` given an error result leaves `_has` `False` and logs a `warning`; given a success dict stores it; given a malformed near-error result `{"Error": {"Code": ""}}` stores it, because `is_error` is `False` and the backstop does not guess
    - **Validates: Requirement 3.2**

- [x] 7. `main.py` — the `check_done` marker
  - [x] 7.1 Add `logger.debug(f"check_done check_id={selected_id} rows={len(findings)}")` after the per-check `list()` inside the guard's success path, and `logger.debug(f"check_done check_id={selected_id} rows=synthetic")` in the `except`. (Landed at `info`; demoted to `debug` after a production run showed 914 marker lines dominating an operator's stderr.) No other change to `main.py`
    - _Requirements: 6.3_

  - [x] 7.2 Extend `tests/unit/cli/test_exit_codes_scan.py` with one test over the `probe_scan` fixture asserting exactly one `check_done` record per probe, in execution order, with `rows=synthetic` for the raising probe
    - _Requirements: 6.3_

- [x] 8. The stdout contract — expected green against the current tree
  - [x] 8.1 Write `tests/property/test_stdout_contract_property.py`
    - **Property 20: the library entry point writes nothing to stdout** — reuse `probe_scan`; install a `_RaisingStdout` whose `write`/`writelines` raise via `monkeypatch.setattr(sys, "stdout", ...)`; `run_checks()` over the three probes plus a fourth whose mock client returns an error result completes and returns four `Finding`s; `run_checks(check_id="SRA-TYPO-99")` raises `UnknownCheckError` with the stream never called; `show_progress=True` *does* call the stream, proving the test can see a write
    - **Property 21: no library module can write to stdout** — AST over `core/`, `services/`, `utils/outputs.py`, and `__init__.py` with its docstring stripped: no `print` call, no `sys.stdout` / `sys.__stdout__` attribute, no `warnings.warn`, no `logging.StreamHandler` or `logging.basicConfig` outside `core/logging.py`; at runtime the root logger has one handler on `sys.stderr` and every `sraverify` handler is on `sys.stderr`
    - Both halves must pass here, before any client or base is edited. A failure at this step is a pre-existing leak and is fixed in this task
    - Both halves pass against the current tree: **no pre-existing stdout leak**. The only `print()` in a library module is inside `__init__.py`'s module docstring, which the AST sees as a `Constant` and not a `Call`, so no source-text stripping was needed. `core/logging.py` is the only handler-constructing module
    - One deviation from the design: the root-logger assertion (Requirement 8.8) runs in a **subprocess**. pytest's logging plugin attaches `LogCaptureHandler`, `_LiveLoggingNullHandler`, and a `/dev/null` `_FileHandler` to the root logger, so "exactly one handler" is not observable in-process; asserting it under pytest would mean weakening it to something that no longer detects the regression it exists for
    - **Validates: Requirements 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8**

- [x] 9. The reflection test modules, the adapter tables, and the ledger
  - Every module snapshots its discovered set at import, parametrizes with ids of the form `<service>.<Class>.<method>` or `<service>.<operation>.<code>`, and asserts the snapshot is non-trivially sized. Every module carries `_PENDING: frozenset[tuple[str, str]]` and a hook applying `pytest.mark.xfail(strict=True, reason="pending batch N")` to ids whose pair is in it
  - **Done.** 92 client adapters and 99 accessor adapters, all 18 services; Property 3a passes for every service in both directions. Suite: 6448 passed, 990 xfailed, **0 failed, 0 xpassed**
  - **Deviation, and it matters.** The ledger is one shared module, `tests/property/_migration_ledger.py`, not a `_PENDING` constant per test module. The reason is that a single pending set would be wrong in both directions: the pre-migration tree does not violate the properties uniformly, so a set that marked everything would produce strict XPASS, and a set that marked nothing would fail. The ledger therefore carries **one set per property**, each *measured* by running the property with the ledger neutralised rather than predicted. Requirement 7.10a's per-`(service, method)` granularity is preserved and strengthened — it is now per `(property, service, method)`
  - Measured pre-migration failure counts, which are the shape of the work remaining: Properties 1/2 fail for all 92 client methods; Property 3 for 50; Property 4 for 37; constructor-only acquisition for exactly the 6 clients Requirement 1.11 names; Property 7 for 64 of 70 accessors (the 6 being the 2 reference implementations plus 4 that cache nothing); Property 8 for all 71; Property 9 for 5
  - **New finding worth acting on: 45 checks *raise* when handed an error result** where they index or iterate the list their accessor used to return — `securitylake` 15 of 17, `cloudtrail` 13 of 13, `securityhub` 6, `config` 4, `securityincidentresponse` 3, `macie` 2, `accessanalyzer` 1, `inspector` 1. Recorded as `CHECKS_CRASHING_ON_AN_ERROR_RESULT`. Each would contribute one synthetic ERROR row and lose its other Regions' rows if a client were migrated without its checks in the same change. This is independent confirmation of the batch boundary the design chose
  - Two harness bugs found and fixed while calibrating, both of which would have made a property pass vacuously: the mock context's `_has` was pinned to `False`, so "a failed call is re-issued" and "a warm cache skips the client" were measuring the mock rather than the accessor (replaced with a real dict-backed cache); and `inspect.cleandoc` was used to dedent method source, which only fixes the first line (replaced with `textwrap.dedent`)
  - **`_PENDING` starts holding every discovered pair, including the two reference client methods and the two guarded accessors.** The references return `{"Error": {"Code", "Message"}}` with no `Operation`, so the strict `is_error` does not recognize their error result and Property 1 fails for them until their service's batch.
  - _Requirements: 7.9, 7.10, 7.10a, 7.11_

  - [x] 9.1 Write `tests/property/test_client_contract_property.py`
    - Discovery: `pkgutil.iter_modules` over `sraverify.services`, import `<svc>.client`, classes named `*Client`, public functions via `inspect.getmembers`
    - `ClientAdapter` dataclass (`method`, `args`, `boto_attr`, `boto_method`, `operation`, `success`) and one adapter table per service — all 18, written now against the current method signatures. The `success` shape is the boto3 response the method reads, which migration does not change
    - **Property 3a: the adapter table is complete and exact** (client half) — per service, `{a.method} == discovered` both ways, with the missing and stale names in the assertion message
    - **Property 1: every client method returns an error result on `ClientError`** — including the single `aws_call_failed` record assertion
    - **Property 2: every client method returns an error result on any `BotoCoreError`** — `EndpointConnectionError` and `NoCredentialsError`
    - **Property 3: programming defects propagate; contract violations are named** — `RuntimeError` propagates; closure returning `[]` raises `ClientContractError`
    - **Property 4: every client method returns a non-error result dict on success**
    - **Property 6: no client method returns an erasing value or a bool** — static: no `Try` in any `client.py`; every `get_client(` call inside `__init__`; every `call_aws` first argument a string literal; no `bool` return annotation; `is_access_analyzer_available` absent from `services/`
    - **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 1.10, 1.11, 1.12, 2.1, 2.2, 2.3, 2.6, 5.9, 7.1, 7.2, 7.3, 7.4, 7.4a, 7.10, 7.11**

  - [x] 9.2 Write `tests/property/test_accessor_cache_property.py`
    - Discovery: every public method in `vars(<Service>Check)` — the class's own dict, not a source-text heuristic
    - `AccessorAdapter` dataclass (`method`, `kind` ∈ {`accessor`, `helper`, `table`}, `args`, `client_method`) and one table per service, all 18 written now. `helper` entries are asserted never to touch `self._ctx`; `table` is `NOT_CONFIGURED_ERRORS`
    - **Property 3a: the adapter table is complete and exact** (accessor half) — `{a.method} == vars(cls) public methods` both ways
    - **Property 7: every accessor refuses to cache an error result and re-issues** — `_set` not called; error result returned unchanged; second call re-invokes the client method — the once-per-caller cost Requirement 3.5 accepts, observed directly
    - **Property 8: every accessor produces `NoClient` and does not cache it** — `check._clients` empty
    - **Property 9: successful responses are cached under the same namespace and key** — `_set` once with the service `NAMESPACE`, the adapter's key, and the success dict itself; a warm `_has` skips the client
    - **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 7.5, 7.10, 7.11**

  - [x] 9.3 Write `tests/property/test_discriminator_property.py`
    - **Property 11: `is_not_configured` is total and conservative** — over every service's `NOT_CONFIGURED_ERRORS`, every declared fact returns `True` for its operation and code (and a message containing its needle); the same code under an undeclared operation, an undeclared code, a declared needle absent from the message, and an empty error dict all return `False`; hypothesis over `cell_text()` for the message cases
    - **Property 11a: every table entry carries evidence, and no placeholder survives** — every value is a `NotConfigured` with non-blank `evidence`; for every service with no pair remaining in `_PENDING`, no `evidence` begins `TO CONFIRM`
    - **Property 12: the discriminator table is declared once per service** — `"NOT_CONFIGURED_ERRORS" not in vars(cls)` for every registered check; the value read through the check equals its service base's
    - **Validates: Requirements 4.2, 4.3, 4.4, 4.5, 4.6, 4.6a, 7.7**

  - [x] 9.4 Write `tests/property/test_check_classification_property.py`
    - **Property 14: every check yields only ERROR when every accessor fails non-semantically** — catalog-wide over `all_checks()`; mock context with `regions=["us-east-1"]`, non-empty audit and log-archive account lists, warm `get_account_info`; every `accessor`-kind method on the service base (from 9.2's tables) patched to return `error_result(code="TestDenied", message="denied", operation=<name>)`; availability lookup patched to `True`; `list(check.execute())` yields at least one `Finding`, all `Status.ERROR`, every `actual_value` matching `^\S+ failed: TestDenied: `, no exception
    - **Property 14a: discriminated error results yield FAIL** — for every service with a non-empty table and every check consuming a declared operation, a matching error result yields at least one FAIL and nothing PASS
    - **Property 14b: an unsupported Region yields no row and no call** — for every check calling `service_available_in_region`, with the lookup patched to `False`, `execute()` yields nothing and no accessor is called
    - **Validates: Requirements 4.1, 4.2, 4.3, 4.8, 4.9, 4.12, 5.5, 5.6, 7.5a**

  - [x] 9.5 Write `tests/property/test_no_confessing_fail_property.py`
    - **Property 13: no confessing `failed()` and no `except`-to-`failed()`** — AST over every `sra_*` module: no `self.failed` whose `actual_value` literal or f-string literal portions match the Requirement 4.7 patterns or interpolate an `except ... as` name; no `Try` inside `execute` containing `self.failed`
    - **Property 6a: no check module reaches the SDK directly or catches inside `execute()`** — no `session.client`, `_ctx.get_client`, `boto3.client`, `boto3.Session` attribute chains; no `Try` anywhere inside `execute`
    - The seven current `except` sites (`accessanalyzer_02/03/04`, `config_09`, `cloudtrail_08/09/10`) and the 25 confessing modules are in `_PENDING` for this module by module name until their batch
    - **Validates: Requirements 2.8, 4.7, 4.11, 7.5b, 7.6**

  - [ ] 9.6 Write `tests/property/test_availability_property.py`
    - **Property 16: availability call sites name a literal** — every `service_available_in_region(` call in `services/` passes a string literal in the Requirement 5.7 candidate set
    - **Property 18: test identifiers name the target** — a fixture inspecting `request.node.callspec.id` in every parametrized test of the modules above
    - **Property 19: the contract tests are offline** — an autouse fixture in `tests/conftest.py` patching `botocore.httpsession.URLLib3Session.send` to raise; the whole suite still passes
    - **Validates: Requirements 5.7, 7.9, 7.11**

- [x] 10. `util/generate_iam_policy.py` — make it see the tree again, before the tree moves
  - [x] 10.1 Extend the generator to bind `self.<attr> = ctx.get_client('<service>', ...)` in `__init__` to its service and attribute every `self.<attr>.<method>(` and `self.<attr>.get_paginator('<method>')` in the module to that service; treat the `call_aws` first-argument literal as a cross-check against the receiver method's PascalCase form and warn on mismatch
    - Rewritten to attribute by AST rather than by regex. It also binds a **local** assignment (`sts_client = self.ctx.get_client("sts")`), not only an attribute one, so the eight in-method acquisitions Requirement 1.11 has yet to move are still attributed — without that, Shield would lose four services' worth of actions until Batch 6
    - It now exits non-zero with an explanation if it attributes nothing at all, which is the failure it shipped in silently
    - _Requirements: 1.12_

  - [x] 10.2 Write `tests/unit/util/test_generate_iam_policy.py` asserting the exact action set derived for `WAFClient` (nine services) and `ShieldClient` (five) against the current tree
    - 22 tests. Both exact action sets asserted in both directions, plus a per-module assertion that every client binds at least one boto3 client — so a single client changing its acquisition form is caught rather than only the all-or-nothing case
    - _Requirements: 1.12_

  - [x] 10.3 Run the generator against the current tree and diff against `generated_sraverify_iam_policy.json` and `generated_sraverify_cf_policy.yaml`
    - Any difference means the committed policy has already drifted from the code. Report it to the user before proceeding; do not silently regenerate the artefacts here
    - **The pre-rewrite generator emitted `{"Statement": []}` — an empty policy.** Requirement 1.12's claim that "its current output is derived from nothing" is exact: nothing in the tree has used `session.client(...)` since the scan-context refactor, so it matched zero call sites. "Generated policy unchanged" has not been evidence of anything for some time
    - **After the rewrite both artefacts are byte-identical to the committed files.** So the committed action set has *not* drifted in content — 78 actions across 29 boto3 services, matching exactly. The committed artefacts are correct; only the generator was broken
    - Two deliberate non-changes, to keep the comparison meaningful: no acronym normalisation (`GetWebAcl` is left as-is rather than corrected to `GetWebACL` — IAM matches case-insensitively, and normalising would put a 7-action diff into a deployed policy for no functional gain), and no trailing newline on the JSON. Both are noted in the code with the reasoning
    - One pre-existing oddity observed and left alone: `Cognito-idpPermissions` and `Security-irPermissions` are not valid IAM Sids, which must be alphanumeric. Harmless, because `1-sraverify-member-roles.yaml` carries hand-written statements rather than this snippet
    - _Requirements: 1.12_

- [x] 11. `util/gate.py` — the acceptance gate, tested before it is trusted
  - [x] 11.1 Write `util/gate.py`: parse two consolidated CSVs and two `stderr/` directories; parse `check_done` and `aws_call_failed` lines (the latter's `message=` via `json.loads`); derive check→operation dependencies statically by AST (check module → accessor names → base accessor → client method → `call_aws` literal); group in-scope rows as multisets under (`AccountId`, `AccountType`, `Region`, `CheckId`); pair exact → unique non-blank `ResourceId` → sorted admitted transition; judge per Requirement 6 criteria 4–8; masked-FAIL sweep; totals; SHA-256 of every input; non-zero exit listing offending keys and rows
    - One deliberate design decision worth recording: the gate keeps its **own** copy of the semantic-code table rather than importing `NOT_CONFIGURED_ERRORS` from the candidate tree. If it imported them, a *wrong* table entry would admit exactly the rows that entry caused — the code under test would be grading its own answer
    - It also duplicates the 16-column `FIELDS` tuple rather than importing `Finding.FIELDS`, because it runs against artefacts produced by another commit's code and importing would check the wrong tree's idea of the schema
    - Evidence matching requires the failure to name the **same Region** as the row, not just the same operation. Without that, a four-Region scan logging four failures in one check's window would admit a transition in the Region that actually succeeded
    - `--notes` writes the batch gate note, including every input's SHA-256, so a decision is re-derivable from immutable artefacts
    - _Requirements: 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 6.8, 6.9, 6.10, 6.11, 6.12, 6.13, 6.15_

  - [x] 11.2 Write `tests/unit/util/test_gate.py` against synthetic CSV pairs and stderr sets covering every admitted transition and every rejected one: PASS→FAIL rejects; FAIL→ERROR admits with matching `aws_call_failed` evidence and rejects without; ERROR→FAIL admits only for the listed check IDs; multi-row groups (three ALBs) pair correctly including one added; blank and duplicate `ResourceId` pair deterministically and identically on two runs; out-of-scope service difference rejects; masked-FAIL sweep catches a FAIL with a non-semantic `aws_call_failed`; `message=` with an embedded newline parses
    - 54 tests, green. Every case above plus: all four PASS transitions; FAIL→ERROR rejected when the evidence is semantic, when the operation is not a dependency, and when the failure names another Region; the `us-west-1`/App Runner removed-row admission against the real availability lookup; a reordered column; and each of the seven metadata cells rejecting on change
    - _Requirements: 6.2, 6.4, 6.5, 6.6, 6.7, 6.8, 6.10, 6.15_

  - [x] 11.3 Delete `.tmp/diff2.py` and `.tmp/impact.py` once 11.2 passes; they are the gate's ancestors and are superseded
    - _Requirements: 6.15_

- [~] 12. `2-sraverify-codebuild-deploy.yaml` — per-invocation stderr capture — **WITHDRAWN, not shipping**

  The edit was written and validated, then **reverted**. `2-sraverify-codebuild-deploy.yaml` is unchanged by this feature.

  **Why.** The template is published in a public repository, and the artefact it added exists only to feed `util/gate.py` — a development tool. Putting machinery in front of every downstream user of this template, for the sole benefit of our own acceptance gate, is the wrong trade. Anyone who needs per-invocation stderr can get it from a local run: `util/local_scan.py` produces exactly the layout the gate expects, in one process on one machine.

  **What it would have cost, and no longer does.** The CodeBuild CloudWatch log would have stopped carrying sraverify's own `WARNING`/`ERROR` lines inline. The replay step put them back, but an operator debugging a scan would still have had a second place to look.

  **What was lost: nothing the gate needed.** All twelve gate scans in this feature ran locally anyway, for an independent reason recorded under "Why the gate scans run locally" below — the buildspec clones from GitHub, so a CodeBuild-based gate would have needed twelve public pushes. The two reasons point the same way.

  - 12.1 — done, then reverted. `aws cloudformation validate-template` accepted it and the extracted build block was `bash -n` clean, so the revert is a scope decision, not a retreat from a broken change.
  - 12.2 — **not run.** It needed approval to start a build against the deployed project; with 12.1 reverted there is nothing to validate.
  - _Requirements: 6.3 — satisfied by `util/local_scan.py` instead, which produces per-invocation stderr without touching deployed infrastructure_

- [x] 13. Checkpoint — Phase 0 gate
  - Run the full suite: 3026 existing tests plus everything above pass; every reflection test for an unmigrated pair reports `xfail`, none `xpass`
  - Run `util/gate.py` with the same consolidated CSV and stderr directory on both sides: zero differences, zero rejections
  - Confirm `git diff --stat` touches nothing under `services/`
  - Ask the user if questions arise
  - **All three met.** Suite: **6524 passed, 9 skipped, 990 xfailed, 0 failed, 0 xpassed** (from a 3026 baseline). The gate self-comparison against the archived 3063-row baseline CSV reports zero differences and totals that match the recorded baseline exactly — 3063 rows, 112 confessing FAIL, 158 check IDs, 0 synthetic, 1762/1286/15 PASS/FAIL/ERROR
  - `git diff --stat -- services/` touches exactly one file, `waf/base.py`, which is task 4.3's deliberate delegate. No client, no check, and no other base is edited
  - One observation from the self-comparison worth carrying forward: the archived baseline log yields **zero** `aws_call_failed` records, because the pre-change code emitted hand-written `WARNING` prose instead. The gate's evidence path is therefore untested against a real scan until task 12 lands and a scan runs with the new structured records
  - Task 12 is **not** done and is the one Phase 0 item outstanding: it edits and deploys a live CodeBuild project and needs explicit approval

---

### Design change: no shared `call_aws` guard — decided 2026-09-15

The design specified `call_aws`, a helper in `core/aws_errors.py` that ran a
closure and wrote the two `except` clauses once for all 92 client methods. After
4 methods were migrated, this was reconsidered and **rejected** on the grounds
that a reader of `client.py` should see the error handling at the call site
rather than a lambda handed to a function in another module. The added layer
was judged more likely to confuse than the repetition it saved.

**What replaces it.** Every client method carries its own plain `try`/`except`:

```python
def get_detector_details(self, detector_id: str) -> Mapping[str, Any]:
    try:
        return self.client.get_detector(DetectorId=detector_id)
    except AWS_EXCEPTIONS as e:
        return self.aws_error(e)
```

`ClientContractError` is deleted; it existed only for the guard's non-dict check,
and the contract test now catches a non-dict return.

Cost accepted: two identical clauses in every method. Suite after the change:
**6620 passed, 0 failed, 0 xpassed**, with GuardDuty fully migrated.

### Design change: `AWSClient.aws_error(e)`, no per-call-site arguments — decided 2026-09-15

The first draft of the above had each handler call
`sentinel_from(e, operation="GetDetector", region=self.region)`, a module-level
function in `core/aws_errors.py`. Three objections, taken in order, reduced that
to `self.aws_error(e)`:

**The name.** `sentinel_from` describes the return type, not the situation. The
handler now reads as what it is: this was an AWS error, turn it into one.

**`operation=`.** Asked whether the literal could come from the calling function
instead, since a hand-typed string can disagree with the method it labels. A probe
settled it: botocore sets `operation_name` on **every** `ClientError`, so the
literal was redundant where it agreed and silently wrong where it did not — and
nothing at runtime could tell which, making it the one value in the client tier no
test could defend. It is now read from the exception. Rejected along the way:
introspecting botocore's `_make_api_call` traceback frame (works, but clever), and
an optional override for multi-client wrappers (rejected as "multiple ways to do
it").

**`region=`.** Every client already stores its Region, so the parameter was noise
with a failure mode — a copy-pasted method could log a Region that succeeded. It
now comes from `self.region`.

That left `aws_error` needing `self`, which is what motivated a small
`AWSClient` base class in `core/aws_client.py` holding `region`, `ctx`, and
`aws_error`. Every `<Service>Client` inherits it and chains `super().__init__`.

**The one asymmetry, and why it is acceptable.** A `BotoCoreError` carries no
operation, because the request never completed. Rather than reintroduce a
parameter for that case alone — the "multiple ways to do it" objection again — those
error results carry `UNKNOWN_OPERATION = "Request"`. Verified safe on three counts
before adopting it: a transport code is never semantic for any operation, so the
placeholder cannot produce a fabricated FAIL; botocore's own message names the
endpoint, so the row still says which service and Region could not be reached; and
the gate matches evidence on service and Region, with `explains()` treating the
placeholder as evidence for any operation the check depends on.

Two consequences outside the clients. `util/generate_iam_policy.py` loses
`collect_operation_literals` and `cross_check_literals` — there is no literal left
to cross-check, and a check that cannot fail is not coverage. `util/gate.py`'s
`derive_dependencies` now derives operations from boto3 method names alone, which
also made its comparison case-insensitive: `get_web_acl_for_resource` PascalCases
to `GetWebAclForResource` while AWS reports `GetWebACLForResource`, and a
case-sensitive compare silently dropped every Shield and WAF record.

**What holds the repetition to the contract.** The dynamic half is unchanged:
Properties 1–4 drive every method through a simulated `ClientError`,
`EndpointConnectionError`, `NoCredentialsError`, and `RuntimeError`. The static
Property 6 is *sharper* than the guard design allowed, because it reads each
`except` clause directly: the handler must catch exactly `AWS_EXCEPTIONS`, its body
must be the exact string `return self.aws_error(e)`, nothing may be passed to
`aws_error` beyond the exception, and the class must inherit `AWSClient` and chain
`super().__init__`. A handler that catches too little, too much, a typed service
exception, or returns anything else fails at the line that introduces it. "No
`try` in any client" was the guard-specific rule and is gone.

Suite after this second change: **6647 passed, 3 skipped, 935 xfailed, 0 failed,
0 xpassed**.

The design and requirements documents still describe `call_aws`, `sentinel_from`,
and `ClientContractError`; they are historical and are not being rewritten. These
two notes, plus the module docstrings in `core/aws_client.py` and
`core/aws_errors.py`, are the record.

### Terminology: "sentinel" became "error result" — decided 2026-09-15

Renamed after Batch 1, before Batch 2, because the word was wrong and the cost of
fixing it scales with the number of migrated services.

A *sentinel* is conventionally a placeholder standing in for absence — `None`,
`-1`, a unique object. The value this contract introduces is the opposite of a
placeholder: a structured record carrying the AWS code, message, and operation,
which exists precisely so that a failure stops being represented by absence. The
name was inherited from the design it replaced, where the alternative really was a
bare `{}`, and it stopped describing anything once the builder became `aws_error`
and the predicate `is_error`.

| Was                                   | Is                          |
| ------------------------------------- | --------------------------- |
| `ErrorSentinel`                       | `ErrorResult`               |
| `error_sentinel()`                    | `error_result()`            |
| `no_client_sentinel()`                | `no_client_result()`        |
| `is_error()`, `AWSClient.aws_error()` | unchanged — already correct |
| prose "the error sentinel"            | "the error result"          |

54 source files and all three spec documents. **Behaviour-neutral and verified as
such**: 6663 passed / 3 skipped / 935 xfailed / 0 failed / 0 xpassed both before
and after, the two IAM artefacts still reproduce byte-for-byte, and the Batch 1
gate still admits with the same 7 verdicts.

Three uses of the word were **kept**, because they are the correct conventional
sense, and finding them is why this was not a blind search-and-replace:

- `services/iam/client.py` — `"__global__"` is a sentinel *cache key* standing in
  for "no region".
- `tests/unit/core/test_select.py` — `"all"` is a sentinel *account-type* meaning
  "do not filter", not a value to match.
- `tests/property/test_no_accumulator_property.py` — `_sentinel_helper` is a
  placeholder function standing in for a re-created `create_finding`.

Two cleanups landed with it. `TRANSPORT_EXCEPTIONS` became
`_TRANSPORT_EXCEPTIONS`: nothing outside the module consumed the exception
classes, its only job being to derive `TRANSPORT_ERROR_CODES`. And the docstring
claim that the derived set "replaces the hand-written constant in
`services/waf/client.py`" was corrected to say it does not yet — `sra_waf_06`
still imports `TRANSPORT_ERROR_CODES` from that module, the two agree today, and
Batch 6 removes the copy. A standing drift risk, not a live defect.

**Spec documents updated.** `requirements.md` and `design.md` each gained a
"Superseded during implementation" section recording all three design changes (no
shared guard, `aws_error(e)` with no parameters, no `ClientContractError`).
`requirements.md` criteria 1.5, 2.5, and 7.3 were **amended**, because a normative
criterion referencing a class that was never shipped is actively wrong rather than
merely stale. `design.md`'s module inventory was corrected to list
`core/aws_client.py` and to strike `ClientContractError`; its `call_aws` section
and Decision points 1 and 4 are marked superseded in place and retained as the
record of the reasoning, and Part II carries a reading note that "route through
`call_aws`" now means the plain handler.

### How the gate scans actually run — decided 2026-09-15

The design assumed the CodeBuild project would produce both scans of every gate
pair. It cannot, without a change nobody wants: its buildspec does
`git clone -b $GIT_BRANCH https://github.com/awslabs/sra-verify.git`, so every
scan runs code that has been pushed to a **public** repository — and the gate needs
twelve of them.

**Resolution: the gate scans run locally, from the working tree**, via a new
`util/local_scan.py`. The gate does not care where its inputs came from; it needs a
consolidated CSV and per-invocation stderr files, and that script produces both in
the layout `util/gate.py` expects. It also makes the reference/candidate window
*tighter* than CodeBuild can — two runs minutes apart on one machine, rather than
two builds that each re-clone and re-install.

Verified end to end before Batch 1: four invocations (one per account type) across
the four available profiles produce 268 rows over one Region, covering **all 158
check IDs** and **158 `check_done` markers**, and `util/gate.py` self-compares them
with zero differences.

Two limitations, recorded because they bound what the gate can prove:

- **Credentials are broader than production.** `SRAMemberRole`'s trust policy is
  conditioned on `SRAVerifyCodeBuildServiceRole` and cannot be assumed from a local
  Admin profile, so these scans run with Admin. Fewer calls are denied, so fewer
  ERROR rows appear — including the `securitylake:ListSubscribers` denial behind the
  8 measured masked-FAIL rows. A reference/candidate comparison is still sound
  because both sides use the same credentials, but Batch 3 needs the targeted
  restricted-permission run the design's Manual Validation section describes.
- **Coverage is 4 of the org's 13 accounts** — one per account type, which is what
  drives check selection. A check that only fails in one of the other nine is not
  exercised.

The `2-sraverify-codebuild-deploy.yaml` edit stays in the repo (Requirement 6.3
asks for it, and it makes the deployed pipeline gate-able for whoever next deploys)
but is **not deployed**, so task 12.2 stays open.

---

### Phases 1–6 — Service batches

The same procedure for every batch. Each service in a batch is one sub-task; the gate is the batch's final sub-task.

Per service:

1. **`client.py`.** The class inherits `AWSClient` and its `__init__` chains `super().__init__(region, ctx)`. Every `ctx.get_client()` moves to `__init__`. Every method body becomes a plain `try` around the boto3 call and any pagination it already has, returning a named-key dict, with exactly one handler:

   ```python
   except AWS_EXCEPTIONS as e:
       return self.aws_error(e)
   ```

   Nothing is passed to `aws_error` but the exception — no `operation=`, no `region=`. Delete every existing `try`/`except`, every typed `self.client.exceptions.*` catch, every probe, and any private classifier (`_log_aws_failure`). Add no pagination.
2. **`base.py`.** Every accessor: hit → `no_client_result` on missing wrapper → call → `is_error` guard → `_set` → return the dict unchanged. Declare `NOT_CONFIGURED_ERRORS` with a `NotConfigured(evidence=...)` per entry, seeded from the design's per-service table; a `TO CONFIRM` placeholder is allowed only until this batch's gate, and is replaced with an observed log line or deleted before landing. Add pure helpers over a success dict where several checks share an extraction.
3. **Checks.** `"Error" in result` before any success key; `self.is_not_configured(result["Error"])` → `failed()` naming the condition, else `error()` with `actual_value=f"{Operation} failed: {Code}: {Message}"` and `remediation=self._remediation_for(error)`; availability guard at the top of the region loop where the service is a candidate; every confessing `failed()` becomes `error()` or a discriminated `failed()`; every `except` inside `execute()` removed.
4. **Ledger.** Remove this service's `(service, method)` pairs and module names from every `_PENDING`. Suite green with no `xpass`.
5. **Gate.** Scan the reference commit (last commit before the batch) and the candidate commit back to back with the CodeBuild project; run `util/gate.py` scoped to the batch's services; keep its notes file with the scan artefacts, carrying both commit hashes, artefact keys, digests, any discriminated-wording changes declared for criterion 5, every re-run and its outcome; land only on zero rejections, and record the verdict and totals in this file.

- [x] 14. Batch 1 — guardduty
  - [x] 14.1 Migrate `services/guardduty/client.py` (4 methods)
    - `get_detector_id` returns `{"DetectorIds": [...]}`; the `"ERROR:..."` string is gone. `get_detector_details`, `describe_organization_configuration`, `list_organization_admin_accounts` get the plain handler. `Message` from `e.response`, not `str(e)`
    - _Requirements: 1.1, 1.3, 1.4, 1.5, 1.10, 1.11, 2.1, 2.2_

  - [x] 14.2 Migrate `services/guardduty/base.py` (4 accessors)
    - `get_detector_id` passes the dict through and stops caching `None`; `detector_id_of(success_dict) -> Optional[str]` helper. `get_detector_details` calls `get_detector_id` internally, returns its error result unchanged on failure, else reads the ID for its own call. Table: `DescribeOrganizationConfiguration` → `BadRequestException` with evidence from the GuardDuty API reference and the existing `_15`/`_16`/`_20`–`_25` behaviour
    - _Requirements: 1.5, 3.1, 3.2, 3.4, 3.7, 4.4, 4.6a_

  - [x] 14.3 Migrate the 25 GuardDuty checks
    - `_02`–`_12`, `_17`–`_19`: "Unable to retrieve detector details" → `error()`. `_01`: error result → ERROR; empty `DetectorIds` → FAIL. `_14`: `BadRequestException` + "not the master account" stays ERROR with its remediation; not in the table. `_15`, `_16`, `_20`–`_25`: inline `BadRequestException` test → `is_not_configured`
    - _Requirements: 4.1, 4.2, 4.3, 4.7, 4.8, 4.9_

  - [x] 14.4 Ledger and gate for Batch 1
    - Remove guardduty pairs from `_PENDING`; suite green. Reference/candidate scans; `util/gate.py --services GuardDuty`. Expected: the 14 confessing modules produced zero rows in the baseline (GuardDuty was healthy), so the visible change is the `_15`/`_16`/`_20`–`_25` FAIL wording and any ERROR `ActualValue` reformatting
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 6.8, 6.9, 6.12, 6.13, 6.14, 7.10a, 7.12_
    - **GATE ADMITTED.** 891 rows both sides, 7 admitted, 0 rejected, 0 needing re-run, 0 synthetic.
    - The expectation held exactly: the 14 confessing modules produced zero rows (GuardDuty is healthy in all four Regions), and the only change is the FAIL wording for `_16` and `_20`–`_25`. `_15` hits the same condition but already worded it well, so the candidate log holds **8** `aws_call_failed` records against 7 changed rows
    - Those 8 records are the first structured evidence the gate has had to parse from a real scan — the archived baseline yields zero, because the pre-change code logged prose
    - **`candidate_error` is 0**: local Admin credentials deny nothing, so this pair does not exercise the FAIL→ERROR transition at all. Batch 3's restricted-permission run is where that gets tested
    - **The gate needed one fix.** Its first run rejected 20 out-of-scope rows, none in GuardDuty and none a regression: 4 live AWS timestamps (`SRA-CLOUDTRAIL-08`/`-09`/`-10`, `SRA-CONFIG-03`) and 8 set-iteration orderings (`SRA-MACIE-07`, `SRA-SECURITYHUB-08` — the known set-join defect). Added `normalise_volatile`, applied by `row_tuple`: timestamps tokenised, account IDs tokenised plus a digest of the sorted multiset, so reordering compares equal while changed membership does not. 10 new tests in `test_gate.py`, one of which caught a real non-idempotence defect in the first draft. Without this the same 20 rows would have been reported in every remaining batch

- [x] 15. Batch 2 — macie, securityhub
  - [x] 15.1 Migrate `services/macie/client.py` (16 handlers, 8 methods)
    - `get_account_id` moves `sts` acquisition to `__init__`. The 14 erasing handlers that recognize `AccessDeniedException` / "Macie is not enabled" and return `{}` are deleted; the reference method's hand-written handlers become `self.aws_error(e)` too, so it emits `Operation`
    - _Requirements: 1.1, 1.4, 1.5, 1.6, 1.10, 1.11, 2.1, 2.2_

  - [x] 15.2 Migrate `services/macie/base.py` (7 accessors)
    - Table: `ResourceNotFoundException` and `AccessDeniedException` ["macie is not enabled"] declared for `GetClassificationExportConfiguration`, `GetFindingsPublicationConfiguration`, `DescribeOrganizationConfiguration`, `GetAdministratorAccount`, `ListMembers`, each with evidence (the API reference for `ResourceNotFoundException`; the 2026-09-12 log line for the overloaded `AccessDeniedException`). `is_macie_disabled_error` becomes a one-line delegate, deleted in Phase 7
    - _Requirements: 3.1, 3.2, 3.7, 4.4, 4.5, 4.6a_

  - [x] 15.3 Migrate the 10 Macie checks
    - `_01`, `_02`, `_08`, `_10`: "Failed to retrieve" → discriminated FAIL or `error()`. `_07`, `_09`: same for members/accounts. `_03`, `_04`: `is_not_configured`. `_07`'s set-join untouched. Availability guard `"macie2"`
    - _Requirements: 4.1, 4.2, 4.3, 4.7, 4.8, 5.5, 5.7_

  - [x] 15.4 Migrate `services/securityhub/client.py` (16 handlers, 8 methods)
    - The `None` tri-state is gone: `get_enabled_standards` and `list_enabled_products_for_import` return the response dict or an error result. `describe_organization_configuration`'s silent `except` is gone with the rest
    - _Requirements: 1.1, 1.4, 1.5, 1.6, 1.8, 1.10, 2.1, 2.2_

  - [x] 15.5 Migrate `services/securityhub/base.py` (9 accessors)
    - `get_enabled_standards` / `get_enabled_products_for_import` drop the `is None` branches. `get_organization` stops building and caching its own error result (it writes the shared `organizations` namespace). Table: `GetEnabledStandards` and `ListEnabledProductsForImport` → `InvalidAccessException` ["not subscribed to aws security hub"], evidence from the Security Hub API reference
    - _Requirements: 3.1, 3.2, 3.4, 3.7, 4.4, 4.5, 4.6a_

  - [x] 15.6 Migrate the 11 Security Hub checks
    - `_02`: "Unable to retrieve" → `error()`. Consumers of the two tri-state accessors: `is None` → `is_not_configured`
    - _Requirements: 4.1, 4.2, 4.3, 4.7, 4.8_

  - [x] 15.7 Ledger and gate for Batch 2
    - Expected: 104 of the 112 baseline confessing rows (MACIE-01 ×51, -02 ×51, -08 ×4, -10 ×4 … and SECURITYHUB-02 ×2) change verdict or wording; every FAIL→ERROR must show `aws_call_failed` evidence; MACIE-03/-04's 52 FAILs each stay FAIL
    - _Requirements: 6.1, 6.2, 6.4, 6.5, 6.6, 6.8, 6.9, 6.12, 6.13, 6.14, 7.10a, 7.12_

    - **GATE ADMITTED.** 891 rows both sides, 44 admitted, 0 rejected, 0 needing re-run, 0 synthetic.
    - **Every confessing FAIL row in the organization is now gone: 18 -> 0.** All 18 that survived Batch 1 belonged to these two services; 8 became honest ERROR rows and the rest became FAIL rows stating the real reason
    - The discriminator's value is demonstrated cleanly here. Two `AccessDeniedException`s from `macie2` in the same account and Region: `ListMembers` + "Macie is not enabled" -> **FAIL**, `DescribeOrganizationConfiguration` + "you must be the Macie administrator" -> **ERROR**. Verified against the raw AWS CLI. The pre-migration client mapped both to `{}` and both were reported as FAIL, so a code-only table could not have worked
    - **New finding: erasure also manufactured false PASSes, and Non-Goal 2 is amended.** `SRA-SECURITYHUB-09` reported PASS ("No Security Hub member accounts found") for two Regions where Security Hub is not enabled at all -- `list_members` returned `[]` on any `ClientError` and `if not securityhub_members: yield self.passed(...)` read that as an empty answer. The requirements' 120-row/3.9% impact floor counted only *confessing FAIL* rows, so this class was never sized, and it is strictly worse: nobody investigates a pass
      - Resolved as **FAIL** per the standing FAIL-versus-ERROR rule (AWS answered; the control is absent). Needed `ListMembers` -> `BadRequestException` with needle `no such resource found` in the table -- the needle is load-bearing, because `securityhub` also returns that code for an invalid input parameter, which must stay an ERROR
      - `util/gate.py` gained `ADMITTED_PASS_TO_FAIL`, a module constant beside `ADMITTED_ERROR_TO_FAIL` and reviewed the same way. It admits PASS -> FAIL only for a declared check **and only with a *semantic* record in evidence** -- stricter than the FAIL -> ERROR rule, which wants a non-semantic one, because a PASS -> FAIL asserts AWS established the control is absent
      - **Expect this in Batches 4-6.** 22 sites across 8 services test an accessor's return for emptiness and yield PASS (`waf` 9, `shield` 4, `firewallmanager` 3, `macie` 3, `guardduty` 1, `iam` 1, `securityhub` 1). Most are legitimate, but pre-migration every one was reachable from a failed call
    - **The gate caught three defects in this batch's own migration**, none of them visible to the test suite: `SRA-SECURITYHUB-04`/`-10`/`-11` invented new `CheckedValue` text instead of reusing each check's existing string; `SRA-MACIE-07`'s guard dropped the Region from its `ResourceId`; and criterion 5 was too narrow, admitting a declared FAIL wording change only when `ActualValue` moved alone. A discriminated FAIL states a different reason and the advice follows it, so criterion 5 now admits `{ActualValue, Remediation, ResourceId}` for a declared check. Batch 1 never hit that because GuardDuty's seven checks happened to keep identical remediation text
    - Suite: **6975 passed, 2 skipped, 750 xfailed, 0 failed, 0 xpassed**

- [x] 16. Batch 3 — securitylake
  - [x] 16.1 Confirm the `UnauthorizedException` semantics against a controlled account before editing the table
    - Run `sraverify --check SRA-SECURITYLAKE-01 --debug` against an account with Security Lake not enabled in a Region and capture the `aws_call_failed` code. If `UnauthorizedException` is observed with a "not enabled" message, record the line as the evidence string; if not, the `UnauthorizedException` entries are omitted and the code resolves to ERROR
    - _Requirements: 4.6a_

  - [x] 16.2 Migrate `services/securitylake/client.py` (15 handlers, 10 methods)
    - `_log_aws_failure` deleted. `is_security_lake_enabled` (probe) becomes `list_data_lakes` → `{"dataLakes": [...]}`. `get_sqs_queue_encryption` moves `sqs` acquisition to `__init__`. Every typed `ResourceNotFoundException` catch deleted; the code reaches the table
    - _Requirements: 1.1, 1.4, 1.5, 1.6, 1.7, 1.10, 1.11, 2.1, 2.2, 2.6_

  - [x] 16.3 Migrate `services/securitylake/base.py` (10 accessors, 19 `_set` sites)
    - Six accessors stop caching `[]`/`{}`/`None`/`False` on failure and on no-client; `_prime_region_log_sources` stops seeding `[]` on failure; `is_security_lake_enabled` answers the bool after the guard. Table per the worked example, with `_RNF` evidence from the API reference and `_UNAUTH` resolved per 16.1
    - _Requirements: 3.1, 3.2, 3.4, 3.7, 4.4, 4.6a_

  - [x] 16.4 Migrate the 17 Security Lake checks
    - `_16`, `_17` per the worked example: error result → discriminated FAIL or ERROR; the confident "is not set up as query access subscriber" wording stays for a genuinely empty list. Availability guard `"securitylake"` (17/34)
    - _Requirements: 4.1, 4.2, 4.3, 4.8, 4.9, 5.5, 5.7_

  - [x] 16.5 Ledger and gate for Batch 3
    - Expected: the 8 baseline `SECURITYLAKE-16/17` FAIL rows become ERROR with `ListSubscribers failed: AccessDeniedException: …` and matching evidence in the audit account's stderr; Property 11a passes with no `TO CONFIRM` in the securitylake table
    - _Requirements: 6.1, 6.2, 6.4, 6.5, 6.6, 6.9, 6.10, 6.12, 6.13, 6.14, 7.10a, 7.12_

    - **16.1 confirmed, and it overturned the design's assumption.** The design expected `UnauthorizedException` from any `securitylake` operation to mean "Security Lake is not enabled here", and the pre-migration client acted on it (`_log_aws_failure` demoted it to `debug`). Checked against a controlled account on 2026-09-15: **`UnauthorizedException` does occur, but not where the design placed it and not with the meaning it assumed.** It appears on `GetDataLakeSources` (observed as `UnauthorizedException: Unauthorized` from the log-archive account, which is not the delegated administrator) and *not* on `ListDataLakes` or `ListSubscribers`. Either way it is a permission fact about the caller, not a statement that no data lake exists, so it stays an ERROR. From an account that is not the delegated administrator, both `ListDataLakes` and `ListSubscribers` answer `AccessDeniedException: The request failed because you don't have sufficient permissions to perform this operation for your organization.` That is a permission failure, so an **ERROR** -- declaring it would have fabricated a FAIL for every non-delegated-administrator account
      - `NOT_CONFIGURED_ERRORS` therefore declares only `ResourceNotFoundException`, for the five operations whose pre-migration code already caught it as a typed exception. `AccessDeniedException` is deliberately absent, and that absence is what converts the tree's **only measured masked-FAIL rows** (8, on `SRA-SECURITYLAKE-16`/`-17`) into ERROR
    - Client, base, and all 17 checks migrated; securitylake removed from the ledger. Suite: **7143 passed, 2 skipped, 625 xfailed, 0 failed, 0 xpassed**

  - [x] 16.6 **Three regressions the gate caught — all fixed**
    - The candidate scan produced **843 rows against the reference's 891**, and **924 `aws_call_failed` records against 64**. Both trace to the same file and both are mine, not pre-existing
    - **(a) `SRA-SECURITYLAKE-01` collapses 52 rows to 4 in the log-archive account.** The check fans out one row per active organization account (13 accounts x 4 Regions). My `get_data_lake_sources` guard sits *above* that loop, so a failed `GetDataLakeSources` yields one ERROR per Region instead of one row per account. Fix: move the guard inside the per-account loop, or emit one ERROR row per account carrying that account's `resource_id`, so the row count and the per-account resource identity both survive. The row key is what a consumer diffs, so collapsing is not acceptable even though the verdict is honest
    - **(b) 832 redundant `ListLogSources` calls.** `_prime_region_log_sources` used to seed `[]` into every account's cache slot on failure; I removed that so a failure is not fabricated as "no sources configured". Correct in principle, but it means every one of the 8 log-source checks x 13 accounts x 4 Regions re-issues the call -- 832 where there were ~16, which is throttling territory. Fix: record the failure **once per Region** in a dedicated slot (`log_sources_error:{region}` holding the error result) and have `check_log_source_configured` consult that slot before calling. That avoids both the re-issue storm and the fabricated per-account `[]`
    - **(c) related gap, same area:** `SRA-SECURITYLAKE-06`..`-13` call `check_log_source_configured`, which returns a bare `bool` and so cannot report a log-source failure at all. Only their `get_organization_accounts` call is guarded. They need an error-bearing log-sources accessor to guard on before using the predicate -- otherwise a denied `ListLogSources` still reads as "source not configured", which is the same masked-FAIL shape this batch was meant to remove, just moved. **Measured:** a log-archive scan of one Region yields 104 FAIL rows saying "<source> is not configured for account X" while the log records `ListLogSources/AccessDeniedException` for that Region -- so this batch has not yet removed the masked FAILs, it has relocated them from `_16`/`_17` to `_06`..`_13`
    - _Requirements: 3.4, 4.1, 4.7, 6.2_

    - **GATE ADMITTED.** 891 rows both sides, **492 admitted, 0 rejected**, 0 needing re-run, 0 synthetic — and **no `--wording-changed` declarations were needed**, because every difference is a FAIL -> ERROR the gate matched against a non-semantic log record on its own.
    - **484 rows moved FAIL -> ERROR**, mostly 52-row blocks (13 accounts x 4 Regions) on `_01`, `_06`..`_13`, plus `_05`, `_16`, `_17`. FAIL fell 641 -> 149; ERROR rose 8 -> 500
    - For scale: the whole feature was justified by a measured **120** confessing rows org-wide. This one service produced **484** rows stating findings the scan never established. The 120 counted only rows whose *wording* confessed; these did not confess at all, which is why that figure was always described as a floor
    - Caveat on the number: local Admin profiles mean the log-archive account is denied more Security Lake calls than production `SRAMemberRole` from the audit account would be. The shape of the correction is real; the exact count is specific to this credential arrangement. The restricted-permission run is still outstanding
    - All three regressions fixed and verified: `_01` now fans its failure out per account (891 rows restored); the new error-bearing `get_log_sources` accessor gives one shared cached slot so failure records fell 924 -> **124**; and all eight log-source checks now guard it, closing the gap where 104 measured FAIL rows still said "not configured" while `ListLogSources` was denied
    - The lesson worth keeping: a bare `bool` from a base accessor cannot carry the distinction this feature exists to preserve. `check_log_source_configured` had *relocated* the masked FAILs from `_16`/`_17` to `_06`..`_13` rather than removing them
    - Suite: **7148 passed, 2 skipped, 625 xfailed, 0 failed, 0 xpassed**

- [x] 17. Batch 4 — s3, inspector, accessanalyzer
  - [x] 17.1 Migrate `services/s3/` (2 handlers, 1 accessor, 4 checks)
    - `get_public_access_block` returns `{"PublicAccessBlockConfiguration": {...}}` or an error result; the `NoSuchPublicAccessBlockConfiguration` collapse is gone. Table: `GetPublicAccessBlock` → `NoSuchPublicAccessBlockConfiguration` with S3 Control API reference evidence. `_01`–`_04`: discriminated FAIL keeps "No public access block configuration found"; `AccessDenied` → ERROR
    - _Requirements: 1.5, 1.6, 3.1, 4.1, 4.2, 4.4, 4.6a, 4.9_

  - [x] 17.2 Migrate `services/inspector/` (8 handlers, 5 accessors, 11 checks)
    - `get_account_status` reads the account from `{"accounts": [...]}` after the guard; `_01`–`_04` require a real `state.status` for FAIL. `list_organization_accounts` stays first-page-only (Requirement 1.13). Availability guard `"inspector2"` (32/34)
    - _Requirements: 1.5, 1.13, 3.1, 4.1, 4.3, 4.9, 5.5, 5.7_

  - [x] 17.3 Migrate `services/accessanalyzer/` (9 handlers, 2 accessors, 4 checks)
    - `is_access_analyzer_available` deleted; `_setup_clients` registers every Region unconditionally. `_02`: `self.session.client('organizations')` and its bare `except` → `failed()` removed, routed through `get_delegated_admin`. `_03`, `_04`: bare `except` → `error()` removed. `_01`: `[]` on `AccessDenied` → ERROR. Table: `ListDelegatedAdministrators` → `AWSOrganizationsNotInUseException`. No availability guard (34/34)
    - _Requirements: 1.7, 2.8, 3.1, 4.1, 4.9, 4.11, 5.9_

  - [x] 17.4 Ledger and gate for Batch 4
    - This batch's purpose is gate step 7, the masked-FAIL sweep: every `S3-01`–`04`, `INSPECTOR-01`–`04`, and `ACCESSANALYZER-01` FAIL in the candidate must have no non-semantic `aws_call_failed` in its window. Record the count of masked FAILs found; it is the first measurement of the ceiling the requirements call unknowable
    - _Requirements: 6.1, 6.2, 6.4, 6.6, 6.9, 6.10, 6.12, 6.13, 6.14, 7.10a, 7.12_

    - Clients, bases and 18 of 19 checks migrated (`sra_accessanalyzer_02` needed a full rewrite rather than a guard: it reached `self.session.client('organizations')` **directly** and wrapped the whole body in `except Exception:` whose handler yielded a **FAIL** naming the exception, so a denied `ListDelegatedAdministrators` and a genuinely absent delegated administrator produced the same finding). `try`/`except` removed from `_03` and `_04` as well
    - **The Access Analyzer availability probe is deleted, not converted.** It issued a live `ListAnalyzers` per Region purely to answer a bool, and `_setup_clients` registered a client **only if the probe said yes** — so one transport blip silently removed a whole Region from the scan and every check then reported it as unconfigured. `accessanalyzer` has an endpoint in 34 of 34 Regions, so the probe could never legitimately say no
    - **Extraction moved out of two Inspector accessors into pure helpers** (`account_status_of`, `status_by_account`), per Requirement 1.5. The second matters: `batch_get_account_status` previously wrapped each 10-account batch in a bare `except Exception` that logged at `debug` and carried on, so a denied call produced a **partial** map indistinguishable from a complete one — and an account missing from it read as "not enrolled". Batches now fail as a whole
    - `s3`'s table declares `NoSuchPublicAccessBlockConfiguration` and deliberately **not** `AccessDenied`; those are the two codes `s3control` overloads onto `GetPublicAccessBlock`, and mapping both to `{}` is what made `SRA-S3-01`..`-04` report "No public access block configuration found" with no tell in the CSV
    - `accessanalyzer`'s table is **empty**, deliberately: an account with no analyzer is a *successful* `ListAnalyzers` returning `[]`, so every error from these operations is an inability to determine. The pre-migration code had this backwards
    - Suite: **6406 passed, 1 failed** in the property suite

  - [x] 17.5 **Resolved: `SRA-ACCESSANALYZER-04`'s account guard deleted (option 2)**
    - `test_a_check_yields_only_error_when_every_accessor_fails[SRA-ACCESSANALYZER-04]` fails, and it is a genuine tension rather than a defect in the migration
    - `_04` opens with a scan-configuration guard: if `--audit-account` was supplied and the scanned account is not one of them, it yields **one global ERROR** row, "Invalid account for IAM Access Analyzer check: Account X is not an audit account", and returns **before touching any accessor**. The property-test fixture sets `account_id=111122223333` and `audit_accounts=[<other>]`, so the guard always fires under test
    - That row is correct by every project rule — wrong/missing required input is an ERROR, reported once with `region="global"`, with scan-environment remediation. But it **names no operation**, because none was attempted, and the test asserts every ERROR row matches `^\S+ failed: <Code>: `
    - Three options, none yet taken:
      1. **Narrow the test's premise** so the operation-shape assertion applies only when an accessor was actually consulted. Correct in principle — if no accessor was reached, the "every accessor failed" premise never held — but my first attempt at detecting that broke ~20 pending-service xfails, so it needs doing carefully
      2. **Delete `_04`'s account guard** as redundant: the check is `account_type=audit`, so `--account-type` selection already restricts it, and `SRA-ACCESSANALYZER-03` performs the audit-account comparison as its actual purpose. This is a row-count change in a real scan, so it needs the gate's judgement
      3. Exempt the one check in the ledger — least attractive, since the ledger is deleted in Phase 7
    - _Requirements: 4.1, 4.8, 7.14_

    - **GATE ADMITTED with zero differences.** 891 rows both sides, 0 admitted, 0 rejected, 0 needing re-run, 0 synthetic. PASS 242 / FAIL 149 / ERROR 500 — identical to Batch 3 in every cell.
    - The cleanest outcome a batch can have: three services migrated, a probe deleted, extraction restructured, and the report did not move. Every erasure removed here sits on a path this organization does not currently exercise under these credentials, so the corrections are latent. With production `SRAMemberRole` the `s3` and `accessanalyzer` fixes would be expected to surface real FAIL→ERROR transitions
    - **The gate caught three defects in this batch's own migration:**
      1. `SRA-ACCESSANALYZER-04` collapsed 4 Region rows into 1 — the **same** "guard above the fan-out" mistake as `SRA-SECURITYLAKE-01` in Batch 3, made independently. Worth adding to the authoring guide as a named trap (task 23)
      2. `SRA-INSPECTOR-07` lost a legitimate PASS in all four Regions. `inspector2:GetDelegatedAdminAccount` answers `ValidationException: Invoking account is the delegated admin.` when the caller *is* the delegated admin — not a failure, not "not configured", but the answer stated as a refusal. Handled with a dedicated `InspectorCheck.caller_is_delegated_admin` predicate; a `NOT_CONFIGURED_ERRORS` entry would have made a correctly-configured org **FAIL**. **This is the clearest evidence so far that the discriminator's two buckets are not exhaustive** — some AWS errors are facts about the caller
      3. `SRA-ACCESSANALYZER-04`'s account-validation guard removed (option 2, user's call): it emitted the catalog's only ERROR row naming no operation, and re-litigated `--account-type` selection inside the check
    - Suite: **7284 passed, 2 skipped, 511 xfailed, 0 failed, 0 xpassed**

- [x] 18. Batch 5 — config, cloudtrail, ec2
  - [x] 18.1 Migrate `services/config/` (22 handlers, 5 accessors, 9 checks)
    - `get_account_id`, `get_management_account_id` → response dicts; `get_bucket_location` → `{"LocationConstraint": ...}`; `get_bucket_policy` → `{"Policy": "<json>"}`; `sts` acquisition to `__init__`. Aggregator methods stay first-page-only. `_01`, `_02`: "status could not be determined" → `error()`. `_09`: bare `except` around `describe_configuration_aggregator_sources_status` removed
    - _Requirements: 1.5, 1.11, 1.13, 3.1, 4.1, 4.7, 4.11_

  - [x] 18.2 Migrate `services/cloudtrail/` (8 handlers, 3 accessors, 13 checks)
    - `describe_trails` → `{"trailList": [...]}`; `sts` to `__init__`. `_11`: "bucket owner could not be determined" → `error()`. `_08`, `_09`, `_10`: `except (ValueError, TypeError)` → `failed()` becomes `CloudTrailCheck.parse_delivery_time(value) -> Optional[datetime]` with `error()` on `None`; a FAIL→ERROR flip on a branch the baseline never exercised, declared for gate criterion 6
    - _Requirements: 1.5, 1.11, 3.1, 4.1, 4.7, 4.10, 4.11_

  - [x] 18.3 Migrate `services/ec2/` (4 handlers, 1 accessor, 1 check)
    - Mechanical; `sts` to `__init__`
    - _Requirements: 1.5, 1.11, 3.1, 4.1_

  - [x] 18.4 Ledger and gate for Batch 5
    - After this batch every one of the 25 confessing modules is migrated; gate step 8's confessing-FAIL count must be zero and Property 13 has no remaining pending module names
    - _Requirements: 6.1, 6.2, 6.4, 6.6, 6.9, 6.11, 6.12, 6.13, 6.14, 7.10a, 7.12_

    - Clients and bases migrated for all three services; all 23 checks have their accessor guards; ledger updated. Suite: **7509 passed, 16 failed**
    - `cloudtrail` is the service that justifies the batch boundary most clearly: **all 13 of 13 checks iterate or index the trail list**, so all 13 *raise* on an error result rather than mis-reporting it. Migrating the client alone would have converted each into one synthetic ERROR row and discarded every row it had already yielded for other Regions
    - Guards for `get_trail_status` in `_07`..`_10` sit **inside** the per-trail loop, so one undetermined trail costs one row rather than the check's whole output — the fan-out trap from Batches 3 and 4, avoided deliberately this time
    - `config`'s table declares `AWSOrganizationsNotInUseException` (`DescribeOrganization`) and `NoSuchBucketPolicy` (`GetBucketPolicy`) and **nothing for the `describe_*` operations**, because Config having no recorder, channel or aggregator is a *successful* empty list rather than an error. `ec2`'s table is empty for the same reason — `GetEbsEncryptionByDefault` answers a boolean
    - `get_bucket_location`'s `None` → `us-east-1` mapping moved to `ConfigCheck.bucket_region_of`, a pure helper over a success dict. It had to move: the client returned `None` for both "the bucket is in us-east-1" and "the call failed", so a caller writing `location or 'us-east-1'` would have silently treated a denial as us-east-1

  - [x] 18.5 **All 16 resolved — the four groups are closed**
    - None is damage from the migration; each is a check-body defect the new guards have now exposed. Scoped and grouped:
    - **(a) `except` inside `execute()` — 4 checks.** `cloudtrail/_08`, `_09`, `_10`, `config/_09` still catch exceptions inside `execute()`, which the contract forbids: the orchestrator's guard is the only place that may. Remove the handlers; the accessor guards above them now cover the AWS failures they were catching
    - **(b) Confessing FAIL wording — 6 checks.** `cloudtrail/_08`, `_09`, `_10`, `_11`, `config/_01`, `_02` still contain genuine confessing rows, e.g. `"' exists but status could not be determined"` at `config_01:182`. These are the *original* rows the feature exists to remove, and their ledger entries were dropped when the services were marked migrated. Each needs converting to `error()` naming the operation and code, or to a discriminated `failed()`
    - **(c) A post-loop global FAIL fires when every Region errored — 5 checks.** `SRA-CONFIG-04`, `-05`, `-07`, `-08`, `-09` end with "No organization aggregator found in any region" (or the delegated-administrator equivalent). With every Region undetermined that verdict rests on nothing. `_09` is already fixed via an `undetermined` flag; `_04` and `_05` use `if <flag>: ... else: <global FAIL>` and need the same treatment (my scripted attempt aborted on an ambiguous anchor, so nothing was written); `_07`/`_08` sit outside a Region loop and need checking separately
    - **(d) One adapter entry.** `ConfigCheck.bucket_region_of` is a new public base method and needs an `A(..., "helper", ...)` declaration in `test_accessor_cache_property.py`, like `detector_id_of` and `account_status_of`
    - Once these land: full suite green, then scan and gate against Batch 4's candidate
    - _Requirements: 4.1, 4.7, 4.9, 7.14_

    - **GATE ADMITTED with zero differences.** 891 rows both sides, 0 admitted, 0 rejected, 0 synthetic — identical to Batch 4 in every cell, the second batch running to land verdict-for-verdict unchanged.
    - **The gate found a pre-existing `NameError`.** Its first run rejected on a synthetic row: `SRA-CLOUDTRAIL-09` referenced `latest_delivery_time`, which the module never defines (`_10` had the identical bug). Both were invisible before, because the surrounding `except (ValueError, TypeError)` did not catch `NameError` — it propagated and became a synthetic ERROR row for the whole check. Removing that handler is what surfaced it. An AST sweep for unresolved local names now reports **0 across all 158 checks**
    - Three genuine confessing FAIL rows converted to ERROR (`config_01`, `config_02`, `cloudtrail_11`): AWS answered but its answer was silent about the thing asked, so undetermined rather than absent
    - `cloudtrail/_08`,`_09`,`_10`'s `except (ValueError, TypeError)` was catching a *malformed timestamp*, not an AWS failure — still forbidden inside `execute()`, so the parse moved to `CloudTrailCheck.parse_delivery_time`, which answers `None`. `config_09`'s `except Exception` around a direct client call became an error-result guard
    - Five Config checks ended with a global "not found in any region" verdict that fired even when every Region errored. Each now tracks `undetermined` and returns; `SRA-CONFIG-09` needed an extra return or it fell through to a client lookup with `org_aggregator_region` still `None`
    - Suite: **7527 passed, 2 skipped, 307 xfailed, 0 failed, 0 xpassed**

- [x] 19. Batch 6 — waf, firewallmanager, shield, organizations, iam, account, auditmanager, securityincidentresponse
  - [x] 19.1 Migrate `services/waf/` (14 handlers, 9 accessors, 9 checks)
    - 11 code-dropping handlers → `self.aws_error(e)`; the `{"WebACL": None}` and `{"LoggingConfiguration": None}` synthesized responses gone, `WAFNonexistentItemException` reaches the table for `GetWebACLForResource` and `GetLoggingConfiguration`. `TRANSPORT_ERROR_CODES` import in `sra_waf_06` moves to `core.aws_errors` and the module-local constant is deleted. `region_supports_service` delegate removed in favour of direct `service_available_in_region` calls. Availability guards `"amplify"` (20/34) and `"appsync"` (31/34) added beside `"apprunner"`
    - _Requirements: 1.1, 1.6, 2.7, 3.1, 4.4, 5.5, 5.7, 5.10_

  - [x] 19.2 Migrate `services/firewallmanager/` (2 handlers, 2 accessors, 10 checks)
    - The `ResourceNotFoundException` handler that rewrote the message and dropped the code → `self.aws_error(e)`; table: `GetAdminAccount` → `ResourceNotFoundException`. `_01`'s hardcoded Region untouched
    - _Requirements: 1.1, 1.6, 3.1, 4.4_

  - [x] 19.3 Migrate `services/shield/` (7 handlers, 4 accessors, 14 checks)
    - `lambda`, `cloudfront`, `wafv2`, `cloudwatch` acquisition to `__init__`; `get_web_acl_for_resource` chooses between two held attributes. `Message` normalization changes every Shield ERROR `ActualValue`. The synthesized `WAFNonexistentItemException` for a CloudFront distribution with no `WebACLId` stays. `list_protections` stays first-page-only. Table: five operations → `ResourceNotFoundException`, `GetWebACLForResource` → `WAFNonexistentItemException`
    - _Requirements: 1.3, 1.11, 1.13, 3.1, 4.4_

  - [x] 19.4 Migrate `services/organizations/`, `services/iam/`, `services/account/`, `services/auditmanager/`
    - Organizations: already canonical; `AWSClient` adoption, transport coverage, five accessors stop caching the error result; table: `DescribeOrganization` → `AWSOrganizationsNotInUseException`, `ListPolicies` → `PolicyTypeNotEnabledException`. IAM: `Code="UnknownError"` gone with the catch-all; `list_users` stops caching the error result. Account: `Message` normalization; table: `GetAlternateContact` → `ResourceNotFoundException`. Audit Manager: the return-less handler → `self.aws_error(e)`; confirm the "Please complete AWS Audit Manager setup" code against a not-yet-set-up account before declaring the table entry, and omit it if unconfirmed; the existing `NoClient` error-result shape stays
    - _Requirements: 1.1, 1.3, 1.4, 1.10, 3.1, 3.4, 4.4, 4.6a_

  - [x] 19.5 Migrate `services/securityincidentresponse/` (6 handlers, 1 `_set` accessor plus five delegating accessors, 5 checks)
    - Client: `AWSClient` adoption with `BotoCoreError` coverage; `_discover_memberships`'s `except Exception` becomes dead and is removed; the fallback tuple stops caching an error result; `get_organization_accounts` stops collapsing `"Error"` to `[]`. `_04`: "no active memberships" ERROR → discriminated FAIL, the listed ERROR→FAIL flip. Table: `GetRole` → `NoSuchEntity`. Region resolution untouched (Non-Goal 6)
    - _Requirements: 1.1, 2.1, 3.1, 3.2, 4.4, 4.10_

  - [x] 19.6 Ledger and gate for Batch 6
    - Largest `ActualValue` churn on ERROR rows (the `str(e)` → response-message normalization); lowest verdict risk. Declare the SIR-04 ERROR→FAIL flip for criterion 6. After this gate, `_PENDING` is empty in every module
    - _Requirements: 6.1, 6.2, 6.4, 6.5, 6.6, 6.9, 6.12, 6.13, 6.14, 7.10a, 7.12_

---

### Phase 7 — Close

- [x] 20. Delete the ledger
  - [x] 20.1 Remove `_PENDING` and the xfail hook from every reflection test module; suite green with zero `xfail` and zero `xpass`
    - _Requirements: 7.10a_

- [x] 21. Delete the transitional code
  - [x] 21.1 Delete `MacieCheck.is_macie_disabled_error`; confirm `_log_aws_failure`, `is_access_analyzer_available`, `TRANSPORT_ERROR_CODES` in `waf/client.py`, and `region_supports_service` are gone; confirm `grep -rn "except\|try:" services/*/client.py` returns nothing and `grep -rn "get_client(" services/*/client.py` matches only `__init__` bodies
    - _Requirements: 1.10, 2.2, 5.10_

- [x] 22. Regenerate the IAM policy artefacts
  - [x] 22.1 Run `util/generate_iam_policy.py`; the output is expected to equal the committed artefacts except that `accessanalyzer:ListAnalyzers` no longer appears from the probe — it still appears from `SRA-ACCESSANALYZER-01`, so the action set is unchanged. Any other difference is investigated, not committed. `1-sraverify-member-roles.yaml` unchanged
    - _Requirements: 1.12_

- [x] 23. Steering and developer documentation
  - [x] 23.1 `creating_checks_best_practices.md`: replace the "Client method" canonical shape with the `AWSClient` / `self.aws_error(e)` form; add the discriminator table with its evidence rule, the check-body pattern, and the constructor-only acquisition rule; add `NOT_CONFIGURED_ERRORS` to the identity rules; remove the `securitylake_16/17`, `_log_aws_failure`, and Access Analyzer probe entries from Known Defects; Logging section becomes the Stdout_Contract with a pointer to `test_stdout_contract_property.py`
    - _Requirements: 8.9_

  - [x] 23.2 `structure.md`: same canonical-shape replacement; `core/aws_errors.py`, `core/availability.py`, `util/gate.py`, and the new test modules in the tree; the `_set` backstop under ScanContext; `main.py`'s `check_done` line under the orchestrator
    - _Requirements: 8.9_

  - [x] 23.3 `tech.md`: `util/gate.py` under Commands with its two-scan procedure; the buildspec's `stderr/` artefacts under Deployment; Logging section becomes the Stdout_Contract; the pagination deferrals under Known inconsistencies
    - _Requirements: 8.9_

  - [x] 23.4 `sra-verify/sraverify/README.md`: the client and accessor contract, `AWSClient.aws_error`, and the discriminator table in the developer guide
    - _Requirements: 8.9_

- [x] 24. Inventory regeneration
  - [x] 24.1 Regenerate `sra-verify/docs/checks.txt` with the console script and `cmp` against the committed file; expected identical, since no `CheckMeta` changed
    - _Requirements: 6.8_

- [x] 25. Final gate
  - [x] 25.1 One reference/candidate pair with all batches landed — reference is the last commit before Batch 1, candidate is HEAD — through `util/gate.py` unscoped. Totals: confessing FAIL count zero, 158 check IDs, zero synthetic rows. Archive as `gate/final/` and record the before/after FAIL and ERROR counts here
    - _Requirements: 2.5, 6.9, 6.11, 6.12, 6.13_

- [x] 26. Final checkpoint
  - Ensure all tests pass, every batch gate note records zero rejections, and the final gate has admitted the migration. Ask the user if questions arise.

## Notes

- **No test task is optional.** Requirement 7.12 forbids it, and the reflection tests double as the migration's progress tracker: an unmigrated method is an `xfail`, a migrated one left in the ledger is a failure. Removing the tests would remove the signal.
- **This change ships in batches; the check-contract formalization did not.** Every task leaves an importable tree and a runnable scanner. A batch that cannot pass its gate is reverted or fixed, not carried.
- **Two tasks touch infrastructure or deployed configuration.** Task 1.1 writes to the findings bucket; task 12 edits and deploys the CodeBuild template. Both need explicit approval before the write.
- **Three table entries need live confirmation before they are declared.** Security Lake `UnauthorizedException` (task 16.1), Audit Manager's setup-required code (task 19.4), and any entry whose only evidence is an existing docstring. An unconfirmed entry is omitted; the code then resolves to ERROR, which is the safe default.
- **Out of scope, and no task generates them**: pagination for the five first-page-only methods; `securityincidentresponse` Region resolution; the `sra_macie_07` set-join and `sra_firewallmanager_01` literal Region; the MCP server's `f.get('Status')` repair; deleting the four `get_account_id` duplicates in favour of `ScanContext.get_account_info()`; yielding partial rows when a check raises; a cassette-style replay gate; any change to the CLI's stdout output.
