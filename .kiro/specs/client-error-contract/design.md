# Design Document: Client Error Contract

## Overview

The scanner reports on 158 controls through a three-tier error model: clients catch, checks classify, the orchestrator contains. The model is sound and the middle tier is well specified — `passed()`, `failed()`, and `error()` are keyword-only, FAIL-versus-ERROR is a documented product principle, and the check-contract formalization made a malformed row impossible to construct. What that work did not touch is the input to the middle tier. A check can only classify an error it has been handed, and 100 of the 144 exception handlers in the client layer hand it nothing: they return `{}`, `[]`, `None`, or a bare boolean, and the AWS error code and message are gone before `execute()` runs.

This design closes that gap by making one shape mandatory at the client tier and one predicate mandatory at the check tier. Every `<Service>Client` method returns a dict — a named-key success dict on success, `{"Error": {"Code", "Message", "Operation"}}` on failure — from a plain `try`/`except` that catches `ClientError` and `BotoCoreError`, hands the exception to `AWSClient.aws_error(e)`, and lets anything else propagate as the programming defect it is. *(As built. This document specifies a single shared guard, `call_aws`; see "Superseded during implementation" below.)* Every `<Service>Check` base accessor passes that dict through unchanged and refuses to cache an error result. Every service base class declares a table of `(operation, code)` pairs that mean "not configured", read by one shared predicate, `is_not_configured`, so two checks reading the same error result cannot disagree. An offline regional-availability lookup in `core/` lets a check skip a Region where the service has no endpoint before it issues a call there. And a reflection-driven contract test suite enumerates every client method and every accessor, so the next handler that erases an error fails a test rather than a scan.

The prototype exists and is validated. Commit `bdad609` brought `MacieClient.get_classification_export_configuration` and `WAFClient.list_services` to this contract, held 52 FAIL rows on each of `SRA-MACIE-03` and `-04` at FAIL while correcting their stated reason, and recovered three `SRA-WAF-06` rows that a transport failure had been discarding. This design generalizes that to every method of all 18 clients (the two reference clients still carry 14 and 11 non-conforming handlers respectively), every accessor on the 18 base classes, and every check that consumes them, in six service batches, each gated by a keyed CSV comparison reconciled against the build log.

One property rides along. The scanner is a library behind an MCP server that talks over stdio, so the library must never write to stdout. Today that holds by convention. This design touches every client and base module and adds three diagnostic paths, so it also adds the two tests that turn the convention into a contract (Requirement 8, Properties 20 and 21) and lands them in Phase 0, before the first module is edited.

Two things this design deliberately does not do. It does not centralize the FAIL-versus-ERROR judgement across services — the mapping is a function of `(operation, code)` and it stays declared per service — and it does not change how the orchestrator handles a check that raises. Once no client raises for an AWS outcome, a synthetic ERROR row is evidence of a programming defect in some tier, and that signal is worth keeping sharp; which is also why the client guard does not catch `Exception`.

---

## Superseded during implementation

This document is the design as decided before implementation. Three things were
decided differently once the migration was under way, and the record of why is in
`tasks.md` under two dated "Design change" notes. Everything else here — the
three-tier model, the discriminator table and its evidence rule, the accessor
shape, the availability lookup, the reflection test strategy, the batch
boundaries, and the acceptance gate — was built as specified.

| This document says | As built |
| --- | --- |
| A single shared guard, `call_aws(operation, *, region, fn)`, wraps a closure and writes the two `except` clauses once for all 92 methods | A plain `try`/`except` in every method, whose one line is `return self.aws_error(e)` |
| The error result is built by a module-level function taking `operation=` and `region=` | Built by `AWSClient.aws_error(e)`, a method on a base class every client inherits, taking **only** the exception |
| A non-mapping success return raises `ClientContractError` at runtime | No such class; Property 4 asserts the `Mapping` return per method, so it fails before it ships |
| The value is called a **sentinel** | Called an **error result** — `ErrorResult`, `error_result()`, `no_client_result()`, `is_error()` |

Why each changed, briefly:

**The guard.** Rejected on the judgement that a reader of `client.py` should see
the error handling at the call site rather than a lambda handed to a function in
another module. The repetition was accepted as the cheaper cost. Sections
[`call_aws`](#call_aws) and [Decision point 1](#decision-point-1--one-shared-guard-versus-three-except-clauses-per-method)
below argue the opposite conclusion and are retained as the record of the
reasoning, not as a description of the tree.

**The two keyword arguments.** `operation=` was removed after a probe confirmed
botocore sets `operation_name` on every `ClientError`: a hand-typed literal was
redundant where it agreed with the call it labelled and silently wrong where it did
not, and nothing at runtime could tell the difference — making it the one value in
the client tier no test could defend. `region=` was removed because every client
already stores its Region, so the parameter was noise with a failure mode (a
copy-pasted method logging a Region that succeeded). Removing both is what made a
base class necessary, and what makes the handler byte-identical everywhere.

The asymmetry this leaves: a `BotoCoreError` carries no operation, because the
request never completed. Those error results carry `UNKNOWN_OPERATION = "Request"`
rather than reintroducing a parameter for one case. Verified safe on three counts —
a transport code is never semantic for any operation, so the placeholder cannot
produce a fabricated FAIL; botocore's message names the endpoint, so the row still
says what could not be reached; and the gate's `explains()` treats a record
carrying it as evidence for any operation the check depends on.

**`ClientContractError`.** It existed only for the guard's non-mapping check.
With no guard there is no single place to make that check at runtime, and 92
copies of an `isinstance` would duplicate what the contract suite already asserts
once per method.

Two knock-on simplifications outside the clients, both recorded here because they
removed code this document specifies: `util/generate_iam_policy.py` lost
`collect_operation_literals` and `cross_check_literals` (there is no literal left
to cross-check, and a check that cannot fail is not coverage), and
`util/gate.py`'s `derive_dependencies` now derives operations from boto3 method
names alone — which also made its comparison case-insensitive, since
`get_web_acl_for_resource` PascalCases to `GetWebAclForResource` while AWS reports
`GetWebACLForResource`.

---

## Motivation

Every figure below is measured against the current tree or against `sraverify-consolidated-20260912_183733.csv` (13 accounts, 4 Regions, 3063 rows), not estimated. The audit scripts are in `.tmp/audit_clients.py` and `.tmp/impact.py`; the endpoint probe in `.tmp/availability_probe.py`.

### Three error-result shapes coexist, and most handlers use none of them

| Failure shape returned                       | Handlers | Clients                                                                                                                                     |
| -------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `{"Error": {"Code", "Message"}}`             | 30       | organizations 5/5, shield 7/7, securityincidentresponse 6/6, iam 3/3, account 1/1, guardduty 2/4, macie 2/16, waf 3/14, auditmanager 1/2    |
| `{"Error": {"Message"}}` — code dropped      | 13       | waf 11, firewallmanager 2                                                                                                                   |
| `"ERROR:{code}:{msg}"` — a string            | 1        | guardduty `get_detector_id`                                                                                                                 |
| Bare `{}` / `[]` / `None` / `True` / `False` | 100      | config 22, securityhub 16, securitylake 15, macie 14, accessanalyzer 9, cloudtrail 8, inspector 8, ec2 4, s3 2, guardduty 1, auditmanager 1 |
| **Total**                                    | **144**  |                                                                                                                                             |

Among the 30 that carry a code, `Message` is `e.response["Error"]["Message"]` in organizations, iam, and the two reference methods, but `str(e)` — botocore's `An error occurred (Code) when calling the Op operation: ...` wrapper — in shield, account, auditmanager, and guardduty. A discriminator matching on message text sees two different strings for the same AWS answer depending on which service produced it.

The 100 erasing handlers are not all careless. Fourteen in `macie` and five in `securitylake` inspect the code, recognize `AccessDeniedException` or `ResourceNotFoundException`, log a debug line saying so, and *then* return `{}`. `securitylake._log_aws_failure` is a 50-line classifier whose docstring ends: "The caller is responsible for returning whatever empty value (`[]`, `{}`, `None`, `False`) is appropriate." The classification is made and discarded in the same function.

Two probes return a bare `bool` by design and so have no failure shape at all. `AccessAnalyzerClient.is_access_analyzer_available` returns `True` on `AccessDeniedException` — a permission failure reported as "service present" — and `SecurityLakeClient.is_security_lake_enabled` returns `False` on any exception.

### Transport failures escape

| Catches                                    | Clients                                                                                                                                   |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------- |
| A `BotoCoreError` member explicitly        | 4: accessanalyzer (`EndpointConnectionError`), iam (three types), securitylake (`BotoCoreError`), waf (three types, `list_services` only) |
| Bare `Exception` (so transport implicitly) | 10 clients, 44 handlers — of which 41 return an erasing value                                                                             |
| `ClientError` only                         | 7: account, auditmanager, firewallmanager, guardduty, organizations, securityincidentresponse, shield                                     |

In the seven `ClientError`-only clients, an `EndpointConnectionError` escapes the client, escapes `execute()`, and reaches the orchestrator's guard. `run_checks` materializes `list(check.execute())` inside that guard, so the exception unwinds before `all_findings.extend(findings)` runs and every row already yielded is dropped. One unreachable Region costs the check's output for every Region. With the bounded `Config` (10 s connect, 3 standard-mode attempts) that failure also takes 30 seconds or more to surface.

`securitylake` shows that catching and erasing are independent defects: its seven `(BotoCoreError, ClientError)` handlers catch everything and return `[]`, `{}`, `None`, or `False`.

### Failures are cached

| Accessor disposition toward a client failure                          | Methods |
| --------------------------------------------------------------------- | ------- |
| Writes the result to the cache unguarded                              | 66      |
| Guards partially — tests for one encoding of failure, caches another  | 4       |
| Caches the failure deliberately, with a comment saying so             | 2       |
| Refuses to cache an error result (`Macie` export config, `WAF` App Runner) | 2       |
| **Total accessors calling `_set`**                                    | **72**  |

The four partial guards: `GuardDutyCheck.get_detector_id` detects the `ERROR:` string and then caches `None` in its place; `SecurityHubCheck.get_enabled_standards` and `get_enabled_products_for_import` skip the write when the client returns `None` (the "not subscribed" signal) but cache `[]` (every other failure); `SecurityIncidentResponseCheck._discover_memberships` skips Regions whose response carries `"Error"` but falls back to caching `(regions[0], response_from_regions[0])`, which may itself be an error result.

The two deliberate: `IAMCheck.list_users` ("Cache both success and error responses") and `SecurityHubCheck.get_organization`, which constructs the error result in its own `except ClientError` and then caches it under the shared `organizations` namespace, where `OrganizationsCheck.get_organization` will read it back. Six `SecurityLakeCheck` accessors cache `[]`, `{}`, `None`, or `False` on exception with the comment "Preserve pre-refactor behavior".

The consequence is that a throttled or denied call in one Region is replayed to every subsequent check in that Region for the rest of the scan. `SecurityLakeCheck.get_subscribers` caching `[]` on `AccessDenied` is what turned one denied call into 8 wrong rows across `SRA-SECURITYLAKE-16` and `-17`.

### The report states findings the scan never established

Two kinds of wrong FAIL row, distinguished by whether the CSV can detect them.

**Confessing FAILs** carry wording that admits the uncertainty. 112 in the baseline: `SRA-MACIE-01` ×51 and `-02` ×51 ("Failed to retrieve Macie findings publication configuration"), `-08` ×4 and `-10` ×4 ("Failed to retrieve Macie organization configuration"), `SRA-SECURITYHUB-02` ×2 ("Unable to retrieve Security Hub organization configuration"). Twenty-five check modules contain a `failed()` with such wording; the 14 GuardDuty modules among them (`_02`–`_12`, `_17`–`_19`, "Unable to retrieve detector details") produced zero rows in this scan only because GuardDuty happened to be healthy.

**Masked FAILs** carry confident wording on an erased error. The 8 Security Lake rows are the measured instance: "Audit account <id> is not set up as query access subscriber", while the build log for the same account and Region records `AccessDenied` on `ListSubscribers`. The unmeasured instances are structural: `S3Client.get_public_access_block` maps `NoSuchPublicAccessBlockConfiguration` and `AccessDenied` both to `{}`, so `SRA-S3-01`–`04` say "No public access block configuration found" either way; `InspectorClient` maps every failure to `{}`, so `SRA-INSPECTOR-01`–`04` say "Inspector state status: NOT_ENABLED"; `AccessAnalyzerClient.list_analyzers` returns `[]` on `AccessDenied`, so `SRA-ACCESSANALYZER-01` says "No IAM Access Analyzer configured". Whether any of those fired wrongly in the baseline scan cannot be determined from the CSV. That is the point: 120 is the floor, and only the build log bounds the ceiling.

The dashboards count every FAIL as a finding. Each wrong one sends someone to investigate a misconfiguration that does not exist, and hides that the control was never evaluated.

### Stdout is clean by convention, not by contract

The MCP server in `sra-verify-mcp` imports `SRAVerify`, calls `run_checks()`, and speaks JSON-RPC to its client over stdio. One stray byte on stdout from the library breaks the transport. Three things keep that from happening today, and none of them is tested:

| Layer                            | What it does                                                                                                                                                                                                             | Where                                             |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------- |
| Logger routing                   | Strips the root logger's handlers at import, installs a stderr handler, binds `sraverify` to stderr with `propagate=False`, forces boto3/botocore/urllib3 to WARNING propagating to that root                            | `core/logging.py`                                 |
| No `print()` on the library path | All 17 `print()` calls in the package are in `main()` (6), `print_banner` (14 lines, one function), `ScanProgress` (2), and the `--list-*` branches (4). `run_checks()` reaches none of them unless `show_progress=True` | `main.py`, `utils/banner.py`, `utils/progress.py` |
| The server's own belt and braces | `warnings.filterwarnings('ignore')`, root at CRITICAL on stderr, and after importing `sraverify` it clears that logger's handlers and installs a `NullHandler`                                                           | `server.py:20–48`                                 |

The second layer is the one that matters and the one with no guard. A `print()` added to a base accessor while debugging, or a `logging.StreamHandler()` added with its default stream by someone who does not know why `core/logging.py` passes `sys.stderr` explicitly, ships silently. The scanner's own history has the shape of this defect — the steering docs record that stdout hygiene was a problem for the MCP server before `core/logging.py` did its root-logger surgery — and this design touches every `client.py` and every `base.py` in the tree, which is the widest surface a stray `print()` has had since the scan-context refactor.

This design adds three diagnostic paths of its own: the client handler's `error` log on every caught exception (`AWSClient.aws_error` as built, `call_aws` as designed), the availability lookup's `warning` on an unknown service id, and the `_set` backstop's `warning`. All three go through `logger`. Requirement 8 makes that the rule for every library module and gives it two tests: a dynamic one that runs the library entry point with a stdout that raises on write, and a static one that walks the AST for `print`, `sys.stdout`, and `warnings.warn`.

One adjacent fact, recorded here because it gates validation and is not this design's to fix: `server.py:293–295` calls `f.get('Status')` on `run_checks()`'s return value, which has been a `Finding` dataclass with no `.get()` since 2026-09-14. Every MCP `run_check` call raises `AttributeError` today. The check-contract design listed the repair as a required follow-up; it is still open, and until it lands the MCP path cannot exercise any batch of this migration.

### Regional availability is answered by a live probe in one place and not at all elsewhere

`AccessAnalyzerCheck._setup_clients` issues `accessanalyzer:ListAnalyzers` in every Region to decide whether to register a client — one AWS call per Region before any check runs, and `accessanalyzer` has an endpoint in all 34 commercial Regions, so the probe never says no. `WAFCheck.region_supports_service` answers the same question offline from botocore's endpoint data, correctly, for `apprunner`, and is the only such helper in the package. Measured against botocore 1.43.6, seven services the scanner consults have uneven commercial coverage: `apprunner` 11/34, `auditmanager` 12/34, `securitylake` 17/34, `amplify` 20/34, `macie2` 22/34, `appsync` 31/34, `inspector2` 32/34. In a Region without an endpoint, every one of those produces either an `EndpointConnectionError` that today escapes or an ERROR row that says nothing actionable.

---

## Non-Goals

Deliberate exclusions, each with its accepted cost. These restate the requirements' Out of Scope list with the design consequences added.

### 1. A cross-service classification table

`BadRequestException` is an ERROR through `guardduty:ListOrganizationAdminAccounts` ("not the master account", meaning run from the management account) and a FAIL through `guardduty:DescribeOrganizationConfiguration` ("not the delegated administrator", meaning the control is absent). Both are correct for their operation. The classification is therefore keyed by `(operation, code)`, and it stays declared on each service's base class. Accepted cost: auditing one service's classification means reading one table; auditing all of them means reading eighteen.

### 2. Any PASS verdict change

The design touches the failure path and the no-client path only. A row that passes today should pass afterward with the same `ActualValue`. This is a hypothesis the acceptance gate tests (Requirement 6.6 rejects any PASS transition), not a fact the design asserts. Accepted cost: known success-path defects — `sra_macie_07`'s set-join, `sra_securityincidentresponse_01`'s `regions[0]` label, `sra_firewallmanager_01`'s hardcoded `us-east-1` — remain live, including in files this design edits.

### 3. Retry at the check layer

`botocore.config.Config` owns retries: 3 attempts, `standard` mode. A call that fails past that budget yields an ERROR row. Accepted cost: throttling is reported, not recovered.

### 4. A base-driven region loop

No `evaluate(region)` hook. The availability guard goes into each check body that needs it, ahead of the call. Accepted cost: the guard is duplicated across the checks of seven services, and a check that needs one and lacks one is found by the gate (an ERROR row in a Region the service does not serve), not by the type system.

### 5. Yielding partial rows when a check raises

`run_checks` keeps `list(check.execute())` inside its guard. After this design no client raises, so an exception reaching the orchestrator means a programming error in a check or base class, and a single synthetic ERROR row that names the exception type is the right report of that. Making the orchestrator more forgiving would blunt the signal this design sharpens. Accepted cost: a genuine bug in one check still costs that check's whole output for one account.

### 6. `securityincidentresponse` region resolution

The base declares no `NAMESPACE`, pins `regions[0]` in three accessors, and produces an unstable row key. Deferred as a separate Region-labelling change. In scope for this design: its `_discover_memberships` sweep stops caching an error result as the fallback tuple, and its `get_organization_accounts` stops collapsing `"Error"` to `[]`. Its client already returns a full error result from all six handlers and needs only the `Message` normalization and the transport guard.

### 7. Deleting the per-client `get_account_id()` duplicates

`cloudtrail`, `config`, `ec2`, and `macie` each wrap `sts:GetCallerIdentity`, duplicating `ScanContext.get_account_info()`. Each has an erasing handler and is brought to the contract by the sweep. Replacing their callers with `self.account_id` is a separate cleanup. Accepted cost: four redundant STS calls per scan persist.

### 8. Region-level fan-out of a non-regional condition

This design does not revisit which rows are `global` and which are per-Region. A `NoClient` error result for a Region is a per-Region undetermined state and is reported in that Region's row.

### 9. Repairing the MCP server

`server.py`'s `f.get('Status')` against `Finding` objects is a defect in the other repository. The fix is `f.status == Status.PASS` or `f.to_row()["Status"]`, and it is small, but it lands there, not here. Accepted cost: the MCP path is unavailable for validating this migration until that repair ships, and the stdout contract is held by this repository's tests alone rather than by an end-to-end MCP round trip.

### 10. Quieting the CLI surface

`main()`, `print_banner`, `ScanProgress`, and the inventory listings write to stdout deliberately. The buildspec parses the summary, the operator reads the banner, and `test_exit_codes_scan.py` asserts `-> Scan complete!` appears on stdout and asserts it does *not* appear on the write-failure path. The stdout contract stops at the library boundary. Accepted cost: a consumer who calls `main()` instead of `run_checks()` gets a banner, which is the documented behaviour of `main()`.

---

# Part I — High-Level Design

## Architecture

The three tiers and the context are unchanged in shape. What changes is the contract on the two arrows that cross from the client tier upward.

```
                              before                                          after
                       ─────────────────────                      ──────────────────────────────
  SecurityCheck        reads {} / [] / None / str / error result      reads a dict; tests "Error" first;
  (check body)         guesses which branch is "no data"          classifies via is_not_configured()
        ↑                                                          ↑
        │  mixed types, failure indistinguishable                  │  always a dict; error result or named-key
        │  from empty                                              │
  <Service>Check       caches whatever arrives                    passes the dict through unchanged;
  (base accessor)      (66 unguarded, 2 deliberate)               never caches an error result; NoClient error result
        ↑              returns {} / [] / None on no-client         for a missing wrapper
        │                                                          ↑
        │  4 shapes; 7 clients let BotoCoreError through           │  one shape; nothing propagates
        │                                                          │
  <Service>Client      try / except ClientError / return {}       call_aws(operation, region, fn)
  (client.py)          (144 hand-written handlers)                (one guard, three except clauses, once)
        ↑                                                          ↑
  boto3 client via ScanContext.get_client()  ────────────────────  unchanged
```

New modules in `core/` carry the shared pieces. *As built there are three, not
two: dropping the shared guard's `operation=` and `region=` arguments meant the
builder needed `self`, so it moved onto a base class of its own.*

- `core/aws_errors.py` — the error result type and constructor, `is_error`, the transport exception tuple and its code set, `NO_CLIENT_CODE`, `UNKNOWN_OPERATION`, and the `is_not_configured` predicate over a per-service table. Defines the shape; does not build it.
- `core/aws_client.py` *(as built; not in the original design)* — `AWSClient`, the base class every `<Service>Client` inherits, holding `region`, `ctx`, and `aws_error(e)`; and `AWS_EXCEPTIONS`, the `(ClientError, BotoCoreError)` pair every handler catches.
- `core/availability.py` — `service_available_in_region(service_id, region)`, lifted from `WAFCheck.region_supports_service` and given a process-lifetime cache and the non-regionalized rule.

One new class attribute on `SecurityCheck`: `NOT_CONFIGURED_ERRORS`, defaulting to an empty mapping, overridden on each service base class. One new method, `is_not_configured(error)`, delegating to the module function with the class's table.

One four-line backstop in `ScanContext._set`: a value that `is_error` recognizes is logged at `warning` and not stored. The accessor discipline is the primary control; this is defense in depth for the accessor that forgets.

Every diagnostic these additions emit goes through `sraverify.core.logging.logger`. None of them imports `sys` for output, calls `print`, or calls `warnings.warn`. That is not a style choice; it is Requirement 8, and two tests hold it (Properties 20 and 21).

Nothing else in `core/` changes. *(`core/errors.py` was to gain `ClientContractError`; it was never shipped.)* `main.py` gains one `info` log line per check and nothing else. `Finding`, `CheckMeta`, the registry, discovery, and the CSV writer do not change.

## Module inventory

### New

| Module                                               | Contents                                                                                                                                                                                                                            |
| ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `core/aws_errors.py`                                 | `ErrorDetail`, `ErrorResult` (TypedDicts); `_TRANSPORT_EXCEPTIONS`, `TRANSPORT_ERROR_CODES`, `NO_CLIENT_CODE`, `UNKNOWN_OPERATION`; `error_result()`, `no_client_result()`, `is_error()`, `NotConfigured`, `NotConfiguredTable`, `is_not_configured()`. ~~`call_aws()`~~ — not built |
| `core/aws_client.py` *(as built)*                    | `AWSClient` with `region`, `ctx`, and `aws_error(e)`; `AWS_EXCEPTIONS = (ClientError, BotoCoreError)` |
| `core/availability.py`                               | `service_available_in_region()`, its `lru_cache`, the unknown-service and non-regionalized rules                                                                                                                                    |
| `tests/property/test_client_contract_property.py`    | Reflection over every client method: error result on `ClientError`, on transport, on `RuntimeError`; dict on success                                                                                                                    |
| `tests/property/test_accessor_cache_property.py`     | Reflection over every base accessor: error result not cached, second call re-issues; `NoClient` not cached                                                                                                                              |
| `tests/property/test_discriminator_property.py`      | Every service table: unknown code → False; declared pair → True; declared code on undeclared operation → False; no check overrides the table                                                                                        |
| `tests/property/test_check_classification_property.py` | Catalog-wide over `all_checks()`: every accessor patched to a non-semantic error result yields only ERROR rows naming operation and code (Property 14); a declared semantic error result reaches `failed()` (14a); an unsupported Region yields no row and no call (14b) |
| `tests/property/test_availability_property.py`       | Offline lookup: unknown id → True + warning; partition derivation; `apprunner`/`us-west-1` → False; `shield` → True everywhere                                                                                                      |
| `tests/property/test_no_confessing_fail_property.py` | AST walk of every `sra_*` module: no `failed()` whose `actual_value` matches the confessing patterns; no bare `except Exception` resolving to `failed()`                                                                            |
| `tests/property/test_stdout_contract_property.py`    | Dynamic: `run_checks()` over the three-probe catalog with a raising stdout completes. Static: no `print`, `sys.stdout`, `sys.__stdout__`, or `warnings.warn` in any library module. Every logger handler binds `sys.stderr`         |

### Rewritten

| Module                          | Change                                                                                                                                                                                                                                                                                                                                                                                                           |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 18 × `services/<svc>/client.py` | The class inherits `AWSClient` and chains `super().__init__(region, ctx)`. Every method body becomes a plain `try` around the boto3 call and any pagination, returning a named-key dict, with one handler: `except AWS_EXCEPTIONS as e: return self.aws_error(e)`. *(Design said `return call_aws(...)` around a closure.)* `str(e)` messages, typed `self.client.exceptions.*` catches, code-dropping error results, the `ERROR:` string, the two bool probes, and the return-less handler all go.                                                                                                  |
| 18 × `services/<svc>/base.py`   | Every accessor: `is_error` guard before `_set`; `no_client_result` where it returned `{}`/`[]`/`None`; pass the dict through; `NOT_CONFIGURED_ERRORS` table declared. `AccessAnalyzerCheck._setup_clients` loses its probe. `WAFCheck.region_supports_service` delegates to `core/availability`. `MacieCheck.is_macie_disabled_error` is replaced by the table (a delegate for one batch, deleted in Phase 7). |
| `core/check.py`                 | `NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {}` and `is_not_configured(self, error)`. Nothing else.                                                                                                                                                                                                                                                                                                   |
| `core/scan_context.py`          | The `_set` backstop. Nothing else.                                                                                                                                                                                                                                                                                                                                                                               |
| Check modules                   | Every consumer of a changed accessor: `"Error" in result` test first, classify via `is_not_configured`, extract after. Confessing `failed()` calls become `error()` or discriminated `failed()`. See the per-service table in Part II.                                                                                                                                                                           |

### Untouched

`core/finding.py`, `core/metadata.py`, `core/registry.py`, `core/discovery.py`, `core/enums.py`, `core/logging.py`, `core/session.py`, `utils/`, `1-sraverify-member-roles.yaml`, `docs/checks.txt` (no metadata changes).

### Edited, narrowly

| Module                              | Change                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `main.py`                           | One `logger.info(f"check_done check_id={selected_id} rows={len(findings)}")` after the per-check `list()` and inside the guard's success path, plus the same line with `rows=synthetic` in the `except`. Nothing else. The gate uses it to attribute `aws_call_failed` lines to checks by position.                                                                                                                                                                 |
| `core/errors.py`                    | ~~`class ClientContractError(SRAVerifyError)`~~ — **not built**; the class existed only for the shared guard's non-mapping check.                                                                                                                                                                                                                                                                                                                                     |
| `2-sraverify-codebuild-deploy.yaml` | Each `sraverify` invocation in the buildspec redirects stderr to `stderr/<account_id>-<account_type>.log`; the upload step copies `stderr/` beside the raw CSVs. Purely additive to the artefact set; the `parallel` fan-out, the consolidation step, and the dashboard copy are unchanged. This is an infrastructure template edit and lands with Phase 0 after review.                                                                                            |
| `util/generate_iam_policy.py` | Binds each `self.<attr> = ctx.get_client('<service>', ...)` in a client's `__init__` to its service, then attributes every `self.<attr>.<method>(` and `self.<attr>.get_paginator('<method>')` in the module to that service — the receiver-attribution it already performs for `session.client(...)`, which nothing in the tree has used since the scan-context refactor. *(The design also had it cross-check a `call_aws` operation literal against the receiver method's PascalCase form. There is no literal as built — `aws_error` reads the operation from botocore — so `collect_operation_literals` and `cross_check_literals` were removed; the receiver attribution is the whole mechanism.)* Gains tests asserting the exact action set for `WAFClient` (nine services) and `ShieldClient` (five). Run against the current tree in Phase 0 and again after Phase 7; the final output is expected to equal the committed artefacts minus the Access Analyzer probe's use of `ListAnalyzers`, which `SRA-ACCESSANALYZER-01` still needs. |
| `util/gate.py` (new)                | The acceptance gate. Multiset matching, structured-log parsing, static check→operation derivation, admitted-transition rules, digest recording. Tested by `tests/unit/util/test_gate.py` against synthetic CSV and stderr pairs.                                                                                                                                                                                                                                    |

## Components and Interfaces

### The error result

```python
class ErrorDetail(TypedDict):
    Code: str        # AWS error code, or the exception type name where none exists
    Message: str     # e.response["Error"]["Message"], or str(e) where none exists; never empty
    Operation: str   # botocore operation name, e.g. "ListSubscribers"

class ErrorResult(TypedDict):
    Error: ErrorDetail
```

`Operation` is the addition over the two reference implementations. It exists because the check needs to name the operation in an ERROR row's `ActualValue` (Requirement 4.8) and the discriminator needs it to look up the table (Requirement 4.4), and threading it as a separate parameter through every accessor would mean every accessor has to know which operation its client called. `ClientError` carries `e.operation_name` for free; for transport and unexpected exceptions `call_aws` uses the name it was given.

### `call_aws`

> **Superseded — not built.** The shared guard was rejected during implementation;
> every client method carries its own plain `try`/`except` calling
> `AWSClient.aws_error(e)`. Retained as the record of the reasoning. See
> [Superseded during implementation](#superseded-during-implementation).


```python
def call_aws(operation: str, *, region: str, fn: Callable[[], Mapping[str, Any]]) -> Mapping[str, Any]
```

Runs `fn()` and returns its result, or the error result. Two `except` clauses: `ClientError`, then `BotoCoreError`. Nothing else — a programming defect raised inside `fn` propagates unchanged, and `BaseException` is never caught. Each clause logs exactly one structured `aws_call_failed` line at `error`. A result that is not a `Mapping` raises `ClientContractError` *outside* the `try`: a client that returns a list has a programming defect, and the orchestrator's synthetic row is the right report of that. `fn` may call methods on clients the wrapper already holds; it must not acquire one — `ctx.get_client()` is constructor-only (Requirement 1.11), because inside the closure a construction failure would be a `BotoCoreError` and become an error result instead of the defect it is.

`fn` is a zero-argument closure so that pagination lives inside the guard:

```python
def list_subscribers(self) -> Mapping[str, Any]:
    def _pages():
        subscribers = []
        response = self.client.list_subscribers()
        subscribers.extend(response.get("subscribers", []))
        while response.get("nextToken"):
            response = self.client.list_subscribers(nextToken=response["nextToken"])
            subscribers.extend(response.get("subscribers", []))
        return {"subscribers": subscribers}
    return call_aws("ListSubscribers", region=self.region, fn=_pages)
```

A one-call method is a lambda: `return call_aws("GetDetector", region=self.region, fn=lambda: self.client.get_detector(DetectorId=detector_id))`.

### Base accessor

```python
def get_subscribers(self, region: str) -> Mapping[str, Any]:
    cache_key = f"subscribers:{region}"
    if self._ctx._has(self.NAMESPACE, cache_key):
        return self._ctx._get(self.NAMESPACE, cache_key)
    client = self.get_client(region)
    if client is None:
        return no_client_result(service="Security Lake", region=region, operation="ListSubscribers")
    result = client.list_subscribers()
    if is_error(result):
        return result
    self._ctx._set(self.NAMESPACE, cache_key, result)
    return result
```

Six lines of logic, identical in every accessor: hit, no-client, call, guard, store, return. The accessor does not extract; the check receives `{"subscribers": [...]}` and reads the key after testing for `"Error"`. Where several checks share an extraction, the base may offer a pure helper that takes the success dict — `subscribers_of(result) -> list` — but not one that takes the accessor's output, because that would re-introduce a function that has to handle both shapes.

### Discriminator

```python
NotConfiguredTable = Mapping[str, Mapping[str, NotConfigured]]
#                            ^operation  ^code    ^NotConfigured(evidence=..., message=None)

def is_not_configured(table: NotConfiguredTable, error: Mapping[str, str]) -> bool
```

On `SecurityCheck`:

```python
NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {}

def is_not_configured(self, error: Mapping[str, str]) -> bool:
    return is_not_configured(type(self).NOT_CONFIGURED_ERRORS, error)
```

On a service base class:

```python
class MacieCheck(SecurityCheck):
    NAMESPACE = "macie"
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {
        "GetClassificationExportConfiguration": {
            "ResourceNotFoundException": NotConfigured(
                evidence="https://docs.aws.amazon.com/macie/latest/APIReference/classification-export-configuration.html#classification-export-configuration-http-responses (404 ResourceNotFoundException: no Macie session)",
            ),
            # AccessDeniedException is overloaded: Macie returns it both when
            # Macie is disabled in the Region and when the caller lacks the
            # permission. Only the message separates the two.
            "AccessDeniedException": NotConfigured(
                message="macie is not enabled",
                evidence="CodeBuild log 2026-09-12 18:37, account 111122223333 us-west-1: 'Macie is not enabled' on GetClassificationExportConfiguration with Macie disabled",
            ),
        },
        ...
    }
```

Lookup: operation → code → `NotConfigured` fact, whose optional `message` is a case-insensitive substring of `Message`. Anything not found is `False`. Every fact carries non-blank `evidence`, enforced at construction, so a table cannot be declared without saying why. A check calls `self.is_not_configured(result["Error"])` and branches to `failed()` or `error()`. The table is declarative so that the contract tests can enumerate it (Requirement 7.7) and so that a reviewer auditing a service reads data, not control flow.

### Availability lookup

```python
def service_available_in_region(service_id: str, region: str) -> bool
```

Offline, credential-free, `lru_cache`d on `(service_id, region)`. Returns `False` only when `service_id` is a known boto3 service, its regional endpoint list for the Region's partition is non-empty, and the Region is not in it. Every other outcome — unknown id (with a `warning`), empty regional list (non-regionalized or no endpoint data), any exception (with a `debug`) — returns `True`. A check consults it at the top of its region loop and `continue`s past a Region it says no to, issuing no call and yielding no row.

## Data models

There are no new persistent data models. The error result and the success dict are the wire format between tiers; `Finding` is unchanged. The one new class-level declaration is `NOT_CONFIGURED_ERRORS`, a nested mapping of string to string to optional string, declared as a literal on each service base class and never mutated.

The `ActualValue` of an ERROR row produced from an error result follows one shape so that Requirement 4.8 is met uniformly:

```
{Operation} failed: {Code}: {Message}
```

e.g. `ListSubscribers failed: AccessDeniedException: User: arn:aws:sts::111122223333:assumed-role/SRAMemberRole/sraverify-session is not authorized to perform: securitylake:ListSubscribers`. A transport ERROR row reads `ListServices failed: EndpointConnectionError: Could not connect to the endpoint URL: "https://apprunner.us-west-1.amazonaws.com/"`. A `NoClient` row reads `ListSubscribers failed: NoClient: No Security Lake client is registered for Region eu-west-3`. The orchestrator's synthetic row keeps its distinct prefix, `Error running SRA-X-NN:`, so the two are never confused (Requirement 2.5).

---

# Part II — Low-Level Design

> **Reading note.** Part II was written against the shared-guard design and says
> "route through `call_aws`" throughout its per-service tables. Read that as "give
> the method a plain `try`/`except` whose handler is `return self.aws_error(e)`" —
> the mechanism changed, the per-service *content* (which methods, which success
> shapes, which `(operation, code)` table entries, which checks to fix) did not,
> and that content is the value here. `tasks.md` carries the operative,
> as-built instructions per batch.

## `core/aws_errors.py`

```python
"""
The client error contract.

One error-result shape, one guard that produces it, one predicate that reads it.
Every ``<Service>Client`` method returns through ``call_aws``; every
``<Service>Check`` base class declares a ``NOT_CONFIGURED_ERRORS`` table that
``is_not_configured`` reads. Nothing in this module issues an AWS call.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Final, TypedDict

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)

from sraverify.core.errors import ClientContractError
from sraverify.core.logging import logger


class ErrorDetail(TypedDict):
    Code: str
    Message: str
    Operation: str


class ErrorResult(TypedDict):
    Error: ErrorDetail


#: The three transport subclasses a check may want to word remediation for
#: ("confirm the endpoint is reachable"). The guard catches all of
#: BotoCoreError; this set only names the members whose meaning is "network".
_TRANSPORT_EXCEPTIONS: Final = (
    EndpointConnectionError,
    ConnectTimeoutError,
    ReadTimeoutError,
)

#: The ``Code`` values those three produce. Derived, so the two cannot drift.
TRANSPORT_ERROR_CODES: Final[frozenset[str]] = frozenset(
    exc.__name__ for exc in _TRANSPORT_EXCEPTIONS
)

#: ``Code`` for the no-client condition: a base accessor found no client
#: wrapper for the Region. Undetermined, never cached, always an ERROR.
NO_CLIENT_CODE: Final = "NoClient"


def _require_text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"error_result: {name} must be a non-blank str, got {value!r}")
    return value


def error_result(*, code: str, message: str, operation: str) -> ErrorResult:
    """Build an error result. Every field is a non-blank str; that is the whole contract."""
    return {
        "Error": {
            "Code": _require_text("code", code),
            "Message": _require_text("message", message),
            "Operation": _require_text("operation", operation),
        }
    }


def no_client_result(*, service: str, region: str, operation: str) -> ErrorResult:
    return error_result(
        code=NO_CLIENT_CODE,
        message=f"No {service} client is registered for Region {region}",
        operation=operation,
    )


def is_error(value: Any) -> bool:
    """
    True iff ``value`` is a well-formed error result: a mapping whose
    ``Error`` member is itself a mapping whose ``Code``, ``Message``, and
    ``Operation`` are each a non-blank str.

    Strict on purpose, in both directions. A success dict from an operation
    that happens to have a top-level ``Error`` member of another shape must
    not be mistaken for an error result; and a half-built error result — a blank Code,
    a missing Operation — must not pass as one and be half-read downstream,
    nor fail the test and be cached as a success. The only value that
    satisfies this is one ``error_result()`` could have built.
    """
    if not isinstance(value, Mapping):
        return False
    err = value.get("Error")
    if not isinstance(err, Mapping):
        return False
    return all(
        isinstance(err.get(k), str) and err[k].strip()
        for k in ("Code", "Message", "Operation")
    )


def call_aws(
    operation: str,
    *,
    region: str,
    fn: Callable[[], Mapping[str, Any]],
) -> Mapping[str, Any]:
    """
    Run ``fn()`` — one AWS call, or one paginated sequence of calls — and
    return its dict, or the error result.

    Catches exactly two things: ``ClientError`` (AWS answered with an error
    code) and ``BotoCoreError`` (the SDK could not complete the call —
    endpoint, timeout, credentials, resolution). Both are AWS outcomes and
    both become error results. Anything else raised inside ``fn`` is a programming
    defect in the client and propagates unchanged; the orchestrator's guard
    reports it as a synthetic row naming the exception type, which is the
    correct report of a defect.

    ``fn`` returning something other than a Mapping is also a defect, and is
    raised as ``ClientContractError`` from outside the ``try`` so it cannot be
    confused with an AWS outcome and so the synthetic row names the contract.
    """
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        code = err.get("Code") or type(e).__name__
        message = err.get("Message") or str(e)
        op = getattr(e, "operation_name", None) or operation
        logger.error(
            f"aws_call_failed operation={op} region={region} code={code} message={json.dumps(message)}"
        )
        return error_result(code=code, message=message, operation=op)
    except BotoCoreError as e:
        code = type(e).__name__
        message = str(e) or code
        logger.error(
            f"aws_call_failed operation={operation} region={region} code={code} message={json.dumps(message)}"
        )
        return error_result(code=code, message=message, operation=operation)

    if not isinstance(result, Mapping):
        raise ClientContractError(
            f"{operation}: client returned {type(result).__name__}, not a dict; "
            f"wrap the value under its AWS response member name"
        )
    return result


@dataclass(frozen=True, slots=True)
class NotConfigured:
    """
    One declared "this code, from this operation, means not configured" fact.

    ``evidence`` is required and non-blank: the AWS API reference URL that
    documents the code's meaning for the operation, or a build-log line from a
    controlled account observed to produce it. A table entry converts an ERROR
    into a FAIL; an entry without evidence is an assertion, not a fact.
    ``message``, when given, is a case-insensitive substring the error message
    must contain — the discriminator for an overloaded code.
    """
    evidence: str
    message: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.evidence, str) or not self.evidence.strip():
            raise ValueError("NotConfigured.evidence must be a non-blank str")


NotConfiguredTable = Mapping[str, Mapping[str, NotConfigured]]
#                            ^operation  ^code    ^fact with evidence


def is_not_configured(table: NotConfiguredTable, error: Mapping[str, str]) -> bool:
    """
    Decide whether ``error`` (the ``Error`` sub-dict of an error result) means the
    control is absent for the operation that produced it.

    Lookup is operation → code → optional message substring. Anything not
    declared is False: an unknown code, a known code from an operation it is
    not declared for, or a declared substring that does not appear in the
    message. False means ERROR; True means FAIL.
    """
    by_code = table.get(error.get("Operation", ""))
    if not by_code:
        return False
    fact = by_code.get(error.get("Code", ""))
    if fact is None:
        return False
    if fact.message is None:
        return True
    return fact.message.lower() in error.get("Message", "").lower()
```

### Decision point 1 — one shared guard versus three `except` clauses per method

> **Decided the other way in the end.** This section argues for the shared guard;
> the repetition won. The reasoning below is why it was a close call, and the
> counter-argument that settled it was that the handler is now *byte-identical* in
> every method — one exact statement, nothing per-call-site to get wrong — which
> the static Property 6 test asserts as an exact string.


`IAM_Client.list_users` is the most complete hand-written shape in the tree: `ClientError`, then a transport tuple, then `Exception`, each returning an error result. Replicating even a corrected version of that across 144 handlers means 144 chances to drop a clause, use `str(e)`, or return `[]`. `call_aws` writes the clauses once. Every client method becomes `return call_aws(op, region=..., fn=...)`, and the closure it passes contains only the boto3 call and whatever pagination it already had.

The cost is a closure per method and an indirection a reader has to follow once. The benefit is that the contract tests in Requirement 7.1–7.3 can be run against `call_aws` directly as a unit test *and* against every client method through the adapter table, and the two agree by construction.

### Decision point 1a — what the guard catches, and what it deliberately lets through

The first draft of this design ended `call_aws` with `except Exception`, on the reasoning that no exception should ever reach a check. That reasoning is wrong in a specific way, and it is worth recording why.

The design's own claim is that once clients stop raising for AWS outcomes, a synthetic ERROR row becomes evidence of a programming defect. A guard that catches `Exception` defeats that claim at the client tier: an `AttributeError` from a typo in a closure becomes a plausible ERROR row with `Code="AttributeError"` for that Region, the other Regions proceed, and the row sits in the report looking like an AWS failure. Worse, it recurs on every scan until someone reads the `Code` column closely enough to notice that `AttributeError` is not an AWS error code. The orchestrator's guard exists precisely to make that defect loud — one synthetic row, a traceback in the log, the check's output for that account gone until it is fixed — and containing the exception one tier lower silences it.

So the guard catches exactly `ClientError` and `BotoCoreError`. The second is the whole family, not the three transport subclasses the first draft named: `NoCredentialsError`, `PartialCredentialsError`, `UnknownServiceError`, `EndpointResolutionError`, `ProxyConnectionError`, `SSLError`, `ConnectionClosedError` are all "the SDK could not complete the call", none carries an AWS error code, and enumerating three of them leaves the rest to propagate as if they were defects. Both families are AWS outcomes; both become error results; both are logged as a structured `aws_call_failed` line the gate can parse by field.

Everything else — `AttributeError`, `KeyError`, `TypeError`, `IndexError`, `ValueError` — propagates unchanged. `BaseException` is never caught, so `KeyboardInterrupt` still aborts the scan. The accepted cost is exactly Non-Goal 5's: a defect in a client costs that check's whole output for one account, on one row that names the defect. That is the same cost a defect in a check body has carried since the check-contract formalization, and it is the right cost, because it is the one that gets the defect fixed.

`ParamValidationError` is a `BotoCoreError` and therefore becomes an error result, even though it is arguably a programming defect (a client passed a malformed parameter). This is accepted: botocore raises it before any network call, it names the parameter in its message, and an error result with `Code="ParamValidationError"` in the CSV is a clear enough signal. Carving it out would mean subclass-testing inside the `except` for one case.

### Decision point 2 — `Message` from `e.response`, not `str(e)`

Four of the nine error result-returning clients use `str(e)`, which yields `An error occurred (ResourceNotFoundException) when calling the GetSubscriptionState operation: The subscription does not exist.` The other five use `e.response["Error"]["Message"]`, which yields `The subscription does not exist.` A discriminator matching a substring works against either, but an `ActualValue` built from the first repeats the code and the operation that the row already carries in its own fields. `call_aws` uses `e.response["Error"]["Message"]` and falls back to `str(e)` only when it is absent. This changes the `ActualValue` of every existing ERROR row from those four clients; the gate admits it under Requirement 6.3.

### Decision point 3 — `Operation` in the error result

Alternatives: pass the operation as a second argument to `is_not_configured`, or have each accessor record it. Both require every accessor to know its client method's operation name and thread it upward, and both make `is_not_configured(error)` a two-argument call at 100+ check sites. `ClientError` already exposes `operation_name`; `call_aws` already receives the name for logging. Putting it in the error result costs one key and buys a one-argument predicate and an `ActualValue` that can name the operation without the check knowing it.

### Decision point 4 — a non-dict success result raises `ClientContractError`

> **Superseded — the class was never shipped.** It existed only for the shared
> guard's check. Property 4's per-method `isinstance(result, Mapping)` assertion
> holds the rule instead, before it ships rather than at scan time.


`call_aws` could coerce a list into `{"Items": [...]}` or wrap it in an error result with `Code="ContractViolation"`. Either would hide the defect behind plausible output. Raising from outside the `try` turns the client bug into a synthetic ERROR row, which is exactly the class of row this design reserves the orchestrator's guard for. The exception is a named `ClientContractError` (new in `core/errors.py`, a `SRAVerifyError` subclass) rather than a bare `TypeError`, so that the synthetic row's `ActualValue` reads `Error running SRA-X-NN: ClientContractError: ListSubscribers: client returned list, not a dict` and identifies the tier at fault without a traceback. The contract test in Requirement 7.3 catches it before it ships.

This is consistent with Requirement 1.9, which is now stated as "returns normally for every `ClientError` and `BotoCoreError`" rather than "never raises". The first draft said "never raises" and then raised here; the reviewer was right that the two could not both be true.

## `core/availability.py`

```python
"""
Offline regional availability from botocore's bundled endpoint data.

No AWS call, no credentials. Lifted from ``WAFCheck.region_supports_service``
and given two things it lacked: a process-lifetime cache, and the rule for
services whose regional endpoint list is empty.
"""
from __future__ import annotations

from functools import lru_cache

import boto3

from sraverify.core.logging import logger


@lru_cache(maxsize=None)
def service_available_in_region(service_id: str, region: str) -> bool:
    """
    True unless botocore positively says ``service_id`` has no endpoint in
    ``region``. Every uncertain outcome is True; see the rules below.

    No session parameter. The endpoint data is process-global and shipped with
    botocore, so the answer cannot depend on which session asks. A fresh
    credential-free ``boto3.Session()`` is built inside the cached call and
    discarded; nothing here holds a reference to the scan's session.
    """
    try:
        session = boto3.Session()  # credential-free; only endpoint data is read
        if service_id not in session.get_available_services():
            logger.warning(
                f"availability: {service_id!r} is not a known boto3 service id; "
                f"treating it as available in {region} rather than suppressing the Region"
            )
            return True
        partition = session.get_partition_for_region(region)
        regional = session.get_available_regions(service_id, partition_name=partition)
        if not regional:
            # Non-regionalized (shield, organizations, iam: partition endpoint
            # only) or no endpoint data at all (security-ir). Either way the
            # per-Region question has no answer, and "no answer" is not "no".
            return True
        return region in regional
    except Exception as e:  # noqa: BLE001 — fail open, deliberately
        logger.debug(
            f"availability: could not determine {service_id} in {region} "
            f"({type(e).__name__}: {e}); treating it as available"
        )
        return True
```

The first draft took a `session` parameter and then ignored it in favour of a fresh `boto3.Session()`, with a `_session_key` helper that was referenced and never written. Both are gone. A parameter the implementation does not use tells the reader the answer depends on something it does not depend on.

### Decision point 5 — every uncertain answer is "available"

A false "available" costs one honest ERROR row for one Region. A false "unavailable" suppresses a Region silently and can hide a real finding forever. The asymmetry decides every edge case the same way: unknown service id, empty regional list, any exception. The only path that returns `False` is a recognized service, a non-empty regional list for the right partition, and a Region absent from it. Measured against botocore 1.43.6, that path fires for `apprunner` in `us-west-1` and for nothing else in the four-Region scan the baseline used; it would fire for `securitylake` in 17 commercial Regions and `auditmanager` in 22.

The empty-list rule is the one the WAF original did not need. `shield`, `account`, `organizations`, `iam`, and `cloudfront` all answer `[]` for the `aws` partition because they are reached through `aws-global`; `security-ir` answers `[]` because botocore 1.43.6 ships no endpoint data for it at all. A naive `region in regional` reads every one of those as "available nowhere" and would suppress every Shield row in the catalog. The requirement records this as the one input on which fail-closed would be wrong for every Region at once.

## `core/scan_context.py` — the `_set` backstop

```python
def _set(self, namespace: str, key: str, value: Any) -> None:
    if is_error(value):
        logger.warning(
            f"ScanContext: refusing to cache an error result under "
            f"{namespace}:{key} ({value['Error'].get('Code')}); the accessor should not have asked"
        )
        return
    with self._lock:
        ...  # unchanged
```

### Decision point 6 — a central backstop, and why it skips rather than raises

The accessor discipline (Requirement 3) is the primary control and the contract tests hold it per accessor. The backstop exists for the accessor added next year by someone who has not read this document. It skips and warns rather than raising because raising inside `_set` would abort the check that called it — losing its rows to a synthetic ERROR — for what is by then a harmless redundancy: the accessor has already returned the error result to its caller correctly, and the only defect is the attempted write. A `warning` in the build log is proportionate.

It is a backstop and not a substitute because it sees only error result-shaped dicts. An accessor that still encodes failure as `[]` or `None` walks straight past it, which is why Requirement 3.4 names the nine sites that do so today and requires each to change.

`structure.md` describes `_has`/`_get`/`_set` as the storage layer. This is a four-line policy in the storage layer, and it is the only change to `scan_context.py` in this design.

## `core/check.py` — two additions

```python
class SecurityCheck(ABC):
    ...
    #: Per-service declaration of which (operation, code) pairs mean "the
    #: control is not configured". Declared on the service base class, never
    #: on a check. Read by ``is_not_configured``.
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {}

    def is_not_configured(self, error: Mapping[str, str]) -> bool:
        """Classify an error result's ``Error`` sub-dict against this service's table."""
        return _is_not_configured(type(self).NOT_CONFIGURED_ERRORS, error)
```

`__init_subclass__` gains one rule alongside the existing shadowing rule: a class created inside a `sra_*` module must not declare `NOT_CONFIGURED_ERRORS` in `vars(cls)`. The table belongs to the service, and a check that overrides it has re-created the per-check classification this design removes. The rule raises `CheckIdentityError` like the others and leaves the registry untouched.

## The check-body pattern

Every consumer of an accessor follows one shape:

```python
for region in self.regions:
    if not service_available_in_region("securitylake", region):
        continue                                        # Requirement 5: no row, no call

    result = self.get_subscribers(region)

    if "Error" in result:                               # Requirement 4.1: before any field
        error = result["Error"]
        if self.is_not_configured(error):               # Requirement 4.2
            yield self.failed(
                region=region,
                resource_id=...,
                actual_value=f"Security Lake is not enabled: {error['Message']}",
            )
        else:                                           # Requirement 4.3
            yield self.error(
                region=region,
                resource_id=...,
                actual_value=f"{error['Operation']} failed: {error['Code']}: {error['Message']}",
                remediation=self._remediation_for(error),
            )
        continue

    subscribers = result.get("subscribers", [])         # extraction after the test
    ...
```

`_remediation_for(error)` is a small helper on `SecurityCheck` that returns the scan-environment remediation for a non-semantic error: for a code in `TRANSPORT_ERROR_CODES`, "Confirm the {Operation} endpoint in {region} is reachable from the scanner's network"; for `NoClient`, "Confirm the Region is enabled for the account and supplied to --regions"; for `AccessDeniedException`, `UnauthorizedOperation`, `AccessDenied`, and `UnauthorizedException`, "Grant the member role permission to call {Operation} for this service (see the SRAVerifyCheckPermissions policy in 1-sraverify-member-roles.yaml)"; otherwise, "Investigate {Code} from {Operation} in the build log". It deliberately does not compose an IAM action string: `meta.service` is a display name (`IAM Access Analyzer`, `FirewallManager`) and not an IAM prefix (`access-analyzer`, `fms`), so any `f"{service}:{Operation}"` would be wrong for several services and confidently wrong is worse than vague. A check that wants to name the exact action passes its own `remediation=`; the `error()` helper still rejects a blank one.

The availability guard appears only in checks whose service is in the candidate set; everywhere else the loop begins at the accessor call.

## Worked example — `SRA-SECURITYLAKE-16`

The check whose 4 wrong FAIL rows are half the measured masked-FAIL count.

### Before

`client.py`:

```python
def list_subscribers(self):
    try:
        response = self.client.list_subscribers()
        subscribers = response.get("subscribers", [])
        while response.get('nextToken'):
            response = self.client.list_subscribers(nextToken=response['nextToken'])
            subscribers.extend(response.get("subscribers", []))
        return subscribers
    except self.client.exceptions.ResourceNotFoundException:
        logger.debug(f"No subscribers found in region {self.region}")
        return []
    except (BotoCoreError, ClientError) as e:
        self._log_aws_failure("listing subscribers", e)
        return []
```

`base.py`:

```python
def get_subscribers(self, region: str) -> List[Dict[str, Any]]:
    ...
    client = self.get_client(region)
    if not client:
        self._ctx._set(self.NAMESPACE, cache_key, [])       # caches no-client as empty
        return []
    try:
        subscribers = client.list_subscribers()
        self._ctx._set(self.NAMESPACE, cache_key, subscribers)   # caches [] from AccessDenied
        return subscribers
    except Exception as e:
        self._ctx._set(self.NAMESPACE, cache_key, [])       # unreachable; client never raises
        return []
```

`sra_securitylake_16.py`:

```python
subscribers = self.get_subscribers(region)
audit_subscriber = next((sub for sub in subscribers if ...), None)
if not audit_subscriber:
    yield self.failed(
        region=region, resource_id=resource_id,
        actual_value=f"Audit account {audit_account_id} is not set up as query access subscriber",
        ...
    )
```

An `AccessDeniedException` on `ListSubscribers` becomes `[]` at the client, is cached at the base, and is reported as a confident FAIL by this check and by `-17` after it.

### After

`client.py`:

```python
def list_subscribers(self) -> Mapping[str, Any]:
    def _pages() -> Mapping[str, Any]:
        subscribers: list = []
        response = self.client.list_subscribers()
        subscribers.extend(response.get("subscribers", []))
        while response.get("nextToken"):
            response = self.client.list_subscribers(nextToken=response["nextToken"])
            subscribers.extend(response.get("subscribers", []))
        return {"subscribers": subscribers}
    return call_aws("ListSubscribers", region=self.region, fn=_pages)
```

`_log_aws_failure` and the typed `ResourceNotFoundException` catch are deleted. `ResourceNotFoundException` now arrives at the check as an error result and the table decides what it means.

`base.py`:

```python
_RNF = NotConfigured(
    evidence="https://docs.aws.amazon.com/security-lake/latest/APIReference/CommonErrors.html — ResourceNotFoundException: the data lake does not exist in this Region",
)
# UnauthorizedException is asserted by the old _log_aws_failure docstring to
# mean "Security Lake isn't enabled"; that is an assertion, not evidence.
# Confirm against a controlled account in Batch 3 and replace this evidence
# string with the observed log line, or delete the entry so the code stays ERROR.
_UNAUTH = NotConfigured(evidence="TO CONFIRM IN BATCH 3 — see design.md Requirement 4.6a")

NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {
    "ListSubscribers": {"ResourceNotFoundException": _RNF, "UnauthorizedException": _UNAUTH},
    "ListDataLakes": {"ResourceNotFoundException": _RNF, "UnauthorizedException": _UNAUTH},
    "GetDataLakeOrganizationConfiguration": {"ResourceNotFoundException": _RNF, "UnauthorizedException": _UNAUTH},
    "ListLogSources": {"ResourceNotFoundException": _RNF, "UnauthorizedException": _UNAUTH},
    "GetDataLakeSources": {"ResourceNotFoundException": _RNF, "UnauthorizedException": _UNAUTH},
}

def get_subscribers(self, region: str) -> Mapping[str, Any]:
    cache_key = f"subscribers:{region}"
    if self._ctx._has(self.NAMESPACE, cache_key):
        return self._ctx._get(self.NAMESPACE, cache_key)
    client = self.get_client(region)
    if client is None:
        return no_client_result(service="Security Lake", region=region, operation="ListSubscribers")
    result = client.list_subscribers()
    if is_error(result):
        return result
    self._ctx._set(self.NAMESPACE, cache_key, result)
    return result
```

`UnauthorizedException` is in the table because `_log_aws_failure`'s own docstring records it as "Security Lake isn't enabled in this region/account" — the classification existed; it was being logged and thrown away. But a docstring is not evidence, so the entry carries a placeholder that Batch 3 must replace with an observed log line from a controlled account, or delete. A placeholder that survives to Phase 7 fails Property 11a.

`sra_securitylake_16.py`:

```python
for region in self.regions:
    if not service_available_in_region("securitylake", region):
        continue
    resource_id = f"arn:aws:securitylake:{region}:{self.account_id}:subscriber/query-access"
    result = self.get_subscribers(region)

    if "Error" in result:
        error = result["Error"]
        if self.is_not_configured(error):
            yield self.failed(
                region=region, resource_id=resource_id,
                checked_value=f"Audit account {audit_account_id} has query access",
                actual_value=f"Security Lake is not enabled in this Region ({error['Code']})",
            )
        else:
            yield self.error(
                region=region, resource_id=resource_id,
                checked_value=f"Audit account {audit_account_id} has query access",
                actual_value=f"{error['Operation']} failed: {error['Code']}: {error['Message']}",
                remediation=self._remediation_for(error),
            )
        continue

    subscribers = result.get("subscribers", [])
    audit_subscriber = next((sub for sub in subscribers if ...), None)
    if not audit_subscriber:
        yield self.failed(... "is not set up as query access subscriber" ...)   # unchanged
    else:
        yield self.passed(...)                                                   # unchanged
```

### What moves in the CSV

| Row condition                                  | Before                      | After                                                      | Gate                             |
| ---------------------------------------------- | --------------------------- | ---------------------------------------------------------- | -------------------------------- |
| Subscriber present                             | PASS                        | PASS, same `ActualValue`                                   | 6.6 unchanged                    |
| Subscriber genuinely absent                    | FAIL "is not set up as ..." | FAIL, same `ActualValue`                                   | unchanged                        |
| Security Lake not enabled (`ResourceNotFound`) | FAIL "is not set up as ..." | FAIL "Security Lake is not enabled in this Region (...)"   | 6.3 admitted                     |
| `AccessDenied` on `ListSubscribers`            | FAIL "is not set up as ..." | ERROR "ListSubscribers failed: AccessDeniedException: ..." | 6.2 admitted, build log required |
| Region with no Security Lake endpoint          | FAIL or ERROR               | no row                                                     | 6.5 admitted                     |

The 4 baseline rows are the fourth line.

## Per-service migration

One row per service. "Handlers" counts the client's `except` clauses today; every one is replaced by `call_aws`. "Accessors" counts `_set` callers in the base; every one gets the guard. "Discriminator seeds" lists the `(operation, code[, message])` pairs already classified as "not configured" somewhere in that service's tree today, which become the initial table; the design adds none that the tree does not already assert. "Checks" names the modules whose body changes beyond the mechanical `"Error"` test, with the reason.

| Service                  | Handlers | Accessors | Discriminator seeds (operation → code [message])                                                                                                                                                                                                                                                                                    | Checks needing more than the mechanical edit                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Batch                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ------------------------ | -------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| guardduty                | 4        | 4         | `DescribeOrganizationConfiguration` → `BadRequestException` (currently FAIL in `_15`, `_16`, `_20`–`_25`)                                                                                                                                                                                                                           | `get_detector_id` returns `{"DetectorIds": [...]}` and the accessor passes it through unchanged; a pure helper `detector_id_of(success_dict) -> Optional[str]` on the base does the `[0]` for checks. `get_detector_details(region)` internally calls `get_detector_id`, tests `is_error`, and returns *that* error result if it fails, else reads the ID to make its own call (the one internal read Requirement 1.5 permits). `_02`–`_12`, `_17`–`_19`: "Unable to retrieve detector details" → `error()` naming operation and code. `_14`: `BadRequestException` + "not the master account" stays ERROR — not in the table; the check keeps its remediation text. `_01`: `None` from `get_detector_id` today means both "no detector" and "call failed"; after, an error result is an ERROR and an empty `DetectorIds` list is the FAIL. | 1 |
| macie                    | 16       | 7         | `GetClassificationExportConfiguration` → `ResourceNotFoundException`; → `AccessDeniedException` ["macie is not enabled"]. Extend the same two to `GetFindingsPublicationConfiguration`, `DescribeOrganizationConfiguration`, `GetAdministratorAccount`, `ListMembers` (the client already recognizes them there and discards them). | `_01`, `_02`, `_08`, `_10`: "Failed to retrieve" → discriminated FAIL or `error()`. `_07`, `_09`: same for `ListMembers` / `ListAccounts`. `_03`, `_04`: replace `is_macie_disabled_error` with `is_not_configured`; the method becomes a one-line delegate for this batch and is deleted in Phase 7. `_07`'s set-join is left alone (Non-Goal 2). Availability guard added (`macie2`, 22/34). `get_account_id` moves its `sts` acquisition to `__init__` (Requirement 1.11).                                                                                                         | 2                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| securityhub              | 16       | 9         | `GetEnabledStandards` → `InvalidAccessException` ["not subscribed to aws security hub"]; `ListEnabledProductsForImport` → same                                                                                                                                                                                                      | The `None` tri-state disappears: `get_enabled_standards` returns a dict or an error result; the two consumers test `is_not_configured` where they tested `is None`. `_02`: "Unable to retrieve" → `error()`. `get_organization` stops caching the error result (it writes into the shared `organizations` namespace, so this also protects `OrganizationsCheck`). `describe_organization_configuration`'s silent `except` gets logged.                                                                          | 2                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| securitylake             | 15       | 10        | Five `securitylake:*` operations → `ResourceNotFoundException`; → `UnauthorizedException`                                                                                                                                                                                                                                           | Worked example above. `is_security_lake_enabled` (probe) becomes `list_data_lakes` → `{"dataLakes": [...]}`; the base answers the bool after the guard. `_16`, `_17` masked FAIL → discriminated. Six accessors stop caching failures; `_prime_region_log_sources` stops seeding `[]` on failure. Availability guard added (17/34). `_log_aws_failure` deleted. `get_sqs_queue_encryption` acquires `sqs` inside the method today; it moves to `__init__` (Requirement 1.11).                                                                                                                                        | 3                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| s3                       | 2        | 1         | `GetPublicAccessBlock` → `NoSuchPublicAccessBlockConfiguration`                                                                                                                                                                                                                                                                     | `_01`–`_04` masked FAIL: "No public access block configuration found" becomes the discriminated FAIL; `AccessDenied` becomes ERROR. Same wording on the FAIL branch, so the gate sees no change where the configuration is genuinely absent.                                                                                                                                                                                                                                                           | 4                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| inspector                | 8        | 5         | none asserted in the tree today                                                                                                                                                                                                                                                                                                     | `_01`–`_04` masked FAIL: "NOT_ENABLED" was computed from `{}`; after, an error result is ERROR and the FAIL requires a real `state.status`. `get_account_status` extracts the account from `{"accounts": [...]}` after the guard. `list_organization_accounts` reads only the first page today (≤20 accounts); this is **not** fixed here — it would change the call count and could add rows — and is recorded as a deferred correction (Requirement 1.13, Non-Goal 5a). Availability guard added (32/34). | 4                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| accessanalyzer           | 9        | 2         | `ListDelegatedAdministrators` → `AWSOrganizationsNotInUseException`                                                                                                                                                                                                                                                                 | `is_access_analyzer_available` deleted; `_setup_clients` registers every Region. `_01` masked FAIL: `[]` on `AccessDenied` → ERROR. `_02`, `_03`, `_04`: bare `except Exception` inside `execute()` (→ `failed()` in `_02`, → `error()` in `_03`/`_04`) deleted; the error result path replaces all three (Requirement 4.11), and `_02` stops calling `self.session.client('organizations')` directly (Requirement 2.8). No availability guard (34/34).                                                                                                                                                                                                                              | 4                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| config                   | 22       | 5         | none asserted                                                                                                                                                                                                                                                                                                                       | `_01`, `_02`: "status could not be determined" → `error()`. `_09`: bare `except Exception` around `describe_configuration_aggregator_sources_status` → `error()` deleted; the accessor's error result replaces it (Requirement 4.11). `get_bucket_policy` returns `{"Policy": "<json>"}`; `get_bucket_location` returns `{"LocationConstraint": ...}`; callers extract. Two aggregator methods read only the first page today; recorded as deferred (Requirement 1.13), not fixed. `get_account_id` moves its `sts` acquisition to `__init__` (Requirement 1.11).                                                                                                                                                                                               | 5                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| cloudtrail               | 8        | 3         | none asserted                                                                                                                                                                                                                                                                                                                       | `_11`: "bucket owner could not be determined" → `error()`. `_08`, `_09`, `_10`: `except (ValueError, TypeError)` around delivery-timestamp parsing → `failed()` becomes a pure `CloudTrailCheck.parse_delivery_time(value) -> Optional[datetime]` helper with the check yielding `error()` on `None` (Requirement 4.11); a FAIL→ERROR flip on a branch the baseline never exercised, listed under Requirement 4.10. `describe_trails` returns `{"trailList": [...]}`. `get_account_id` moves its `sts` acquisition to `__init__` (Requirement 1.11).                                                                                                                                                                                                                                                                                                                                                                                           | 5                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ec2                      | 4        | 1         | none asserted                                                                                                                                                                                                                                                                                                                       | Mechanical, plus `get_account_id` moves its `sts` acquisition to `__init__` (Requirement 1.11).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | 5                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| waf                      | 14       | 9         | `GetWebACLForResource` → `WAFNonexistentItemException`; `GetLoggingConfiguration` → `WAFNonexistentItemException`                                                                                                                                                                                                                   | 11 code-dropping handlers → `call_aws`. `{"WebACL": None}` and `{"LoggingConfiguration": None}` synthesized responses go; the check discriminates the error result instead. `TRANSPORT_ERROR_CODES` import moves to `core.aws_errors`. `region_supports_service` delegates to `core.availability`. Availability guards for `amplify` (20/34) and `appsync` (31/34) added alongside the existing `apprunner` one.                                                                                           | 6                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| firewallmanager          | 2        | 2         | `GetAdminAccount` → `ResourceNotFoundException`                                                                                                                                                                                                                                                                                     | Code-dropping handler that also rewrote the message → `call_aws`; `_01` discriminates. `_01`'s hardcoded `us-east-1` is left alone (Non-Goal 2).                                                                                                                                                                                                                                                                                                                                                       | 6                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| shield                   | 7        | 4         | `GetSubscriptionState`, `DescribeSubscription`, `ListProtections`, `DescribeDRTAccess` → `ResourceNotFoundException`; `GetFunction` → `ResourceNotFoundException`; `GetWebACLForResource` → `WAFNonexistentItemException`                                                                                                           | `get_lambda_function`, `get_web_acl_for_resource`, and `get_cloudwatch_alarms_for_resource` acquire `lambda`, `cloudfront`, `wafv2`, and `cloudwatch` clients inside the method today; all four move to `__init__` (Requirement 1.11), and `get_web_acl_for_resource`'s ARN-based choice between `cloudfront` and `wafv2` becomes a choice between two attributes the wrapper already holds. `Message` normalization (`str(e)` → response message) changes every Shield ERROR row's `ActualValue`; gate 6.3. The synthesized `WAFNonexistentItemException` for a CloudFront distribution with no `WebACLId` stays — it is a real answer expressed in the error-result shape, and `_12` already reads it. Non-regionalized: availability returns True everywhere.                                                                                                                                        | 6                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| organizations            | 5        | 5         | `DescribeOrganization` → `AWSOrganizationsNotInUseException`; `ListPolicies` → `PolicyTypeNotEnabledException`                                                                                                                                                                                                                      | Client already canonical; gains transport guard only. All five accessors cache the error result today ("or Error key if failed") and stop.                                                                                                                                                                                                                                                                                                                                                                 | 6                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| iam                      | 3        | 1         | none                                                                                                                                                                                                                                                                                                                                | Client already complete; `Code="UnknownError"` becomes the exception type name. `list_users` stops caching the error result.                                                                                                                                                                                                                                                                                                                                                                               | 6                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| account                  | 1        | 1         | `GetAlternateContact` → `ResourceNotFoundException`                                                                                                                                                                                                                                                                                 | `Message` normalization. Non-regionalized.                                                                                                                                                                                                                                                                                                                                                                                                                                                             | 6                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| auditmanager             | 2        | 2         | `GetOrganizationAdminAccount` → `ResourceNotFoundException`; → `AccessDeniedException` ["please complete aws audit manager setup"]                                                                                                                                                                                                  | The return-less handler in `get_account_status` → `call_aws`. `_02`'s message-only match gains its code (the client's own comment identifies the code path). Base already uses a `NoClient` error result; it stays. Availability guard added (12/34).                                                                                                                                                                                                                                                      | 6                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| securityincidentresponse | 6        | 1         | `GetRole` → `NoSuchEntity`                                                                                                                                                                                                                                                                                                          | Transport guard (the client catches only `ClientError` today; `_discover_memberships` compensates with `except Exception`, which then becomes dead and is removed). Fallback tuple stops caching an error result. `get_organization_accounts` stops collapsing `"Error"` to `[]`. `_04`: ERROR "no active memberships" → FAIL (the listed ERROR→FAIL flip). Region resolution untouched (Non-Goal 6).                                                                                                       | 6                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |

The `auditmanager` `AccessDeniedException` code for "Please complete AWS Audit Manager setup" is inferred from the client's handler, which suppresses the `error` log for that message inside its `except ClientError`; the batch that migrates it should confirm the code from the build log of a not-yet-set-up account before committing the table entry, and record it in the table's comment.

---

## Error Handling

The three tiers, restated with what each one now guarantees.

### Tier 1 — client

Every method returns through `call_aws`. Guarantees: for every `ClientError` and every `BotoCoreError`, returns an error result with non-blank str `Code`, `Message`, and `Operation`, where `Code` is the AWS code for a `ClientError` and the exception type name for a `BotoCoreError`, and logs one structured `aws_call_failed` line at `error`; on success, returns a `Mapping`; raises `ClientContractError` if the closure returned anything else; and lets any other exception propagate unchanged, because that is a programming defect and belongs to Tier 3. Client construction (`ctx.get_client()`) is outside the guard: it is offline and deterministic, and its failure is a defect that `initialize()` surfaces to Tier 3. The client makes no judgement about what a code means.

### Tier 2 — base accessor and check

The accessor guarantees: an error result is never written to the cache; a missing wrapper produces a `NoClient` error result; the dict is returned unchanged. The check guarantees: `"Error"` is tested before any success-path key; an error result is classified through `is_not_configured`; a semantic code yields FAIL naming the condition, anything else yields ERROR naming `Operation`, `Code`, and `Message` with a scan-environment remediation. A Region the service does not serve yields nothing and costs no call.

### Tier 3 — orchestrator

Unchanged in behaviour; gains one `info` log line per check, `check_done check_id=… rows=…`, after the per-check `list()` and in the `except` (with `rows=synthetic`). Its guard now catches only programming defects, from any tier — a `ClientContractError` from `call_aws`, an `AttributeError` in a client closure or a check body, a `KeyError` from a check reading a success key that the response omitted, a client construction failure in `initialize()`. Each is a defect to fix, and the synthetic row's `Error running SRA-X-NN: <Type>: ...` is its report. A full-organization scan on a supported configuration produces zero such rows (Requirement 2.5), and any that appear in the gate's candidate scan reject that batch.

### The `ScanContext._set` backstop

Tier 1.5, if it must have a number: an error result offered to the cache is refused with a `warning`. It fires only if an accessor has lost its guard, and it turns that regression into a log line rather than a Region's worth of replayed errors.

---

## Correctness Properties

Each property is a statement the test suite holds. Requirement 6 is held by `util/gate.py` and `tests/unit/util/test_gate.py`, not by these properties, because it ranges over live scans. Enumeration is by reflection over the service packages and the registry wherever the property ranges over clients, accessors, or checks, so a service or check added later is discovered without a second edit. Where a property needs to *call* a client method or accessor, it does so through a per-method adapter (arguments, boto3 attribute, operation, success shape) declared in the test module, and a companion property asserts the adapter set equals the reflected set in both directions, so the adapters cannot quietly lag the code.

### Property 1: Every client method returns an error result on `ClientError`

For every public method of every `<Service>Client`, driven through its adapter, when the boto3 call the adapter names raises `ClientError({"Error": {"Code": "TestCode", "Message": "test message"}}, "<Operation>")`, the return value satisfies `is_error`, and its `Error` sub-dict has `Code == "TestCode"`, `Message == "test message"`, `Operation == "<Operation>"`. And exactly one `error`-level record was emitted on the `sraverify` logger whose message matches `^aws_call_failed operation=<Operation> region=\S+ code=TestCode message=test message$`.

Validates: Requirements 1.1, 1.2, 1.3, 1.8, 7.1.

### Property 2: Every client method returns an error result on any `BotoCoreError`

Same enumeration; the adapter's boto3 call raises `EndpointConnectionError(endpoint_url="https://x")` and, in a second case, `NoCredentialsError()`. Return satisfies `is_error`, `Code` equals the exception type name, `Operation` equals the literal the method passed to `call_aws`.

Validates: Requirements 2.1, 2.3, 7.2.

### Property 3: Programming defects propagate; contract violations are named

Same enumeration; the adapter's boto3 call raises `RuntimeError("boom")`, and the test asserts that `RuntimeError` propagates out of the client method unchanged. In a second case, the adapter's closure is patched to return `[]`, and the test asserts `ClientContractError` is raised. No error result is produced in either case.

Validates: Requirements 1.5, 1.9, 2.2, 7.3.

### Property 3a: The adapter table is complete and exact

For every service, the set of public method names discovered on the `<Service>Client` class by reflection equals the set of adapter keys declared for that service, and the same holds for accessors on the `<Service>Check` class (methods whose source contains `_set(` or `get_client(`). A missing adapter and a stale adapter are both failures, each named in the assertion message.

Validates: Requirements 7.4a, 7.5, 7.10.

### Property 4: Every client method returns a non-error result dict on success

Same enumeration; the adapter's boto3 call returns the success shape the adapter declares (a response dict, or a paginator whose `paginate()` yields the declared pages). Return is a `Mapping` and does not satisfy `is_error`.

Validates: Requirements 1.5, 7.4.

### Property 5: `call_aws` never catches `BaseException`

`fn` raising `KeyboardInterrupt` propagates out of `call_aws`.

Validates: Requirement 2.4.

### Property 6: No client method returns an erasing value or a bool

Static: an AST walk of every `client.py` finds no `try` statement at all — every handler has been replaced by `call_aws`, so after migration the client modules contain none — and no `try` around `ctx.get_client(` in any constructor. Every call to `call_aws` passes a string literal as its first argument. No method on any `<Service>Client` has a `bool` return annotation, and the name `is_access_analyzer_available` appears nowhere in `services/`.

Validates: Requirements 1.4, 1.6, 1.7, 1.10, 1.11, 1.12, 2.2, 2.6, 5.9.

### Property 6a: No check module reaches the SDK directly or catches inside `execute()`

Static: an AST walk of every `services/*/checks/sra_*.py` finds no `Attribute` chain ending in `session.client`, `_ctx.get_client`, `boto3.client`, or `boto3.Session`, and no `Try` node anywhere inside a function named `execute`. And an AST walk of every `services/*/client.py` finds every `Call` whose function is an `Attribute` named `get_client` inside a function named `__init__`, and nowhere else.

Validates: Requirements 1.11, 2.8, 4.11, 7.5b.

### Property 7: Every accessor refuses to cache an error result and re-issues

For every method on every `<Service>Check` base class that calls `_set`, with a `MagicMock` context whose `_has` returns `False` and a mock client whose relevant method returns an error result: `_set` is not called; the return value is that error result; a second invocation calls the client method a second time.

Validates: Requirements 3.1, 3.2, 3.3, 3.4, 7.5.

### Property 8: Every accessor produces `NoClient` and does not cache it

Same enumeration; `check._clients` is empty. Return satisfies `is_error` with `Code == NO_CLIENT_CODE`; `_set` not called.

Validates: Requirements 3.7, 7.5.

### Property 9: Successful responses are cached under the same namespace and key

Same enumeration; mock client returns a success dict. `_set` is called exactly once, with the service `NAMESPACE` and the key the adapter declares, and the value stored is the success dict itself; a second invocation with `_has` returning `True` does not call the client. The value differs from today's for every accessor whose client used to extract a list or scalar; the namespace, key, and call count do not. This is the existing `test_service_migration_property` Property 8(c), kept.

Validates: Requirement 3.6.

### Property 10: `ScanContext._set` refuses an error result

A real `ScanContext` given `_set("ns", "k", error_result(...))`: `_has("ns", "k")` is `False` afterward and a `warning` was logged. Given a success dict: stored as before. Given a malformed near-error result (`{"Error": {"Code": ""}}`): stored, because `is_error` is `False` for it and the backstop must not guess — Property 3's `ClientContractError` and Property 1's shape assertion are what keep a malformed error result from ever being produced.

Validates: Requirement 3.2 (backstop).

### Property 11: `is_not_configured` is total and conservative

For every service base class's `NOT_CONFIGURED_ERRORS`: for every declared `(operation, code, needle)`, an error result with that operation and code (and a message containing the needle, when one is declared) returns `True`; the same code under an undeclared operation returns `False`; an undeclared code under a declared operation returns `False`; a declared code with a declared needle and a message lacking it returns `False`; an empty `Error` dict returns `False`. Property-based over `cell_text()` messages for the needle cases.

Validates: Requirements 4.2, 4.3, 4.5, 4.6, 7.7.

### Property 11a: Every table entry carries evidence, and no placeholder survives

For every service base class's `NOT_CONFIGURED_ERRORS`, every value is a `NotConfigured` whose `evidence` is a non-blank string (already enforced at construction; asserted here so a table built any other way fails), and — for every service none of whose `(service, method)` pairs remains in `_PENDING` — no `evidence` string in that service's table begins with `TO CONFIRM`. A placeholder therefore fails the run the moment its service's last adapter leaves the pending set, not at the end of the migration.

Validates: Requirement 4.6a.

### Property 12: The discriminator table is declared once per service

For every registered check class, `"NOT_CONFIGURED_ERRORS" not in vars(cls)`; and the value read through the class equals the value declared on its service base. Also: `__init_subclass__` raises `CheckIdentityError` for a synthetic `sra_*` module declaring one.

Validates: Requirement 4.4.

### Property 13: No confessing `failed()` and no `except`-to-`failed()`

AST walk of every `services/*/checks/sra_*.py`: no call to `self.failed` whose `actual_value` keyword is a string literal or f-string whose literal portions match the Requirement 4.7 patterns, or whose f-string interpolates a name bound by an `except ... as` clause; and no `except Exception` handler inside `execute` that contains a `self.failed` call.

Validates: Requirements 4.7, 4.11, 7.6.

### Property 14: Every check yields only ERROR when every accessor fails non-semantically

For **every** registered check (catalog-wide, by reflection over `all_checks()`, not a sample): construct it, attach a `MagicMock` context with `regions=["us-east-1"]`, `audit_accounts=["111122223333"]`, `log_archive_accounts=["444455556666"]`, and a warm `get_account_info`; patch every method on its service base class whose source contains `_set(` or `get_client(` (the accessors, by the same rule Property 3a uses) to return `error_result(code="TestDenied", message="denied", operation="<name>")`; run `list(check.execute())`. Assert: at least one `Finding`; every `Finding` has `status is Status.ERROR`; every `actual_value` matches `^\S+ failed: TestDenied: `; no exception escapes. Checks whose only accessor calls are guarded by the availability lookup are exercised with the lookup patched to `True`.

This replaces the first draft's one-check-per-batch sample, which could not establish Requirement 4.1 for the catalog. It needs no consumer manifest: the accessors are found by reflection and the check's own control flow does the rest.

Validates: Requirements 4.1, 4.3, 4.8, 4.12, 7.5a.

### Property 14a: Discriminated error results yield FAIL

For every service base class with a non-empty `NOT_CONFIGURED_ERRORS`, and for every check of that service whose accessors include one whose client operation is in the table: same harness as Property 14, but the accessor returns an error result matching a declared `(operation, code, needle)`. Assert every `Finding` from that check is FAIL or ERROR (a check may still ERROR on a second, unpatched accessor) and at least one is FAIL. This does not assert the FAIL's wording — that is a per-check decision the gate reviews — only that the discriminator's `True` reaches `failed()`.

Validates: Requirements 4.2, 4.9.

### Property 14b: An unsupported Region yields no row and no call

For every check whose module calls `service_available_in_region`: same harness as Property 14, with the lookup patched to return `False` for `us-east-1` and the accessors patched to record calls. Assert `execute()` yields zero findings and no accessor was called.

Validates: Requirements 5.5, 5.6.

Validates: Requirement 4.8.

### Property 15: Availability lookup is fail-open and partition-aware

`service_available_in_region(s, "no-such-service", "us-east-1")` is `True` and logs a `warning`; `("apprunner", "us-west-1")` is `False`; `("apprunner", "us-east-1")` is `True`; `("shield", r)` is `True` for every `r`; `("organizations", "us-gov-west-1")` is `True`; `("security-ir", "us-east-1")` is `True`; `("apprunner", "us-gov-west-1")` is `True`. A second call with the same arguments does not re-read the endpoint data.

The last case is a deliberate behaviour change from `WAFCheck.region_supports_service`, which returned `False` there and whose `.tmp/verify_waf06.py` exercise asserted it. App Runner genuinely has no GovCloud endpoints, so `False` was factually right — but the data that produces it, an empty regional list for a recognized service, is the same data `security-ir` produces in every partition because botocore ships no endpoint entry for it at all. The two cannot be told apart, and reading the empty list as "absent" would suppress every Security Incident Response row in every Region. Fail-open costs one ERROR row per Region for `SRA-WAF-06` in a GovCloud scan; fail-closed would cost five checks' worth of silence in every scan. The test asserts `True` and its docstring records this paragraph.

Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.8, 5.11, 7.8.

### Property 16: Availability call sites name a literal

Static: every call to `service_available_in_region` in `services/` passes a string literal as `service_id`, and that literal is in the candidate set recorded in Requirement 5.7.

Validates: Requirement 5.7.

### Property 17: The transport constant is single-sourced

`TRANSPORT_ERROR_CODES == frozenset(t.__name__ for t in _TRANSPORT_EXCEPTIONS)`, and `services/waf/client.py` no longer defines its own.

Validates: Requirement 2.7.

### Property 18: Test identifiers name the target

Every parametrized test in the six reflection-driven modules has an id of the form `<service>.<Class>.<method>` or `<service>.<operation>.<code>`, asserted by inspecting `request.node.callspec.id` in a fixture.

Validates: Requirement 7.11.

### Property 19: The contract tests are offline

`conftest.py` gains an autouse fixture that patches `botocore.httpsession.URLLib3Session.send` to raise; the whole suite still passes. (The existing suite already makes no AWS call; this fixture proves it rather than asserting it.)

Validates: Requirements 7.9.

### Property 20: The library entry point writes nothing to stdout

With `sys.stdout` replaced by a stream whose `write` raises `AssertionError("library wrote to stdout")`, `SRAVerify.run_checks()` over the three-probe isolated catalog from `test_exit_codes_scan.py` (one PASS, one FAIL, one ERROR, with the ERROR probe raising into the orchestrator's guard) completes and returns three `Finding`s. A fourth probe whose mock client returns an error result is added so the `call_aws` → accessor → `is_not_configured` → `error()` path is on the run. Separately, `run_checks(check_id="SRA-TYPO-99")` raises `UnknownCheckError` and the raising stream was never called. `show_progress` is left at its default of `False`; a second case passes `show_progress=True` and asserts the stream *is* called, so the test proves it can see a write and is not vacuous.

Validates: Requirements 8.1, 8.4, 8.5, 8.6.

### Property 21: No library module can write to stdout

Static, over every `.py` under `core/`, `services/`, and `utils/outputs.py` (and `__init__.py` with its docstring stripped): the AST contains no `Call` whose `func` is `Name(id="print")`; no `Attribute(value=Name(id="sys"), attr in {"stdout", "__stdout__"})`; no `Call` whose `func` resolves to `warnings.warn`; and no `Call` to `logging.StreamHandler` or `logging.basicConfig` outside `core/logging.py`. And, at runtime: `logging.getLogger().handlers` has exactly one handler whose `stream is sys.stderr`, and every handler on `logging.getLogger("sraverify")` has `stream is sys.stderr`.

Validates: Requirements 8.2, 8.3, 8.7, 8.8.

---

## Testing Strategy

### Unit tests

`tests/unit/core/test_aws_errors.py`: `call_aws` on each of the three exception paths and on success; `error_result` rejects an empty field; `is_error` on dicts with and without `Error`, on lists, on `None`, and — for each of `Code`, `Message`, `Operation` — with the key missing, blank, whitespace-only, and non-`str`, every one of which must be `False`; `error_result` on the same inputs, every one of which must raise; `is_not_configured` on a hand-built table covering every branch. `tests/unit/core/test_availability.py`: the Property 15 cases against real botocore data.

### Property and reflection tests

Seven new modules under `tests/property/`, listed in the module inventory. Six are reflection-driven over the service packages or the registry and carry the xfail ledger described below; the seventh, the stdout contract, runs the real entry point and passes from Phase 0. The enumeration idiom follows `test_catalog_meta_property.py`: snapshot the collection at import into a module constant, `parametrize` over it with explicit `ids`, and assert the snapshot is non-trivially sized (`>= 18` clients, `>= 60` accessors) so an enumeration bug reads as a failure rather than a vacuous pass.

**Discovering client methods.** `pkgutil.iter_modules` over `sraverify.services`, import `<svc>.client`, select classes whose name ends in `Client` (this includes `IAM_Client`), then `inspect.getmembers(cls, inspect.isfunction)` filtered to names not starting with `_`. This is discovery only; it decides *which* methods must be covered, not how to call them.

**Driving them: the adapter table.** The first draft called every method with `"arg"` for each required parameter and had every boto3 call return `{}`. That cannot work against the real tree: `ShieldClient.get_web_acl_for_resource` branches on `"cloudfront" in resource_arn`, `ConfigClient.get_bucket_location` maps a `None` member to `'us-east-1'`, `InspectorClient.batch_get_account_status` takes a list, several methods index a required response member, and paginators need a `paginate()` that yields pages. Placeholder inputs would fail — or, worse, produce an error result — for harness reasons and be indistinguishable from a contract violation. So each test module declares one adapter per method:

```python
@dataclass(frozen=True)
class ClientAdapter:
    method: str                 # "get_web_acl_for_resource"
    args: tuple                 # ("arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/x/y",)
    boto_attr: str              # "wafv2_client"        — which underlying boto3 client the method uses
    boto_method: str            # "get_web_acl_for_resource"
    operation: str              # "GetWebACLForResource" — the literal passed to call_aws
    success: Mapping | tuple    # a response dict, or a tuple of paginator pages

SHIELD_ADAPTERS: tuple[ClientAdapter, ...] = (...)
```

The harness constructs the client with a `MagicMock(spec=ScanContext)` whose `get_client(name, region=...)` returns a per-name `MagicMock`; for each adapter it configures `getattr(client, boto_attr).<boto_method>` to raise or to return `success` (or `get_paginator(...).paginate.return_value = success` for the tuple form), calls `getattr(wrapper, method)(*args)`, and asserts. Property 3a asserts, per service, that `{a.method for a in ADAPTERS} == discovered_methods` in both directions, so the table is fixture data with a completeness proof rather than a maintained allowlist. Writing the 100-odd adapters is real work and is the honest price of a test that actually exercises the code; it is also the price that the existing `test_service_migration_property.py` already pays for one method per service in its `_invoke_<svc>` functions, which are the pattern being generalized.

**Driving accessors.** Discovery over `<svc>.base` is every public method in `vars(<Service>Check)` — the class's own dict, so inherited `SecurityCheck` methods are excluded and nothing else is. The first draft used "source contains `_set(` or `get_client(`", which misses any accessor that delegates through a private helper: `SecurityIncidentResponseCheck.list_memberships` is `return self._discover_memberships()[1]` and `get_membership` goes through `_sir_client(...)`; neither string appears in either body. The `AccessorAdapter` table for a base therefore classifies *every* public method as one of `accessor` (driven through Properties 7–9, with `args` and the `client_method` it ultimately delegates to), `helper` (a pure function over a success dict, asserted never to touch `self._ctx`), or `table` (`NOT_CONFIGURED_ERRORS`); the equality assertion is over all of them, so a method with no classification fails. The wrapper installed into `check._clients[region]` is a `MagicMock` whose `client_method` returns an error result (Property 7), a success dict (Property 9), or is absent because `_clients` is empty (Property 8). The `_concrete()` wrapper from the migration test is reused, since `SecurityCheck` is abstract.

**Driving checks.** Property 14 needs no adapters. It reflects over `all_checks()`, patches the accessors found by the same source-text rule, and lets `execute()` run. A check's control flow is the thing under test, so the check itself supplies the arguments.

**The strict-xfail ledger.** Until every method is migrated, the client and accessor tests would fail for unmigrated methods. Rather than an allowlist of migrated services (a maintained list, which Requirement 7.10 forbids as the enumeration mechanism), each new test module carries one module constant, `_PENDING: frozenset[tuple[str, str]]` of `(service, method)` pairs, and a parametrize hook that applies `pytest.mark.xfail(strict=True, reason="pending batch N")` to ids whose pair is in it. The key is the pair and not the service because `macie` and `waf` each already have one conforming method beside many non-conforming ones: a service-level mark would XPASS strictly on `get_classification_export_configuration` and `list_services`, and no mark would fail on their siblings. `strict=True` means that when a method is migrated and its test starts passing, the run fails until its pair is removed. The set starts at every discovered pair — including the two reference methods, because they emit `{"Error": {"Code", "Message"}}` with no `Operation` and the strict `is_error` does not recognize that as an error result until their batch adds the key — shrinks with every batch, and is deleted — along with the hook — in Phase 7. It cannot outlive the migration because a stale entry is itself a test failure. Property 11a's placeholder-evidence clause keys on the same set: a service's table may hold `TO CONFIRM` only while at least one of that service's pairs is pending.

**The stdout harness.** `test_exit_codes_scan.py` already has what Property 20 needs: `_isolated_registry` swaps the 158-check catalog for three synthetic probes, `_NoAwsSession` refuses every client construction, and `_seeded_scan_context` pre-warms `get_account_info()` so `run_checks()` runs end to end with zero AWS calls. The new module reuses the `probe_scan` fixture and adds one thing: a `_RaisingStdout` class whose `write` and `writelines` raise, installed with `monkeypatch.setattr(sys, "stdout", ...)` for the duration of the call. `capsys` is deliberately not used — it would capture a `print()` and let the test pass; the point is that the write fails at the call site with a traceback naming the file and line. The `show_progress=True` counter-case exists so that a future refactor which makes `run_checks()` bypass `sys.stdout` for some other reason does not leave the test passing for the wrong reason.

The static half of Property 21 is the same AST-walk idiom as Property 6 and Property 13, over a different module set. It runs in well under a second and has no false-positive surface: a legitimate `print()` in a library module does not exist by definition, and `core/logging.py` is the one file permitted to construct a handler.

### Integration — the acceptance gate

Two scans per batch, compared as multisets, with evidence from structured logs. Not a positional diff, and not a comparison against a scan taken weeks earlier.

**Why two scans and not one.** The first draft compared each batch's after-scan against the 2026-09-12 CSV. Any resource that changed in the organization between then and the gate — a detector enabled, a subscriber added, an account suspended — would show up as a verdict change with no code cause, and the gate would have to reject it or a human would have to wave it through. Running the reference tree and the candidate tree back to back (two CodeBuild runs, same `GitBranch` parameter pointed at each commit) shrinks that window from weeks to minutes. It does not close it: a detector enabled between the two runs still shows up as a difference with no code cause. So the gate's policy for an unexplained difference is reject-and-re-run (step 9), never accept-as-noise, and the two-scan design is what makes re-runs rare enough to be affordable. The 2026-09-12 scan keeps one job, which is supplying the aggregate counts (112 confessing rows, 158 checks) that the gate's totals are measured against.

**Why multisets.** `SRA-WAF-02` emits one row per load balancer; `SRA-SHIELD-03` one per protection; `SRA-IAM-01` one per IAM user. Under the logical key (`AccountId`, `AccountType`, `Region`, `CheckId`) those are several rows, and a dict keyed that way overwrites them while a join cross-multiplies them. The first draft's key was unique only for single-row checks.

**Why structured logs.** The buildspec fans accounts out with `parallel -j5`, so one CloudWatch stream interleaves five processes. Free-text correlation of "an error on this operation for this account in this Region" is not reliable there. Two changes fix it at the source: the buildspec redirects each invocation's stderr to its own file, and the scanner emits two machine-readable lines — `aws_call_failed operation=… region=… code=… message=…` from the guard and `check_done check_id=… rows=…` from the orchestrator. Within one invocation execution is single-threaded, so every `aws_call_failed` line belongs to the check whose `check_done` follows it.

Procedure, implemented by `util/gate.py`:

1. **Scan both trees.** Same CodeBuild project, same accounts, same explicit `--regions us-east-1,us-east-2,us-west-1,us-west-2`, same `--audit-account` and `--log-archive-account`; reference commit then candidate commit, back to back. Each run produces a consolidated CSV and a `stderr/` directory of per-invocation files. Both artefact sets and their SHA-256 digests go to the findings bucket under `gate/batch-N/{reference,candidate}/`; the digests and the two commit hashes go into the gate's notes file, kept with those artefacts.
2. **Parse evidence.** From each `stderr/<account>-<type>.log`, build the ordered list of `check_done` markers and attach to each check the `aws_call_failed` lines that precede it since the previous marker. Build the check→operation dependency statically: for each check module, the accessor names it calls (AST); for each accessor, the client method it delegates to (AST of the base); for each client method, the `call_aws` literal (AST of the client). This is derived, not maintained.
3. **Split by scope.** Rows whose `Service` is in the batch are in scope. Every other row must be present in both scans with all 16 cells identical; any difference there is a regression in shared code and rejects.
4. **Group and pair.** Group in-scope rows by logical key. Within each group: pair rows identical on all 16 cells; then pair remaining rows on `ResourceId`; then pair remaining rows one-to-one by admitted transition (step 5), a candidate row pairing with at most one reference row. Rows still unpaired are added (candidate-only) or removed (reference-only) and go to step 6.
5. **Judge paired rows.** `Status` transitions:
   - PASS → anything, anything → PASS: **reject**.
   - FAIL → ERROR: admit only if the candidate invocation's evidence for that check and Region includes an `aws_call_failed` line whose `operation` is in the check's dependency set and whose `code` `is_not_configured` returns `False` for. Otherwise reject.
   - ERROR → FAIL: admit only if `(CheckId)` is in the Requirement 4.10 list. Otherwise reject.
   - Unchanged `Status`, changed `ActualValue`: admit if ERROR and the new value matches `^\S+ failed: \S+: `; admit if FAIL and the check is in this batch's declared discriminated-wording list; otherwise reject.
   - `ResourceId` changed: admit only alongside an admitted `Status` or `ActualValue` change on the same pair.
   - Any other cell changed: **reject**.
6. **Judge unpaired rows.** Added: admit only if the reference invocation's evidence for that check shows a synthetic-row condition (`rows=synthetic` on its `check_done`, or an `Error running` line). Removed: admit only if `service_available_in_region(<service>, Region)` is `False`. Anything else rejects.
7. **Masked-FAIL sweep.** For every candidate FAIL row from a check named in Requirement 4.9, the candidate evidence for that check and Region contains no `aws_call_failed` line on a dependency operation with a non-semantic code. A hit rejects.
8. **Totals.** Over the whole candidate scan: confessing-pattern FAIL count is non-increasing per batch and zero once the batch containing the last of the 25 modules has landed; distinct `CheckId` count is 158; count of `ActualValue` beginning `Error running SRA-` is zero.
9. **Re-run before rejecting on ERROR.** A pair that is ERROR on exactly one side is re-run for that account with `--check` against both trees before it is counted, so throttling is not mistaken for a regression. The re-run is recorded in the gate notes.

`util/gate.py` takes the two CSV paths and the two `stderr/` directories, exits non-zero on any rejection with the offending logical keys and rows listed, and is itself tested by `tests/unit/util/test_gate.py` against synthetic CSV pairs and stderr sets that cover every admitted and every rejected transition above. `.tmp/diff2.py` and `.tmp/impact.py` are its ancestors and are deleted when it lands.

### Manual validation

One `sraverify --check` per migrated check against a single account, with `--debug`, reading the log to confirm that every `call_aws` failure line names operation, Region, code, and message. For the batch containing Security Lake, one deliberate run with a role lacking `securitylake:ListSubscribers` to observe the 4 rows flip to ERROR with the expected `ActualValue`. For the batch containing WAF, one run including `us-west-1` to confirm `SRA-WAF-06` still emits no row there.

### What is not tested as a property

That the discriminator tables are *correct* — that `UnauthorizedException` from `securitylake:ListSubscribers` really does mean "not enabled". That is an assertion about AWS behaviour, verified against the live service in the gate and recorded in each table entry's comment, not something a mock can establish. The tests hold that the tables are declared once, read conservatively, and enumerable; the gate holds that they are true.

---

## Migration Order

### Phase 0 — Scaffolding and baseline (no service edits)

| Step | Deliverable                                                                                                                                                                                                                                                                                                                |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0.1  | Archive the baseline CSV and CodeBuild log export (Requirement 6.12)                                                                                                                                                                                                                                                       |
| 0.2  | `core/aws_errors.py` with unit tests                                                                                                                                                                                                                                                                                       |
| 0.3  | `core/availability.py` with unit tests; `WAFCheck.region_supports_service` becomes a one-line delegate                                                                                                                                                                                                                     |
| 0.4  | `SecurityCheck.NOT_CONFIGURED_ERRORS`, `is_not_configured`, `_remediation_for`; the `__init_subclass__` rule                                                                                                                                                                                                               |
| 0.5  | `ScanContext._set` backstop with its property test                                                                                                                                                                                                                                                                         |
| 0.6  | The six reflection test modules, with `_PENDING` holding every `(service, method)` pair except the two conforming client methods and the two guarded accessors; suite green                                                                                                                                                                                |
| 0.7  | `test_stdout_contract_property.py` (Properties 20 and 21). Both halves are expected to pass against the *current* tree — this step proves the convention holds today, before the sweep starts touching every client and base module. If either fails here, that is a pre-existing stdout leak and is fixed in this step.   |
| 0.8  | `core/errors.py`: `ClientContractError`. `main.py`: the `check_done` line. Both are behaviour-neutral for the CSV.                                                                                                                                                                                                         |
| 0.9  | ~~`2-sraverify-codebuild-deploy.yaml`: per-invocation stderr capture and upload.~~ **Withdrawn.** Written and validated, then reverted: the template is published publicly and the artefact's only consumer is `util/gate.py`, a development tool. `util/local_scan.py` produces the same evidence locally, and did so for all twelve gate runs.                                                             |
| 0.10 | `util/generate_iam_policy.py` recognizes `ctx.get_client(...)` and `call_aws("<Op>", ...)`. Run against the current tree; the output is compared to the committed artefacts and any difference is investigated *before* migration, because a difference here means the committed policy has already drifted from the code. |
| 0.11 | `util/gate.py` with `tests/unit/util/test_gate.py`; then run it against a scan versus itself (zero differences) to prove the harness end to end.                                                                                                                                                                           |

Phase 0 changes no client, base, or check behaviour and no CSV cell. The full 3026-test suite passes plus the new tests. Step 0.9 is the one infrastructure change and is deployed on its own; step 0.11's self-comparison is the only scan Phase 0 needs.

### Phases 1–6 — Service batches

Each batch: migrate the batch's clients, bases, discriminator tables, and checks; remove the batch's `(service, method)` pairs from `_PENDING`; run the suite; scan the reference commit and the candidate commit back to back; run `util/gate.py` on the pair, scoped to the batch; land or fix.

| Batch | Services                                                                                          | Why this order                                                                                                                                                                                                                                                 |
| ----- | ------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1     | guardduty                                                                                         | 14 of the 25 confessing modules; the third error-result shape (`ERROR:` string); the `BadRequestException` operation split that motivated the operation-keyed table. Small client (4 methods). Proves the whole pattern on the largest service.                    |
| 2     | macie, securityhub                                                                                | The remaining 7 confessing modules, 104 of the 112 baseline confessing rows; the two overloaded codes classified by message; the `None` tri-state. Macie's reference method is replaced by the general mechanism, which proves the generalization is faithful. |
| 3     | securitylake                                                                                      | The 8 measured masked-FAIL rows; the worst client (15 erasing handlers, `_log_aws_failure`); 10 accessors, six of them deliberately caching failures; the bool probe; first availability guard on a new service (17/34).                                       |
| 4     | s3, inspector, accessanalyzer                                                                     | The unmeasured masked-FAIL sites. Gate step 7 is the point of this batch. Access Analyzer's live probe is removed here.                                                                                                                                        |
| 5     | config, cloudtrail, ec2                                                                           | The remaining bare-empty clients (34 handlers); three confessing modules; the four `get_account_id` duplicates brought to the contract.                                                                                                                        |
| 6     | waf, firewallmanager, shield, organizations, iam, account, auditmanager, securityincidentresponse | The clients already carrying a code or a message: `call_aws` adoption, `Message` normalization, transport guard, accessor guards. Lowest verdict risk; largest `ActualValue` churn on ERROR rows (gate 6.3). The one ERROR→FAIL flip.                          |

After Batch 5 the confessing-FAIL count is zero and stays zero (Property 13 holds catalog-wide from Phase 0; the gate's row count confirms it against a live scan). After Batch 6, `grep -rn "except" services/*/client.py` returns nothing.

Batches 4 and 5 may be combined if Batches 1–3 have shaken out the harness; Batch 6 may be split if its gate diff is too large to review in one sitting. The gate does not care how the services are grouped.

### Phase 7 — Close

| Step | Deliverable                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 7.1  | Delete `_PENDING` and the xfail hook from all six test modules; suite green with no xfails                                                                                                                                                                                                                                                                                                                                                     |
| 7.2  | `MacieCheck.is_macie_disabled_error` deleted (Batch 2 left it as a deprecated delegate for one batch in case of rollback); `securitylake._log_aws_failure` confirmed gone                                                                                                                                                                                                                                                                                |
| 7.3  | `creating_checks_best_practices.md`: replace the "Client method" canonical shape with the `call_aws` shape; add the discriminator table and the check-body pattern; remove the `securitylake_16/17`, `_log_aws_failure`, and `accessanalyzer` probe entries from Known Defects; add the `NOT_CONFIGURED_ERRORS` shadowing rule to the identity rules                                                                                                     |
| 7.4  | `structure.md`: same canonical-shape replacement; `core/aws_errors.py` and `core/availability.py` in the module tree; the `_set` backstop noted under ScanContext                                                                                                                                                                                                                                                                                        |
| 7.5  | `tech.md`: `util/gate.py` under Commands; note that the Access Analyzer probe's `ListAnalyzers` call is gone (IAM policy unchanged — the permission is still needed by `SRA-ACCESSANALYZER-01`). Logging section: replace "Never call `print()` from library or check code" with the Stdout_Contract statement and a pointer to `test_stdout_contract_property.py`; same edit in `creating_checks_best_practices.md`'s Logging section (Requirement 8.9) |
| 7.6  | `docs/checks.txt` regenerated and `cmp`'d — expected identical, since no `CheckMeta` changed                                                                                                                                                                                                                                                                                                                                                             |
| 7.7  | One final reference/candidate pair with all batches landed — reference is the last commit before Batch 1, candidate is HEAD — run through `util/gate.py` unscoped; totals per gate step 8; the pair archived as `gate/final/`                                                                                                                                                                                                                            |

---

## Decision Points Summary

| #   | Decision                                                                     | Resolution                                                                                                                                                                                                                                                                                                                                                                                        |
| --- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | One shared guard vs. three `except` clauses per method                       | **`call_aws`.** 144 hand-written handlers become one. Contract tests exercise the guard directly and every method through it via adapters.                                                                                                                                                                                                                                                        |
| 1a  | What the guard catches: `Exception`, or `ClientError` + `BotoCoreError` only | **`ClientError` + `BotoCoreError`, nothing else.** Programming defects propagate to the orchestrator's synthetic row, which is the report a defect should get. The first draft's catch-all would have turned a typo in a closure into a plausible ERROR row per Region, indefinitely. Never `BaseException`.                                                                                      |
| 2   | `Message` from `e.response` vs. `str(e)`                                     | **`e.response["Error"]["Message"]`**, `str(e)` only as fallback. Changes every ERROR `ActualValue` from shield, account, auditmanager, guardduty; admitted by gate 6.3.                                                                                                                                                                                                                           |
| 3   | Where the operation name lives                                               | **In the error result**, as `Operation`. `ClientError` provides it free; `call_aws` receives it for logging anyway. One-argument `is_not_configured(error)`.                                                                                                                                                                                                                                          |
| 4   | A non-dict success result from a client                                      | **`ClientContractError` outside the guard.** A client bug becomes a synthetic ERROR row naming the contract — the orchestrator's guard used for exactly what it is for. Property 3 catches it before it ships. Requirement 1.9 is worded to permit this.                                                                                                                                          |
| 5   | Availability lookup's default on any uncertainty                             | **Available.** Unknown id (warning), empty regional list (non-regionalized or no data), any exception (debug). `False` only on a positive absence. `security-ir` having no endpoint data at all is what forced the empty-list rule to be explicit.                                                                                                                                                |
| 6   | Central `_set` backstop: none / raise / skip                                 | **Skip with a `warning`.** Raising would abort a check for a redundancy; none would leave the next unguarded accessor undetected. Backstop only — it cannot see `[]`/`None`-encoded failures, which is why those nine sites are named in Req 3.4.                                                                                                                                                 |
| 7   | Discriminator as predicate method vs. declarative table                      | **Table**, read by one shared predicate. Enumerable by tests (Property 11), auditable as data, and the `__init_subclass__` rule can forbid a check from declaring one. The Macie predicate is replaced, not wrapped.                                                                                                                                                                              |
| 8   | Accessor extracts on success vs. passes the dict through                     | **Passes through.** Extraction after the `"Error"` test in the check, or in a pure helper taking the success dict. Otherwise the list/dict hazard moves up one tier.                                                                                                                                                                                                                              |
| 9   | Tracking migration progress in tests: allowlist vs. xfail | **Strict xfail keyed on a shrinking set of `(service, method)` pairs.** Per pair, not per service, because `macie` and `waf` each hold one conforming method beside many non-conforming ones. A migrated pair left in the set fails the run; the set is deleted in Phase 7. Reflection remains the enumeration mechanism (Req 7.10). |
| 10  | Gate cadence: per service vs. per batch                                      | **Per batch, scoped per service.** Two scans per batch (reference and candidate). Out-of-scope services must be 16-cell identical across the pair, which also tests the shared code.                                                                                                                                                                                                              |
| 11  | Removing Access Analyzer's live probe                                        | **Removed outright**, not replaced by the availability lookup — `accessanalyzer` is 34/34 in the endpoint data, so the lookup would never say no. One AWS call per Region saved; `AccessDenied` stops being read as "available".                                                                                                                                                                  |
| 12  | Stdout contract: dynamic test, static test, or both                          | **Both.** The dynamic test (a raising stream, not `capsys`) proves the real entry point is clean on the paths it exercises and fails at the offending line. The static test closes the branch-coverage gap the three-probe catalog leaves. Neither alone suffices; together they cost one module and a few hundred milliseconds. Scoped to library modules — the CLI writes to stdout on purpose. |
| 13  | Gate comparand: the 2026-09-12 CSV vs. a same-window reference scan          | **Same-window reference scan.** Two runs per batch, reference commit then candidate commit. Narrows the drift window from weeks to minutes; an unexplained difference is re-run, not waved through. The 2026-09-12 scan supplies aggregate counts only. Cost: one extra CodeBuild run per batch.                                                                                                                                                  |
| 14  | Gate matching: unique key vs. multiset                                       | **Multiset under the logical key**, paired exact → `ResourceId` → admitted transition. The unique key was wrong for every check that emits one row per resource (`SRA-WAF-02`, `SRA-SHIELD-03`, `SRA-IAM-01`).                                                                                                                                                                                    |
| 15  | Gate evidence: merged CloudWatch stream vs. per-invocation stderr + markers  | **Per-invocation stderr files and two structured log lines** (`aws_call_failed`, `check_done`). Costs one `info` line per check in `main.py`, and a local scan runner rather than the buildspec edit first proposed here. Buys deterministic attribution of every failure to one check in one account, which free-text parsing of a `parallel -j5` merged stream cannot give.                                                                            |
| 16  | Test harness inputs: placeholders vs. per-method adapters                    | **Adapters, with a reflection-equality proof.** Placeholders cannot drive methods that branch on an ARN or index a required member. The adapter table is fixture data; Property 3a stops it lagging. ~100 adapters to write; the migration test's `_invoke_<svc>` functions are the pattern.                                                                                                      |
| 17  | Pagination gaps found during the rewrite                                     | **Recorded, not fixed.** Five first-page-only methods stay first-page-only. Fixing them changes call counts and can add rows, which Non-Goal 2 forbids. Deferred to a follow-up with its own gate.                                                                                                                                                                                                |

---

## Constraints Honored

- Zero new runtime dependencies. `boto3`/`botocore` already provide `ClientError`, the transport exceptions, and the endpoint data; `functools.lru_cache` and `typing.TypedDict` are stdlib.
- The 16-column CSV schema and column order are unchanged. Every change this design makes lands in the `Status`, `ActualValue`, `Remediation`, and `ResourceId` cells of rows on failure paths, and in row presence for Regions without an endpoint.
- No `CheckMeta` changes. `docs/checks.txt` is regenerated and compared, and is expected identical.
- No new AWS API operation. One is removed (the Access Analyzer probe's `ListAnalyzers`, which `SRA-ACCESSANALYZER-01` still needs, so the IAM policy is unchanged). `util/generate_iam_policy.py` output and `1-sraverify-member-roles.yaml` are unchanged.
- The scanner stays read-only.
- `main.py` changes by one `info` log line per check (`check_done`), emitted through the `sraverify` logger. `run_checks` keeps `list(check.execute())` inside its guard; the synthetic row keeps its `Error running` prefix; no control flow changes.
- `core/scan_context.py` changes by exactly one four-line guard in `_set`. The session, regions, account lists, `Config`, client cache, lock, lifecycle, and `get_client` are unchanged; `get_client` in particular gains no exception handling, because its failure is a defect and not an AWS outcome.
- `2-sraverify-codebuild-deploy.yaml` changes only in where each invocation's stderr goes and in uploading those files. The fan-out, consolidation, and dashboard steps are unchanged.
- No client method gains or loses an AWS call on its success path. Five known first-page-only paginations stay as they are.
- `core/errors.py` gains one exception class. `util/generate_iam_policy.py` learns the two patterns the tree actually uses.
- No check's PASS path changes. This is a gate-tested hypothesis (Requirement 6.6), not an assertion.
- Every accessor's success-path caching is unchanged in what is fetched, when, under which namespace, and under which key. A scan with no failures issues the same calls it does today, minus the Access Analyzer probe. The cached *value* does change for every accessor whose client used to extract a list or scalar: it is now the named-key success dict.
- `securityincidentresponse` Region resolution, the `regions[0]` labels, `sra_firewallmanager_01`'s literal Region, and `sra_macie_07`'s set-join are untouched.
- Every client `except` handler in the tree is replaced, not adapted. After Phase 7, `services/*/client.py` contains no `try` statement.
- The contract tests land with each batch and are not optional.
- No library module writes to stdout, and this is tested from Phase 0 onward, before any client or base module is edited. Every diagnostic this design adds goes through `sraverify.core.logging.logger`, which binds to stderr. The CLI surface (`main()`, banner, progress, inventory listings) is outside the contract and unchanged.
