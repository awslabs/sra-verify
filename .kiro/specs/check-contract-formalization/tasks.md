# Implementation Plan: Check Contract Formalization

## Overview

Four phases, in the order the design's Migration Order section establishes: scaffolding, base-class rewrite and orchestration, migration of all 158 check bodies, then verification and cleanup. Implementation language is Python 3.11, as the design specifies throughout.

Paths in this plan use the repository's tripled directory name. The pip project root is `sra-verify/sraverify/` and the package itself is `sra-verify/sraverify/sraverify/`, so `core/enums.py` means `sra-verify/sraverify/sraverify/core/enums.py`.

### The change is atomic — plan around it, not against it

`services/__init__.py` imports every service package, and therefore all 158 check modules, on every invocation. `__init_subclass__` requires a `meta` on every class declared in an `sra_*.py` module. A tree with even one unmigrated check does not import.

The consequence, which shapes every task below: **from the first edit in Phase 2 until Phase 3 completes, the scanner does not run.** No task in Phase 2 or Phase 3 can be verified by running a scan, and the design states plainly that Phase 2 has no runnable gate. The only verification available in that window is the subset of unit tests that import `sraverify.core.*` and nothing under `sraverify.services`. Phase 1 is the one exception: nothing in it is reachable from a scan, so it genuinely lands on its own.

Two consequences of that window are ordering requirements with their own tasks, because there is no second chance at either: the baseline CSV capture (task 7) must complete before the first Phase 2 edit, and the catalog survey (task 13) must complete before the first check body is edited.

### Test scope resolved

Design non-goal 4 defers the test harness, while the Phase 1 table gates its steps on unit tests and on correctness properties 6–9 and 19, and the Testing Strategy names specific modules. The resolution used here: **the deferred items are CI, a pytest configuration file, and a general harness. The specific test modules that gate Phase 1 are in scope**, because `pytest` and `hypothesis` are already declared in `extras_require` and `tests/property/test_service_migration_property.py` already establishes the location and the naming style (one module per property). This plan therefore includes tasks for those modules and includes no task for CI, pytest configuration, or a broader harness.

---

## Tasks

### Phase 1 — Scaffolding (no check edits, lands independently)

- [x] 1. Legal value sets and typed errors
  - [x] 1.1 Create `core/enums.py`
    - `Status`, `Severity`, `AccountType` as `enum.StrEnum` with the values the design fixes: `PASS`/`FAIL`/`ERROR`, `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`, `application`/`audit`/`log-archive`/`management`
    - `AccountType`'s values are exactly the `--account-type` choices, so nothing downstream carries a second list of account-type strings
    - _Requirements: 1.3, 2.3, 9.10_

  - [x] 1.2 Create `core/errors.py`
    - `SRAVerifyError` and the five subclasses: `MetadataError`, `CheckIdentityError`, `DuplicateCheckIdError`, `UnknownCheckError` (carrying `check_id` and `suggestions`), `NoChecksSelectedError`
    - One module so `main.py`'s `except` clauses import from a single place
    - _Requirements: 3.1, 4.4, 4.7, 9.4, 9.5_

  - [x] 1.3 Write `tests/unit/core/test_enums.py`
    - Membership, `.value` round-trip, and the `member == "audit"` string comparison that `_select` relies on
    - _Requirements: 1.3, 9.10_

- [x] 2. Finding model and the CSV column contract
  - [x] 2.1 Create `core/finding.py`
    - `Finding` as `@dataclass(frozen=True, slots=True)` with all sixteen fields required and no defaults; `resource_id` the one nullable field
    - `__post_init__`: coerce the three enum fields through `object.__setattr__`, reject a non-`str` in any other field, reject a `title` that does not begin with `check_id` plus one space
    - `FIELDS` as a `ClassVar` tuple in dashboard column order, `to_row()` rendering enums with explicit `.value` and a null `resource_id` as `""`, applying no quoting, escaping, or truncation
    - `GLOBAL_REGION = "global"`
    - _Requirements: 1.1, 1.2, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 1.10, 1.11, 1.12, 1.13, 1.14, 1.15, 1.16, 13.4_

  - [x] 2.2 Write `tests/unit/core/test_finding.py`
    - `to_row` key set and order, null `resource_id` rendering as `""`, frozen-ness, enum coercion accepting a member and its value while refusing anything else
    - _Requirements: 1.5, 1.6, 1.9, 1.12, 1.13_

  - [x] 2.3 Write `tests/property/test_finding_row_contract_property.py`
    - **Property 6: `to_row` yields exactly `FIELDS` in order**
    - **Validates: Requirements 1.4, 1.5, 13.4**

  - [x] 2.4 Write `tests/property/test_finding_value_types_property.py`
    - **Property 7: every row value is a string**
    - **Validates: Requirements 1.6, 1.16**

  - [x] 2.5 Write `tests/property/test_finding_enum_legality_property.py`
    - **Property 8: no out-of-enum status or severity** — `hypothesis` generates non-member strings
    - **Validates: Requirements 1.8, 1.14**

  - [x] 2.6 Write `tests/property/test_finding_immutability_property.py`
    - **Property 9: findings are immutable** — generated assignment against any of the sixteen fields raises `FrozenInstanceError`
    - **Validates: Requirements 1.9, 1.11**

- [x] 3. Check metadata and its validation rules
  - [x] 3.1 Create `core/metadata.py`
    - `Remediation` as a frozen slotted dataclass of three strings with `cli` and `console` defaulting to `""`, and deliberately no `__post_init__` — all rules live on `CheckMeta` so the reported failure follows ascending criterion order
    - `CheckMeta` frozen and slotted, `severity: Severity` and `account_type: AccountType` as members rather than strings, `sra_sections` and `additional_urls` as `tuple[str, ...]` defaulting to `()`
    - `CHECK_ID_RE` and `RESOURCE_TYPE_RE` compiled with `re.ASCII` and applied with `fullmatch`; the length and count constants
    - `__post_init__` applying the thirteen value rules in ascending criterion order, stopping at the first failure, raising `MetadataError` naming the field, the offending value, the check ID, and the defining module file. Rule 4 normalization exempts `remediation.cli` and `remediation.console`
    - Standard library only
    - _Requirements: 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.10, 3.11, 3.12, 3.13_

  - [x] 3.2 Write `tests/unit/core/test_metadata.py`
    - One test per validation rule with a minimal fixture violating only that rule. The whitespace rule uses the actual pre-fix `sra_guardduty_01` description as its fixture, so the test is anchored to the real defect rule 4 is the sole defense against
    - No loader tests — there is no loader
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.13_

  - [x] 3.3 Write `tests/property/test_metadata_validation_property.py`
    - **Property 19: metadata validation totality** — no `CheckMeta` escapes when any rule is violated, and a declaration violating two rules always reports the lower-numbered one. Include the malformed `check_id` plus blank `remediation.text` pair, which is the assertion that catches a regression of the decision to keep all validation on `CheckMeta`
    - **Validates: Requirements 3.10, 3.11, 3.12**

- [x] 4. Registry and discovery
  - [x] 4.1 Create `core/registry.py`
    - `_REGISTRY`, `register()` idempotent for the same class object and raising `DuplicateCheckIdError` for a conflicting one, `all_checks()` returning a `MappingProxyType` over a copy sorted by check ID
    - Import `SecurityCheck` under `TYPE_CHECKING` only, so the runtime edge runs one way
    - No decorators
    - _Requirements: 4.7, 4.8, 4.9, 4.11_

  - [x] 4.2 Create `core/discovery.py`
    - `import_check_modules(package_name)` importing every non-package `sra_*` module in sorted order and returning the imported names; `import_service_packages(package_name)` importing every subpackage in sorted order
    - `pkgutil.iter_modules` plus `importlib.import_module`, resolving by name so no `core` module statically imports a service package; import failures propagate unchanged
    - _Requirements: 5.1, 5.2, 5.3, 5.6, 5.7, 5.8, 5.9_

  - [x] 4.3 Write `tests/unit/core/test_registry.py`
    - **Property 3: duplicate check ID raises** — a second distinct class under an existing ID raises rather than overwriting, and re-registering the same class object is harmless
    - `MappingProxyType` rejects mutation; ordering is sorted
    - Fold the Phase 1 discovery gate assertions in here rather than adding a module beyond the named set: sorted import order and an empty list when no module matches, over a `tmp_path` package
    - _Requirements: 4.7, 4.8, 4.9, 5.1, 5.3_

- [x] 5. Python version floor
  - [x] 5.1 Set `python_requires=">=3.11"` in `sra-verify/sraverify/setup.py`
    - Exactly `>=3.11`. Leave `install_requires` at `boto3` and `colorama`, and leave the version and boto3 pin disagreements alone
    - _Requirements: 12.1, 13.3_

  - [x] 5.2 Confirm a real non-editable `pip install` of the package imports the new `core` modules cleanly
    - `pip install ./sra-verify/sraverify` into a throwaway environment, then `python -c "import sraverify.core.finding, sraverify.core.metadata, sraverify.core.registry, sraverify.core.discovery"`
    - Runs before any Phase 2 edit, while the tree still imports
    - _Requirements: 12.1_

- [x] 6. Checkpoint - Phase 1 gate
  - Run `pytest sra-verify/sraverify/sraverify/tests/` — the 51 existing tests plus everything added above. Ensure all tests pass, ask the user if questions arise.

---

### Phase 2 — Base-class rewrite and orchestration

**Task 7 must complete before any other task in this phase.** From task 8.1 onward the tree does not import and no scan runs until Phase 3 completes. There is no runnable gate at the end of this phase; the gate that would apply here has moved to Phase 4.

- [x] 7. Capture the pre-change baseline CSV — before the first Phase 2 edit
  - [x] 7.1 Write the pinned invocation as a runner script under `.tmp/acceptance/`
    - Pin every argument that can move the row key set: the target account and the assumed role or profile, an **explicit** `--regions` value (never omitted — an omitted value resolves lazily through `ec2:DescribeRegions`, and a region enabled or disabled between the two runs silently shifts the key set), the same `--account-type`, and the same `--audit-account` and `--log-archive-account`
    - The same script produces the after-capture in task 18.1, so the two captures cannot drift in their arguments
    - Choose a target account with a meaningful spread of configured services: a bare account exercises the FAIL branches only, which thins the key set exactly where the key-set gate does its work
    - _Requirements: 11.8, 11.15_

  - [x] 7.2 Run the script against the pre-change tree and store the baseline CSV under `.tmp/acceptance/`
    - This is the only opportunity to produce a comparable "before" artifact from this account. Do not delete `.tmp/acceptance/` between phases — the baseline has to survive until task 18.3
    - _Requirements: 11.8_

- [x] 8. Rewrite the check base class
  - [x] 8.1 Rewrite `core/check.py` class shape and delete the removed members
    - `SecurityCheck(ABC)` with `meta: ClassVar[CheckMeta]`; `__init__` taking no argument beyond the instance and setting only `self._ctx = None` and `self._clients = {}`
    - `abstractmethod execute(self) -> Iterable[Finding]`
    - Read-only `check_id`, `service`, `severity`, `account_type` properties delegating to `meta`; a property with no setter is what makes the 90 post-constructor account-type assignments raise
    - `_require_ctx(accessor)` plus the seven context-delegating properties, raising `RuntimeError` naming the property and the check ID when read before `initialize(ctx)`
    - Keep `initialize(ctx)`, `_setup_clients()`, `get_client()` returning `None` only when no wrapper is registered for the region, and `get_management_accountId()`
    - Delete `create_finding`, `self.findings`, and `get_findings` outright — no adapter, no deprecation window — and add the `_REMOVED_ATTRS` denylist with the paired `__setattr__` and `__getattr__` so re-creating any of them raises with a message naming the replacement
    - _Requirements: 6.1, 6.3, 6.5, 6.6, 6.7, 6.8, 6.9, 6.10, 6.11_

  - [x] 8.2 Add `__init_subclass__` to `core/check.py`
    - `CHECK_MODULE_RE` as `sra_([a-z][a-z0-9]*)_(0[1-9]|[1-9][0-9])` with `re.ASCII`, applied with `fullmatch`; assert the derivation is reversible against the file stem
    - Return silently when the module is absent from `sys.modules` or carries no `__file__`, and when the stem does not begin with `sra_`; raise for everything else
    - Cross-check the four identities in order: file stem, metadata `check_id` read from `vars(cls)` rather than `getattr`, class name, and the containing service package taken from `cls.__module__`
    - Apply the shape rules — no check inherits another check, and no class attribute named `check_id`, `service`, `severity`, or `account_type` anywhere between `cls` and `SecurityCheck`
    - Register last, so a failure leaves the registry byte-identical to its prior state
    - No AWS call and no file read on this path
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.10, 4.12, 4.13, 4.14, 4.15, 4.16, 6.12_

  - [x] 8.3 Add the finding helpers to `core/check.py`
    - Private `_finding(status, ...)` composing `title` as `f"{meta.check_id} {meta.title}"`, defaulting `checked_value` to `f"{service} Configuration"`, and copying `account_id` and `account_name` by value from the context so no `Finding` holds a reference to the check or the context
    - `passed()` with no `remediation` parameter and always `""`; `failed()` falling back to `meta.remediation.text` when `remediation` is omitted or blank; `error()` requiring `remediation` and raising `ValueError` naming the check ID when it is blank
    - Every parameter keyword-only, with `region`, `resource_id`, and `actual_value` required in all three and `resource_id` accepting `None`. This is the guard against a positional swap across 158 migrated call sites, which produces a well-formed row with the wrong values in the wrong columns and cannot be caught downstream
    - Route all three through `_require_ctx` so an uninitialized check raises rather than surfacing an `AttributeError` on `None`
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8, 7.9, 7.10, 7.11, 7.12_

  - [x] 8.4 Write `tests/unit/core/test_check_registration.py`
    - Synthetic subclasses in a `tmp_path` package exercising each `CheckIdentityError` branch: malformed stem, ID disagreeing with the stem, class name disagreeing, wrong service package, missing `meta`, a check inheriting a check, a shadowing class attribute, plus the `base.py` skip and the no-`__file__` silent skip
    - This module imports only `sraverify.core.*`, so it is the one executable verification available during Phase 2 — run it with `pytest sra-verify/sraverify/sraverify/tests/unit/core/`
    - _Requirements: 4.2, 4.4, 4.5, 4.6, 4.13, 4.14, 4.16, 6.12_

  - [x] 8.5 Write `tests/property/test_helper_signature_property.py`
    - **Property 21: helpers reject positional and malformed calls**
    - **Validates: Requirements 7.1, 7.3, 7.11**

  - [x] 8.6 Write `tests/property/test_passed_no_remediation_property.py`
    - **Property 14: `passed()` carries no remediation**
    - **Validates: Requirements 7.2, 7.11**

  - [x] 8.7 Write `tests/property/test_no_accumulator_property.py`
    - **Property 12: yielded output is the only source of findings** — assert against a synthetic subclass now; task 17 re-asserts it over the real catalog
    - **Validates: Requirements 6.3, 6.11**

- [x] 9. Wire discovery into the service packages
  - [x] 9.1 Cut all 18 `services/<svc>/__init__.py` files to a discovery call
    - Four lines each: docstring, import `import_check_modules`, call it with `f"{__name__}.checks"`. `services/guardduty/__init__.py` goes from 58 lines to 4
    - This removes 158 check imports and 158 `CHECKS` dict entries; adding a check file is from here on the whole of registering it
    - _Requirements: 5.5, 11.7_

  - [x] 9.2 Turn `services/__init__.py` into the discovery aggregator
    - Replace the bare docstring with an `import_service_packages(__name__)` call
    - This is the edit that makes the tree all-or-nothing: every check module is imported on every run, so an unmigrated check fails the import
    - _Requirements: 5.2, 5.4, 5.9_

- [x] 10. Rewrite CSV output
  - [x] 10.1 Rewrite `utils/outputs.py`
    - `write_csv_output(findings: list[Finding], output_file: str)` deriving column names solely from `Finding.FIELDS` and rendering rows solely from `to_row()`
    - Pin the dialect: `encoding="utf-8"` with `errors="strict"`, `newline=""` on the open, `lineterminator="\r\n"`, `QUOTE_MINIMAL`, `doublequote=True`. The explicit encoding is the fix for the locale-dependent `UnicodeEncodeError` that loses a completed scan's report under `LANG=C`
    - Delete `REQUIRED_FIELDS`, the missing-field backfill loop, and the legacy `CheckType` migration; keep the always-create-the-file behavior; leave the findings list and every element unmodified
    - Let `OSError` propagate carrying the path and the reason, creating no directory and synthesizing no file name inside a directory path
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8, 8.9, 13.4_

  - [x] 10.2 Write `tests/property/test_csv_no_mutation_property.py`
    - **Property 10: `write_csv_output` does not mutate its input**
    - **Validates: Requirements 8.4**

  - [x] 10.3 Write `tests/property/test_csv_empty_header_property.py`
    - **Property 11: zero findings still write a header**
    - **Validates: Requirements 8.3**

  - [x] 10.4 Write `tests/property/test_csv_round_trip_property.py`
    - **Property 20: CSV round-trip fidelity** — draw cell values containing commas, double quotes, already-doubled double quotes, `\r`, `\n`, `\r\n`, leading and trailing spaces, and non-ASCII characters. Meaningful precisely because quoting lives in one layer; it also covers the encoding and line-terminator pins as a side effect
    - **Validates: Requirements 1.15, 8.7, 8.8**

- [x] 11. Orchestration and CLI
  - [x] 11.1 Replace registration and add `_select` in `main.py`
    - Delete the 18 service imports, the `**` splat, and `ALL_CHECKS` as a module global; add `import sraverify.services  # noqa: F401` with the comment recording that the import is a side effect and is not removable
    - `_select(account_type, service, check_id)` reading `cls.meta` only and instantiating nothing: `--check` narrows the intersection rather than replacing it, an unknown ID raises `UnknownCheckError` carrying up to three `difflib` suggestions at cutoff 0.6, and an empty result raises `NoChecksSelectedError` carrying all three filter values
    - Service matching is full-value ASCII-lower-cased with `strip()` on the supplied value only — `str.lower()`, not `casefold()`, and no prefix or substring match
    - Rewrite `get_available_checks` and `get_available_services` to read `cls.meta` while keeping their existing return shapes, and derive the banner check count from the selected mapping
    - _Requirements: 4.11, 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.8, 9.9, 9.11_

  - [x] 11.2 Correct the orchestration loop and add `_synthetic_error` in `main.py`
    - Move `initialize(ctx)` inside the per-check `try` so it joins construction and execution in one guarded block; catch `Exception`, never `BaseException`, so `KeyboardInterrupt` and `SystemExit` propagate instead of manufacturing one ERROR row per remaining check
    - `findings = list(check.execute())` inside the guarded block, with the explanatory comment: a live generator keeps the check, and therefore the `ScanContext` and every cached boto3 client, reachable past `finally: del ctx`. Without the comment a later reader will "optimize" it into a lazy `extend`
    - Advance the progress indicator outside the `except` so a broken check still advances it exactly once; nest a second guard so a failure while building the ERROR row logs and continues rather than ending the scan
    - Resolve `ctx.get_account_info()` once before the loop, tolerate its failure with empty strings, and return a concrete `list` so `finally: del ctx` runs before the caller sees anything
    - `_synthetic_error(check_class, exc, fallback_account)` building a real `Finding` with all sixteen fields, reading metadata from `check_class.meta` so a construction failure still produces an attributable row, and carrying the exception type as well as its message in `actual_value`
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.8, 10.9, 10.10, 10.11, 10.12_

  - [x] 11.3 Rework the CLI boundary in `main.py`
    - Feed argparse `[t.value for t in AccountType] + ["all"]` so the CLI holds no separate list of account-type strings
    - Resolve the output path before the scan, injecting the `_YYYYmmdd_HHMMSS` stamp only when `--output` was left at its default
    - Exit 2 on `UnknownCheckError` or `NoChecksSelectedError` with the filters and suggestions logged and no file created; exit 1 on an `OSError` from the writer with no scan summary printed; exit 0 once the report is written regardless of FAIL and ERROR counts, because a non-zero exit degrades the CodeBuild fan-out
    - _Requirements: 9.7, 9.10, 9.12, 9.13, 9.14_

  - [x] 11.4 Write `tests/unit/core/test_select.py`
    - The filter matrix plus both error paths, with the no-instantiation spy
    - Cannot be executed until Phase 3 completes: importing `main.py` imports `sraverify.services`. Write it now, run it at task 15.3
    - _Requirements: 9.2, 9.3, 9.4, 9.5, 9.6_

  - [x] 11.5 Write `tests/property/test_select_no_instantiation_property.py`
    - **Property 15: selection never instantiates a check** — patch `SecurityCheck.__init__` with a counter across `_select`, `get_available_checks`, and `get_available_services`
    - **Validates: Requirements 9.1, 9.8, 9.9, 9.11**

  - [x] 11.6 Write `tests/property/test_select_non_empty_property.py`
    - **Property 16: `_select` never returns an empty mapping**
    - **Validates: Requirements 9.2, 9.5, 9.6**

  - [x] 11.7 Write `tests/property/test_unknown_check_exit_property.py`
    - **Property 17: unknown check ID exits without output**
    - **Validates: Requirements 9.4, 9.7, 9.14**

  - [x] 11.8 Write `tests/property/test_context_isolation_property.py`
    - **Property 18: returned findings hold no `ScanContext`** — hold a `weakref` to the context and confirm it is dead after one `gc.collect()` once `run_checks` has returned
    - **Validates: Requirements 1.11, 10.7, 10.11**

- [x] 12. Checkpoint - Phase 2 has no runnable gate
  - Run only `pytest sra-verify/sraverify/sraverify/tests/unit/core/`. The full suite fails at collection from here until Phase 3 completes, because `tests/property/test_service_migration_property.py` imports the 17 service base modules and that triggers discovery over a tree with 158 unmigrated checks. No scan runs. Do not attempt one, and do not weaken task 9.2 to make one possible. Ask the user if questions arise.

---

### Phase 3 — Migrate all 158 check bodies

Every task in this phase is verified by review and by the Phase 3 import gate at task 15, not by running a scan. The tree begins to import again only when task 14 is complete in full.

- [x] 13. Survey the catalog before editing the first check body
  - [x] 13.1 Write a throwaway in-memory survey script under `.tmp/`
    - Walk the 158 existing check classes, read each `__init__`'s metadata assignments, and construct a `CheckMeta` **in memory** from them
    - Collect every validation failure rather than stopping at the first, so the whole list is reviewable at once
    - Writes no artifact and ships nothing. It exists to recover the single reviewable failure list that folding the metadata move into the body migration would otherwise scatter across 158 files
    - _Requirements: 3.4, 3.5, 11.9, 11.10_

  - [x] 13.2 Run the script and triage the failure list
    - Expect three known categories plus whatever else surfaces: the illegal `account_type="account"` in `services/config/base.py`, the `sra_guardduty_01` description whose backslash continuations render 14 consecutive spaces, and every `Ensure`/`Ensures`/`Check`/`Checks` title that must be restated as a fact
    - Decide the replacement title for each violation here, before any body is edited. Mid-migration is the wrong moment to be rewriting a title
    - _Requirements: 3.4, 3.5, 11.9_

  - [x] 13.3 Delete the survey script
    - It is scaffolding for the triage, not a deliverable
    - _Requirements: 11.1_

- [x] 14. Migrate the check bodies, service by service
  - Nine mechanical edits per check, applied identically in every service task below. Control flow, the region loop, and every FAIL-versus-ERROR judgment stay byte-for-byte identical, including the 34 checks that classify AWS error codes themselves and the split classification of `BadRequestException` between `sra_guardduty_14` and `sra_guardduty_15`/`16`/`20`–`25`:
    1. Metadata out of `__init__` into a `CheckMeta(...)` literal in the class body, de-mangling any backslash-continuation text into parenthesized implicit concatenation
    2. Delete the emptied `__init__`
    3. `create_finding(status="PASS"/"FAIL"/"ERROR", ...)` → `passed()` / `failed()` / `error()`
    4. Accumulator, whether `self.findings.append(...)` or a local list → `yield`
    5. `return self.findings` / `return findings` → delete, or a bare `return` where a guard clause needs an early exit
    6. `actual_value=None` → a real descriptive string with whitespace collapsed to single spaces
    7. Drop `remediation=""`, `"No remediation needed"`, and `"No action needed"` from PASS branches — `passed()` has no such parameter
    8. Return annotation → `Iterable[Finding]`, imports updated
    9. Delete the service base class's metadata-only `__init__`, once per service in `base.py`. Leave `NAMESPACE` and every cached accessor verbatim — that deletion is the only permitted edit to a `base.py`, and no `client.py` is touched at all
  - Also delete every post-`super().__init__()` `self.account_type = ...` assignment in the check files, 90 of them across the catalog. These now raise `AttributeError` against the read-only property, so they cannot be deferred to a later task
  - _Requirements: 2.1, 6.1, 6.3, 6.4, 6.13, 7.2, 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 13.6, 13.7_

  - [x] 14.1 Migrate guardduty (25 checks) as the reference implementation
    - First, and on its own, so every subsequent service has one finished service on disk to diff against. `sra_guardduty_01.py` is the design's worked example, including the de-mangled description
    - Delete `GuardDutyCheck.__init__` from `services/guardduty/base.py`
    - _Requirements: 2.1, 11.1, 11.2, 11.6, 13.6_

  - [x] 14.2 Migrate securitylake (17 checks)
    - _Requirements: 2.1, 11.1, 11.2, 11.6, 13.6_

  - [x] 14.3 Migrate shield (14 checks)
    - Shield keeps writing `Region=us-east-1` where the convention says `global`. That is preserved deliberately; changing it would move row keys
    - _Requirements: 2.1, 11.1, 11.2, 11.6, 13.6_

  - [x] 14.4 Migrate cloudtrail (13 checks)
    - _Requirements: 2.1, 11.1, 11.2, 11.6, 13.6_

  - [x] 14.5 Migrate inspector (11 checks)
    - _Requirements: 2.1, 11.1, 11.2, 11.6, 13.6_

  - [x] 14.6 Migrate securityhub (11 checks)
    - _Requirements: 2.1, 11.1, 11.2, 11.6, 13.6_

  - [x] 14.7 Migrate firewallmanager (10 checks)
    - _Requirements: 2.1, 11.1, 11.2, 11.6, 13.6_

  - [x] 14.8 Migrate macie (10 checks)
    - _Requirements: 2.1, 11.1, 11.2, 11.6, 13.6_

  - [x] 14.9 Migrate config (9 checks) — carries known extra work
    - `services/config/base.py` sets `account_type="account"`, which is not a legal value and is why these checks can never be selected by `--account-type` today. Deleting that metadata-only `__init__` removes it; each Config check then declares a legal `AccountType` member in its own `meta`. Their `AccountType` cell changes and they become selectable, both intended
    - Flag the Config 01–06 checks that loop regions while emitting `region="global"` rows as candidates for reclassification if a base-driven region loop is ever adopted. Flag only — no restructuring in this change, since restructuring would move row keys and break the acceptance gate
    - _Requirements: 2.1, 11.1, 11.2, 11.6, 11.10, 11.14, 13.6_

  - [x] 14.10 Migrate organizations (9 checks)
    - _Requirements: 2.1, 11.1, 11.2, 11.6, 13.6_

  - [x] 14.11 Migrate waf (9 checks)
    - _Requirements: 2.1, 11.1, 11.2, 11.6, 13.6_

  - [x] 14.12 Migrate securityincidentresponse (5 checks)
    - `services/securityincidentresponse/base.py` assigns into `self._clients` from three of its accessors. That keeps working — the `__setattr__` denylist covers three names and `_clients` is not one of them
    - _Requirements: 2.1, 11.1, 11.2, 11.6, 13.6_

  - [x] 14.13 Migrate accessanalyzer (4 checks) — carries known extra work
    - `sra_accessanalyzer_03.py`'s `hasattr(self, '_audit_accounts')` branch is dead code, because that attribute lives on `ScanContext` and never on the check. Replace it with `self.audit_accounts`
    - Its post-`super().__init__()` `self.account_type` assignment is removed by the standard edit list regardless
    - _Requirements: 2.1, 11.1, 11.2, 11.6, 11.11, 13.6_

  - [x] 14.14 Migrate s3 (4 checks)
    - _Requirements: 2.1, 11.1, 11.2, 11.6, 13.6_

  - [x] 14.15 Migrate account (3 checks)
    - _Requirements: 2.1, 11.1, 11.2, 11.6, 13.6_

  - [x] 14.16 Migrate auditmanager (2 checks)
    - _Requirements: 2.1, 11.1, 11.2, 11.6, 13.6_

  - [x] 14.17 Migrate ec2 (1 check)
    - _Requirements: 2.1, 11.1, 11.2, 11.6, 13.6_

  - [x] 14.18 Migrate iam (1 check)
    - _Requirements: 2.1, 11.1, 11.2, 11.6, 13.6_

- [x] 15. Catalog import gate — the first executable verification since task 8.1
  - [x] 15.1 Confirm the tree imports and the catalog is complete
    - `python -c "import sraverify.services"` succeeds with no credentials, then `sraverify --list-checks` reports 158 checks and `sraverify --list-services` reports 18 services
    - A `MetadataError`, `CheckIdentityError`, or `DuplicateCheckIdError` here names the offending check and module file; fix it in the owning task 14.x rather than working around it
    - _Requirements: 4.11, 5.4_

  - [x] 15.2 Repair `tests/property/test_service_migration_property.py`
    - Two of its assertions default-construct each service base class, e.g. `GuardDutyCheck()`. `SecurityCheck` is now an ABC with an abstract `execute()`, so those constructions raise `TypeError`. Construct through a minimal concrete subclass that implements `execute` and declares nothing else, keeping all three existing invariants intact
    - This consequence is not recorded in the design. The repair is confined to this test module; no service base class changes
    - _Requirements: 6.1, 6.2, 13.6_

  - [x] 15.3 Run the full test suite
    - `pytest sra-verify/sraverify/sraverify/tests/` — the repaired 51 plus everything added in Phases 1 and 2, including the modules written at 11.4 through 11.8 that could not run until now
    - _Requirements: 6.2, 9.2, 9.4_

- [x] 16. Checkpoint - Phase 3
  - Ensure all tests pass and the catalog imports cleanly. Ask the user if questions arise.

---

### Phase 4 — Verification and cleanup

- [x] 17. Catalog-wide property pass over the real 158 checks
  - Each of these is a read over the registry, needs no credentials, and quantifies over a fixed finite set, so it enumerates the catalog directly rather than sampling it
  - [x] 17.1 Write `tests/property/test_catalog_identity_property.py`
    - **Property 1: four-way check identity** — metadata `check_id`, registry key, class name with `_`→`-`, and module file stem all agree for every registered check
    - **Validates: Requirements 4.1, 4.3, 4.5, 4.6, 4.14, 13.5**

  - [x] 17.2 Write `tests/property/test_registry_bijection_property.py`
    - **Property 2: registry–filesystem bijection** — `len(all_checks()) == len(glob("services/*/checks/sra_*.py"))`, with every file contributing exactly one entry and every entry having exactly one file. This is the guarantee `pkgutil` discovery cannot give on its own, and the design pairs it with the decision to use discovery over explicit imports
    - **Validates: Requirements 5.1, 5.2, 5.4**

  - [x] 17.3 Write `tests/property/test_catalog_meta_property.py`
    - **Property 4: every registered check declares a validated `meta`** — `"meta" in vars(cls)`, deep immutability, `hash(cls.meta)` succeeds, metadata equal across two `run_checks` calls under different accounts and region lists, and no file opened to obtain metadata during import or during a scan
    - **Validates: Requirements 2.1, 2.4, 2.6, 2.7, 4.12, 4.16**

  - [x] 17.4 Write `tests/property/test_catalog_meta_shape_property.py`
    - **Property 5: metadata shape and enum legality** — `isinstance` against `Severity` and `AccountType`, which is what separates a member from a bare string that merely compares equal to one
    - **Validates: Requirements 2.2, 2.3, 3.11**

  - [x] 17.5 Write `tests/property/test_catalog_executable_property.py`
    - **Property 13: every registered check is executable** — every registered class defines `execute` and instantiates, so no abstract method remains unimplemented
    - **Validates: Requirements 6.1, 6.2**

- [x] 18. Acceptance gate — the catalog-wide keyed before/after CSV comparison
  - [x] 18.1 Produce the after-capture using the identical invocation from task 7.1
    - Same account, same role or profile, same explicit `--regions`, same `--account-type`, same `--audit-account` and `--log-archive-account`. Re-run the task 7.1 script unchanged; anything else measures the arguments rather than the change
    - _Requirements: 11.8_

  - [x] 18.2 Write the keyed comparison tool under `.tmp/acceptance/`
    - Key each row on (`AccountId`, `CheckId`, `Region`, `ResourceId`) and sort both captures by that key before comparing anything. **Never a positional diff** — the registry now sorts by check ID, so the first service group moves from GuardDuty to AccessAnalyzer and a positional diff reports a difference on very nearly every line while proving nothing
    - All four key columns lie outside the admitted-difference set, which is what makes a matched pair genuinely the same finding observed twice rather than a difference explained away by the rule under test
    - Compare rows sharing one key as an unordered group, since one key can legitimately carry several rows
    - Emit the key-set result and the cell result separately, so the two gates in 18.3 stay independent
    - _Requirements: 11.15, 11.16_

  - [x] 18.3 Run the gate: key-set equality first, then cells
    - **Key-set gate**: require exact set equality and equal per-key row counts, reporting added and removed keys. This gate is independent of the admitted cell differences — an unequal key set rejects outright and nothing the cell gate admits excuses it. This is the step that catches a check which silently stopped emitting rows, which is the single most likely regression from changing how half the catalog accumulates findings, and the one a cell diff is blindest to because there are no cells to compare
    - **Cell gate**: compare all sixteen cells of each matched row, admitting differences only in `ActualValue`, `Remediation` on PASS rows, whitespace-normalized `Description`, `Title` for retitled checks, and `AccountType` for the reclassified Config checks. Every other cell byte-identical. `Status` is not in the admitted set — a PASS becoming a FAIL, or either becoming an ERROR, is a rejection
    - No length cap applies to `ActualValue`: a check enumerating many non-compliant resource ARNs may legitimately produce a long cell, and truncating it would discard the finding's substance
    - _Requirements: 11.2, 11.4, 11.5, 11.9, 11.15, 11.16_

  - [x] 18.4 Re-run any check whose key carries `ERROR` in exactly one capture
    - `sraverify --check SRA-X-NN` against both trees, per disputed key, not a whole re-scan. Throttling produces exactly the signature of a broken check, and without this step a reviewer decides by intuition which differences to ignore, which is how a real regression gets waved through
    - If the difference persists, it is a regression and the migration is rejected
    - _Requirements: 11.17_

- [x] 19. Cleanup and inventory regeneration
  - [x] 19.1 Delete `sra-verify/sraverify/tests/checks/accessanalyzer/test_sra_iaa_1.py`
    - It imports `sraverify.checks.accessanalyzer.SRA_IAA_1`, a module path that no longer exists, so bare `pytest` from the pip project root fails during collection. The `SRA-IAA-1` short ID is stale; no such check exists. Confirm bare `pytest` collects from `sra-verify/sraverify/` afterwards
    - _Requirements: 11.13_

  - [x] 19.2 Regenerate `sra-verify/docs/checks.txt` from `sraverify --list-checks`
    - Not conditional on the gate at 18.3 passing: regeneration needs only a tree that imports, so a rejection is still followed by a regeneration against the catalog as it then stands rather than leaving a superseded listing in place. By the same constraint it cannot happen any earlier, since a tree with one unmigrated check does not import
    - Expect `Title` changes for retitled checks and `AccountType` changes for the Config checks; the file's structure is unchanged because `get_available_checks` keeps its return shape
    - _Requirements: 9.8, 11.12_

- [x] 20. Confirm the CLI exit codes
  - [x] 20.1 Confirm the exit-2 paths create no file
    - `--check SRA-TYPO-99` exits 2 with `difflib` suggestions logged and no file at the resolved output path; `--account-type audit --service CloudTrail` exits 2 as a real-but-empty filter combination. Both previously logged an error and wrote a header-only CSV with exit 0, which in the CodeBuild fan-out is indistinguishable from a clean scan
    - _Requirements: 9.4, 9.7_

  - [x] 20.2 Confirm exit 0 with findings and exit 1 on a write failure
    - A scan producing FAIL and ERROR rows exits 0, because a FAIL is the tool working and a non-zero status would degrade the `parallel` fan-out; an unwritable `--output` path exits 1 with the path and reason logged and no scan summary on stdout
    - _Requirements: 9.13, 9.14_

- [x] 21. Final checkpoint
  - Ensure all tests pass and the acceptance gate has admitted the migration. Ask the user if questions arise.

## Notes

- **No test sub-task is marked optional.** The standard convention marks tests with `*`, and it is set aside here for one reason: this change has no MVP path. Phase 1's table gates its steps on the unit tests and on properties 6–9 and 19; Phase 2 has no runnable gate at all; Phase 3 does not run until it completes. The test modules are the only executable verification in the change before Phase 4, so none of them is additive coverage that could be skipped for speed.
- **The atomicity constraint is repeated at each phase heading rather than stated once.** From task 8.1 until task 14.18 the tree does not import. If a task in that window appears to need a scan to verify it, the task is wrong, not the constraint.
- **`.tmp/acceptance/` must survive from task 7.2 to task 18.3.** The baseline CSV is unreproducible once Phase 2 begins.
- **Out of scope, and no task generates them**: any change to `core/scan_context.py`, which stays byte-identical; any change to a service `client.py`; per-operation AWS error classification; a base-driven region loop or `evaluate(region)` hook; typed per-service resource models; a `pyproject.toml` migration; a generated machine-readable catalog; CI setup. The IAM policy artifacts and `1-sraverify-member-roles.yaml` are unchanged because no new AWS API call is introduced.
- **Recorded follow-up, not a task in this plan**: the MCP server break lives in the separate `sra-verify-mcp` repository. The design records both the one-line boundary conversion it needs and the `python_requires >= 3.11` consequence for its declared 3.10 floor.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2", "5.1", "7.1"] },
    { "id": 1, "tasks": ["1.3", "2.1", "3.1", "4.1", "4.2", "7.2"] },
    { "id": 2, "tasks": ["2.2", "2.3", "2.4", "2.5", "2.6", "3.2", "3.3", "4.3", "5.2", "10.1"] },
    { "id": 3, "tasks": ["8.1", "10.2", "10.3", "10.4"] },
    { "id": 4, "tasks": ["8.2", "9.1", "9.2"] },
    { "id": 5, "tasks": ["8.3", "8.4", "8.7"] },
    { "id": 6, "tasks": ["8.5", "8.6", "11.1"] },
    { "id": 7, "tasks": ["11.2"] },
    { "id": 8, "tasks": ["11.3"] },
    { "id": 9, "tasks": ["11.4", "11.5", "11.6", "11.7", "11.8"] },
    { "id": 10, "tasks": ["13.1"] },
    { "id": 11, "tasks": ["13.2"] },
    { "id": 12, "tasks": ["14.1"] },
    { "id": 13, "tasks": ["14.2", "14.3", "14.4", "14.5", "14.6", "14.7", "14.8", "14.9", "14.10", "14.11", "14.12", "14.13", "14.14", "14.15", "14.16", "14.17", "14.18"] },
    { "id": 14, "tasks": ["13.3", "15.1", "15.2"] },
    { "id": 15, "tasks": ["15.3"] },
    { "id": 16, "tasks": ["17.1", "17.2", "17.3", "17.4", "17.5", "18.1", "18.2", "19.1", "19.2", "20.1", "20.2"] },
    { "id": 17, "tasks": ["18.3"] },
    { "id": 18, "tasks": ["18.4"] }
  ]
}
```
