---
inclusion: always
---

You are an expert at creating AWS Security Reference Architecture (SRA) Verify security checks. This file is authoritative for **check-authoring detail**: the check module shape, `CheckMeta`, the finding helpers, caching, error handling, FAIL-vs-ERROR, region labelling, and account lists.

`structure.md` owns repo layout, the architecture diagram, the naming tables, the step order for adding a check, and the canonical service-base-class and client code shapes. This file references those rather than restating them.

Per-scan state lives on a `ScanContext`. Identity and description live in a frozen `CheckMeta` in the check class's own body. Registration is automatic.

## Critical Steps Before Coding

1. **Research AWS API documentation first** — use `aws___search_documentation` and `aws___read_documentation`.
2. **Verify API method names and parameters** — don't assume, always check docs.
3. **Understand the response structure** — confirm which fields exist and when AWS omits them.
4. **Look for an existing base class accessor** — reuse before adding a new one (e.g. `get_detector_id(region)`, `get_subscribers(region)`).

## The check module shape

`services/guardduty/checks/sra_guardduty_01.py` is the canonical example. It is the whole file:

```python
"""
Check if GuardDuty detector exists.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_01(GuardDutyCheck):
    """Check if GuardDuty detector exists."""

    meta = CheckMeta(
        check_id="SRA-GUARDDUTY-01",
        title="GuardDuty detector exists",
        description=(
            "This check verifies that an GuardDuty detector exists in the AWS Region. "
            "A detector is a resource that represents the GuardDuty service and should "
            "be present in all AWS member account and AWS Region so that GuardDuty can "
            "generate findings about unauthorized or unusual activity even in those "
            "Regions that you may not be using actively."
        ),
        check_logic=(
            "Get detector_id in each Region. Check fails if there is no detector_id"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="GuardDuty",
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(
            text="Enable GuardDuty in every enabled Region.",
            cli="aws guardduty create-detector --enable --region <region>",
            console="GuardDuty console, Get started, Enable GuardDuty. Repeat per Region.",
        ),
        sra_sections=("Security Tooling account", "Amazon GuardDuty"),
        additional_urls=(
            "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Region.
        """
        for region in self.regions:
            detector_id = self.get_detector_id(region)

            if not detector_id:
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value="No GuardDuty detector in this Region",
                    remediation=f"Enable GuardDuty in {region}",
                )
            else:
                yield self.passed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value=f"Detector {detector_id} present",
                )
```

Note what is **not** there: no `__init__`, not even a metadata-only one. `SecurityCheck.__init__` accepts nothing beyond `self`, so a leftover `super().__init__(account_type=...)` raises `TypeError` naming the argument. There is no `CHECKS` dict edit and no `main.py` edit.

## `CheckMeta`

`meta` is a class-level `CheckMeta` — frozen, slotted, hashable, holding only literal strings, tuples, and enum members. Nothing derived from an AWS response and nothing derived from the invocation.

It is constructed while the class body executes, so `CheckMeta.__post_init__` runs *before* the class object exists. **A defective declaration is an import failure**, raised as `MetadataError` from `core/errors.py`. That means `--list-checks` is a credential-free validation pass over the whole catalog.

### Fields

| Field             | Type              | Notes                                             |
| ----------------- | ----------------- | ------------------------------------------------- |
| `check_id`        | `str`             | Must fullmatch `SRA-[A-Z0-9]+-\d{2}` (ASCII)      |
| `title`           | `str`             | Max 120                                           |
| `description`     | `str`             | Max 1200                                          |
| `check_logic`     | `str`             | Max 400                                           |
| `severity`        | `Severity`        | Enum member, not a string                         |
| `account_type`    | `AccountType`     | Enum member, not a string                         |
| `service`         | `str`             | AWS display name, max 60                          |
| `resource_type`   | `str`             | Must fullmatch `AWS::[A-Za-z0-9]+::[A-Za-z0-9]+`  |
| `remediation`     | `Remediation`     | `text` required and non-blank                     |
| `sra_sections`    | `tuple[str, ...]` | Default `()`, max 20 elements, each max 200 chars |
| `additional_urls` | `tuple[str, ...]` | Default `()`, max 20 elements, each max 500 chars |

`Remediation(text=..., cli="", console="")`. `text` is capped at 1000; `cli` and `console` at 2000 each.

`severity` and `account_type` are `StrEnum` members from `core/enums.py`, so an illegal value is a static type error and no string-to-enum conversion step exists anywhere.

### Validation rules

`__post_init__` applies rules in ascending criterion order and **stops at the first failure**, so a declaration breaking two rules always reports the same one. In order: `check_id` format, `resource_type` format, required text fields non-empty, whitespace normalization, the title first-token rule, length caps, `remediation.text` non-empty, `additional_urls` element rules, `sra_sections` element rules, then sequence element counts.

Two rules deserve their own attention.

**Title states the control as a fact.** The first token of `title`, lowercased with trailing punctuation stripped, must not be `ensure`, `ensures`, `check`, or `checks`. The comparison is token-level, not prefix-level, so `"Checkpoint ..."` and `"Ensured ..."` pass while `"Ensure:"` and `"Checks,"` are caught. The reason is that one title has to read correctly on a PASS row and on a FAIL row: "GuardDuty detector exists" works both ways; "Ensure GuardDuty detector exists" reads as an instruction on a row reporting success.

**Whitespace is normalized, and it is enforced.** `title`, `description`, `check_logic`, `service`, and `remediation.text` must each equal `" ".join(value.split())`. `remediation.cli` and `remediation.console` are exempt — a command example needs its line breaks, and neither field reaches the CSV. This rule is what makes the old advice about backslash continuations obsolete: a continuation leaking a run of indentation into a `Description` cell is now an import failure rather than a style note. Use parenthesized implicit string concatenation.

## Registration is automatic

**A check module's presence on disk is the whole of its registration.** There is no `CHECKS` dict, no `ALL_CHECKS` in `main.py`, no decorator, and no list to keep in sync. The failure mode where a check is written, looks correct, and silently never runs cannot occur.

The chain:

- `services/<svc>/__init__.py` is one call: `import_check_modules(f"{__name__}.checks")`.
- `services/__init__.py` is one call: `import_service_packages(__name__)`.
- `import sraverify.services` therefore registers all 158 checks. `main.py` carries that import with a `# noqa: F401` — it looks removable and is not; drop it and every scan selects nothing.
- Importing a check module executes its class body, which fires `SecurityCheck.__init_subclass__`, which cross-checks identity and calls `register()`.

Only modules whose file name starts with `sra_` are discovered (`CHECK_MODULE_PREFIX` in `core/discovery.py`). Subpackages are skipped. Re-importing is a no-op via `sys.modules`, and `register()` is idempotent for the same class object; a *different* class claiming a live ID raises `DuplicateCheckIdError`.

The registry is read through `all_checks()` only, which returns a `MappingProxyType` over a sorted copy. Nothing on the discovery or registration path issues an AWS call or opens a file.

## Identity is cross-checked four ways

**The module file stem is the authority.** `__init_subclass__` derives the expected check ID from it and compares three other expressions of identity against that. Every rule below raises `CheckIdentityError`:

1. **Stem format** — must fullmatch `sra_([a-z][a-z0-9]*)_(0[1-9]|[1-9][0-9])`. Deliberately tighter than `sra_([a-z0-9]+)_(\d{2})`, which would admit `sra_12_01` and `sra_guardduty_00`. The `01`–`99` range caps one service at 99 checks; the largest today is GuardDuty at 25.
2. **`meta` is declared in the class's own body** — read via `vars(cls)`, never `getattr`. Inheritance would let a class register under an ID it does not own. A check that forgot `meta` raises rather than silently inheriting one.
3. **`meta.check_id` matches the derived ID** — still load-bearing with inline metadata, because nothing else catches `check_id="SRA-GUARDDUTY-02"` inside `sra_guardduty_01.py`.
4. **Class name matches** — `expected_id.replace("-", "_")`. Applies to *every* `SecurityCheck` subclass created inside a `sra_*` module, so a second or intermediate subclass declared there fails rather than registering.
5. **Correct service package** — `cls.__module__` must be `...services.<svc>.checks.sra_<svc>_NN` with `<svc>` matching the file stem's service segment. This is the one rule catching a *filing* mistake: `services/guardduty/checks/sra_shield_01.py` is self-consistent under rules 1–4, yet would inherit `GuardDutyCheck`, use GuardDuty's namespace and client, and report `Service=Shield` on every row.
6. **No check inherits another check** — two classes would answer to one metadata lineage and a `Finding` would no longer be attributable to exactly one check ID.
7. **No class attribute shadows a metadata property** — `check_id`, `service`, `severity`, `account_type`. These are read-only properties delegating to `meta`; a class attribute of the same name shadows the property and silently wins. Checked on `cls` and every intermediate base below `SecurityCheck`.

`register()` is the **last** step, so any failure leaves the registry byte-identical and a failed import contributes no partial catalog entry.

Two conditions leave a subclass unregistered **silently**, with no error:

- The class's module has no record in `sys.modules` or no `__file__` — a class built by `exec`, `type()`, a REPL, or a doctest. Silent because raising would make `SecurityCheck` unusable in a test that declares a throwaway subclass in memory.
- The stem does not start with `sra_`. Silent because service base classes (`GuardDutyCheck`, `ShieldCheck`) live in `base.py`, declare no metadata, and must stay out of the catalog. Note the discriminator is the **file name**, never the presence of `meta` — keying on `meta` would conflate "this class is not a check" with "this check's author forgot the metadata", and those two must not share a code path.

"Ineligible" and "invalid" are different facts.

## `execute()` yields Findings

```python
def execute(self) -> Iterable[Finding]:
    for region in self.regions:
        yield self.passed(...)
```

`execute` is the only abstract method and the only source of findings. `SecurityCheck` is an `ABC`, so a missing or misspelled `execute` fails at *instantiation*, not only when that check happens to run.

`Iterable[Finding]` accepts a generator or a plain `return [...]`. Generators are the convention, because then no accumulator variable exists in the check body at all. A bare `return` is the early-exit idiom for a guard clause. A check that yields nothing is legal and produces zero rows.

**`findings`, `create_finding`, and `get_findings` are gone.** They are in `_REMOVED_ATTRS`, and both reading and *assigning* them raises `AttributeError`. Assignment has to fail too: a migrated check that re-creates `self.findings = []` and appends to it would append rows to a list nobody reads and report zero findings while exiting 0 — the exact defect that made `get_findings()` return `[]` for 79 of 158 checks. A read-only guard would not catch it.

## The three finding helpers

Three status-specific public helpers over one private `_finding` builder. **Every parameter of all three is keyword-only.**

```python
def passed(self, *, region: str, resource_id: Optional[str],
           actual_value: str, checked_value: Optional[str] = None) -> Finding

def failed(self, *, region: str, resource_id: Optional[str],
           actual_value: str, remediation: Optional[str] = None,
           checked_value: Optional[str] = None) -> Finding

def error(self, *, region: str, resource_id: Optional[str],
          actual_value: str, remediation: str,
          checked_value: Optional[str] = None) -> Finding
```

Keyword-only is the point, not a style preference. With positional arguments allowed, `yield self.failed(region, "No detector in this Region", "Enable GuardDuty")` would be well-formed: the sentence lands in `resource_id`, the advice lands in `actual_value`, and `Remediation` silently takes the metadata default. Every value is a legal non-empty string in a legal field, so nothing downstream can catch it, and the row is plausible enough to render in a dashboard. Keyword-only turns that whole class of wrong-cell defect into a `TypeError` at the call site.

`resource_id` is **required** in all three even though it accepts `None`. Optional-with-a-default would let it be forgotten; required-but-nullable forces the author to decide whether this row identifies a resource and to say so.

The signatures encode the remediation rules, and the asymmetry is deliberate:

- **`passed()` has no `remediation` parameter at all**, not even one defaulting to `""`. Passing one is a `TypeError`. A PASS has nothing to remediate, so the empty cell is structural rather than conventional. The 178 semantically empty remediation arguments in the pre-change catalog — `"No remediation needed"` ×114, `""` ×45, `"No action needed"` ×19 — are unrepresentable, and three spellings of "nothing to do" collapse into one canonical empty cell.
- **`failed()` falls back to `meta.remediation.text`** when `remediation` is omitted *and* when it is supplied blank, so no FAIL row can carry an empty `Remediation` cell. Pass an override only for genuinely dynamic text, such as `remediation=f"Enable GuardDuty in {region}"`.
- **`error()` requires a non-blank `remediation`** and raises `ValueError` naming the check ID otherwise. There is no metadata default here on principle: for a FAIL, `meta.remediation.text` is by construction the right advice, because it is the remediation for this control. An ERROR row reports that the control could **not be evaluated**, so its remediation concerns fixing the **scan environment** — grant a permission, pass `--audit-account` — not fixing the control. Emitting "Enable GuardDuty in every enabled Region" against an `AccessDeniedException` would be confidently wrong, which is worse than raising. Emptiness is the whole of the validation; no wording is judged.

`checked_value` defaults to `f"{service} Configuration"` in all three.

Everything else on the row comes from `meta`. `account_id` and `account_name` are copied **by value** out of the context's account-info dict, and `title` is composed as `f"{check_id} {title}"` in exactly one place — which is what makes `Finding`'s title-prefix rule enforceable. Never pass account identity. The returned `Finding` holds no reference to the check and none to the `ScanContext`, which is what lets the orchestrator `del ctx` while the findings outlive the scan.

All three raise `RuntimeError` if `initialize(ctx)` has not run, before any partial row is built.

## Region labelling

Non-regional rows use `GLOBAL_REGION` from `core/finding.py`, whose value is `"global"`. Checks in the tree spell it as the literal `region="global"`.

**A non-regional condition gets ONE row, not one per region.** A missing `--audit-account` is not a regional fact, and fanning it across a 17-region scan produces 17 identical rows that say nothing about any region.

**Put the missing-input guard before the region loop.** Besides the row count, it avoids AWS calls whose result cannot change the outcome. `sra_auditmanager_02` is the reference:

```python
def execute(self) -> Iterable[Finding]:
    if not self.audit_accounts:
        yield self.error(
            region="global",
            resource_id=None,
            actual_value="Audit account ID not provided",
            remediation="Re-run the check with the --audit-account parameter so the delegated administrator can be compared against the audit account"
        )
        return

    for region in self.regions:
        admin_response = self.get_organization_admin_account(region)
        ...
```

Measured: that guard issues zero `GetOrganizationAdminAccount` calls with no flag, versus two with it.

The contrast case is legitimate. `sra_inspector_06` keeps its missing-input guard *inside* the region loop because its row reports a genuinely per-region fact — it interpolates the region-specific delegated admin into `actual_value`:

```python
actual_value=f"Delegated admin account is {delegated_admin_id}, but no audit account was specified for comparison",
```

That row could not be written outside the loop. The rule is about what the row *says*, not about loop position for its own sake.

## Account lists

Always `self.audit_accounts` and `self.log_archive_accounts`. Both are read-only properties delegating to `ScanContext`, and both return `[]` when the flag was not supplied.

**Never** any of these:

- `self._audit_accounts` / `self._log_archive_accounts` — those names live on `ScanContext`, never on a check.
- `hasattr(self, '_audit_accounts')` or `getattr(self, '_audit_accounts', [])`.
- An `initialize` override that reads `**kwargs`.

This is a fixed defect, not a hypothetical. 22 modules did exactly this and silently ignored both CLI flags. `SecurityCheck.__getattr__` raises `AttributeError` for those names, so `hasattr` is cleanly `False` and the branch is dead code that never fires; `getattr(..., [])` always returns the default. In a live management-account scan that produced 9 of 49 rows as ERROR "account ID not provided" while both flags *were* supplied. All 22 are fixed and the catalog greps clean — the only remaining hits are under `.tmp/premigration/`.

**Both flags are documented as lists — prefer iterating.** Seven checks resolve their verdict from element `[0]` alone and silently drop additional comma-separated values: `securitylake_15` and `config_06` on `log_archive_accounts[0]`, and `securitylake_16`, `securitylake_17`, `securityhub_07`, `securityhub_08`, `guardduty_14` on `audit_accounts[0]`. Interpolating `audit_accounts[0]` into a *remediation string* while comparing against the whole list is fine — `config_08` and `macie_06` do that.

## Initialization and the context properties

`initialize(ctx: ScanContext)` is the single initialization path. It assigns `self._ctx`, then calls `self._setup_clients()`.

A fresh `ScanContext` is built per `run_checks()` call and `del`'d in a `finally` block so its boto3 clients become collectible. That is what gives the long-running MCP server per-scan isolation. Never stash per-scan state anywhere else.

Seven properties delegate to the context, all read-only — assigning to any of them raises `AttributeError`:

`session`, `regions`, `account_info`, `account_id`, `account_name`, `audit_accounts`, `log_archive_accounts`

Each routes through `_require_ctx`, so a read before `initialize(ctx)` raises `RuntimeError` naming the check ID and the property rather than surfacing `AttributeError: 'NoneType' object has no attribute ...`. **Caveat:** that clean error is not universal. For the 22 checks whose base-class accessor touches `self._ctx._has(...)` before anything else, the first thing to fail is the `None` dereference, so they raise `AttributeError` instead.

`self.regions` returns the explicit `--regions` list when one was supplied, and otherwise lazily resolves enabled regions via `ctx.get_enabled_regions()` (one `ec2:DescribeRegions` per scan, cached).

`self.get_management_accountId()` takes no argument. The legacy `session` parameter is still accepted but ignored, and passing it logs a debug line.

Four more read-only properties delegate to `meta`: `check_id`, `service`, `severity`, `account_type`. `severity` and `account_type` return enum members.

## Caching

Every service base class declares a `NAMESPACE` class constant and stores cached AWS responses on the per-scan context via `self._ctx._has/_get/_set`. `structure.md` carries the canonical accessor shape.

The rules that matter when authoring:

- `_has` / `_get` / `_set` are for **service base classes only**. A check class never touches them; it calls the typed accessor on its base class.
- Cache keys are `"<thing>:<discriminator>"`. No account-ID or session-region prefix — the context is already per-scan and per-account.
- **Never cache a failure.** If the AWS call errors, leave the slot empty so a retry re-issues the call.
- `get_client(region)` can return `None`, and a missing wrapper for that region is the only reason it does. Always handle it.

## Logging

Use the single shared logger. Never `print()` from check, base, or client code — stdout must stay clean for the MCP server.

```python
from sraverify.core.logging import logger
```

`logger.debug(f"ServiceName: <message>")` in base classes, `logger.warning` for a missing client, `logger.error` for an API failure.

## Error handling: three tiers

1. **Client** — catch `ClientError`, log, return `{"Error": {"Code", "Message"}}`. Clients never raise.
2. **Check** — inspect for the `"Error"` key and decide FAIL vs ERROR.
3. **Orchestrator** — anything escaping `execute()` is caught per check in `run_checks`, logged with `exc_info=True`, and converted into exactly one synthetic ERROR row by `_synthetic_error`. A broken check degrades one row, not the whole scan. The synthetic row carries `region=GLOBAL_REGION`, `resource_id=None`, the check's **real** `severity` from `meta` (the pre-change row carried `"UNKNOWN"`, which was never a legal `Severity`), and `actual_value` naming the exception type as well as its message. It falls back to `meta.remediation.text` — the one place that is allowed, because the orchestrator knows only that something broke, and a cell naming the control beats an empty one.

Note that a check raising midway contributes one synthetic ERROR row **and nothing else**: the rows it yielded before failing go with the discarded generator.

### FAIL vs ERROR

- A semantic AWS code meaning "the thing isn't configured" (e.g. `AWSOrganizationsNotInUseException`) is a **FAIL**.
- A permission or transport failure is an **ERROR**.
- **Missing required input is an ERROR, not a FAIL.** Six checks got this wrong and have been fixed. A missing `--audit-account` means the control could not be evaluated; reporting it as FAIL asserts a negative the scan never established.

```python
if "Error" in response:
    error_code = response["Error"].get("Code", "")
    error_message = response["Error"].get("Message", "Unknown error")
    if error_code == "AWSOrganizationsNotInUseException":
        yield self.failed(
            region="global",
            resource_id=self.account_id,
            actual_value="No organization exists",
        )
    else:
        yield self.error(
            region=region,
            resource_id=self.account_id,
            actual_value=f"Error: {error_message}",
            remediation="Grant the member role organizations:DescribeOrganization",
        )
    return
```

`WARN` was never a legal `Status`. `Status` has exactly `PASS`, `FAIL`, `ERROR`. The three former `status="WARN"` sites — two in `sra_config_07`, one in `sra_config_08` — are now `failed()`, per the product principle that a partially configured control is a failure.

## Data structure gotchas

- An empty dict `{}` is truthy. Use `"key" in config` for existence, not `if config.get("key")`.
- Prefer `config.get("field")` over `config.get("field", {})` so a missing field stays distinguishable from an empty one.
- AWS responses omit fields entirely when a feature is disabled. Do not assume a key is present.
- Do not build an `ActualValue` by joining a `set` — the cell's ordering varies across runs and the CSV stops being diffable.

## Findings and CSV

The three helpers are the only way to build a `Finding`. `Finding` is frozen and validates on construction: it coerces the three enum fields, rejects a non-`str` in any of the twelve string fields, and requires `title` to begin with `check_id` and one space.

The 16-column CSV contract is declared once, as `Finding.FIELDS`, and rendered by `Finding.to_row()`. The dashboards parse that order. `structure.md` carries the column list.

## Security-first approach

- Fail on misconfigurations even when the feature is nominally "enabled" (e.g. a WAF rule set to Count rather than Block).
- Remediation must name the concrete step or console/CLI action, not "configure the service correctly."
- Checks are **read-only**: `Describe*` / `Get*` / `List*` only. Never mutate.

## Efficiency rules

- Minimize API calls — reuse data already fetched by an existing base class accessor.
- Filter resources early to cut downstream work and API calls.
- Leverage batch operations when available.
- Put guards that cannot be changed by an AWS call ahead of the calls.

## Known defects in the tree — do not copy, do not blind-fix

Each of these is real and deliberately still here. The "why" matters, so nobody 'fixes' one without understanding what moves.

- **`sra_firewallmanager_01` hardcodes `region = "us-east-1"` and has no region loop at all.** Firewall Manager's admin API is genuinely single-region, but the literal means `--regions` has no effect on the row's `Region` cell.
- **`sra_securityincidentresponse_01` labels its four real rows with `self.regions[0]`** (falling back to `us-east-1`), so the same org-wide fact gets a different `Region` depending on `--regions` ordering — an **unstable row key**. Only its missing-input row is `global`. Deferred because relabelling moves the `Region` cell on genuine verdicts, which changes rows a consumer may already be diffing.
- **`sra_securitylake_16` and `sra_securitylake_17` emit FAIL on an `AccessDeniedException`.** The cause is one level down: `SecurityLakeClient.list_subscribers` returns a bare `[]` on `ClientError` instead of the `{"Error": ...}` sentinel the client convention requires, so the check cannot tell "no subscribers" from "could not look". An undetermined state reported as a definite negative.
- **`sra_macie_07` builds its `ActualValue` by joining a `set`** (`missing_accounts` is a set difference), so the cell's ordering is non-deterministic across runs and undiffable.
- **`services/securityincidentresponse/base.py` declares no `NAMESPACE`**, and its `list_memberships()`, `get_delegated_administrators()`, and `get_organization_accounts()` all pin `self.regions[0]` while the sibling `discover_sir_region()` resolves the region correctly. That produces a false ERROR whenever the SIR region is not first in `--regions` — it masked 13 genuine PASS rows in a live account.
- **`sra_securityincidentresponse_04` reports "no active Security Incident Response memberships found" as ERROR** where the project rule makes it a FAIL: AWS answered, and the answer is that the control is absent.
- **`IAMCheck._validate_metadata` is dead and unusable.** It validates `check_name`, `description`, and `check_logic` as instance attributes; `check_name` no longer exists on a check at all, and the other two live on `meta`. Nothing calls it.
- **`SRA-CONFIG-08`'s ex-WARN branch is reachable but has never been observed.** It fires when the audit account is the Config delegated administrator for exactly one of `config.amazonaws.com` and `config-multiaccountsetup.amazonaws.com`. Exercising it needs an org configured that way.

Follow these patterns to create consistent, efficient, and maintainable security checks.
