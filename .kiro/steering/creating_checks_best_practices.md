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
- `import sraverify.services` therefore registers all 167 checks. `main.py` carries that import with a `# noqa: F401` — it looks removable and is not; drop it and every scan selects nothing.
- Importing a check module executes its class body, which fires `SecurityCheck.__init_subclass__`, which cross-checks identity and calls `register()`.

Only modules whose file name starts with `sra_` are discovered (`CHECK_MODULE_PREFIX` in `core/discovery.py`). Subpackages are skipped. Re-importing is a no-op via `sys.modules`, and `register()` is idempotent for the same class object; a *different* class claiming a live ID raises `DuplicateCheckIdError`.

The registry is read through `all_checks()` only, which returns a `MappingProxyType` over a sorted copy. Nothing on the discovery or registration path issues an AWS call or opens a file.

## Identity is cross-checked four ways

**The module file stem is the authority.** `__init_subclass__` derives the expected check ID from it and compares three other expressions of identity against that. Every rule below raises `CheckIdentityError`:

1. **Stem format** — must fullmatch `sra_([a-z][a-z0-9]*)_(0[1-9]|[1-9][0-9])`. Deliberately tighter than `sra_([a-z0-9]+)_(\d{2})`, which would admit `sra_12_01` and `sra_guardduty_00`. The `01`–`99` range caps one service at 99 checks; the largest today is GuardDuty at 26.
2. **`meta` is declared in the class's own body** — read via `vars(cls)`, never `getattr`. Inheritance would let a class register under an ID it does not own. A check that forgot `meta` raises rather than silently inheriting one.
3. **`meta.check_id` matches the derived ID** — still load-bearing with inline metadata, because nothing else catches `check_id="SRA-GUARDDUTY-02"` inside `sra_guardduty_01.py`.
4. **Class name matches** — `expected_id.replace("-", "_")`. Applies to *every* `SecurityCheck` subclass created inside a `sra_*` module, so a second or intermediate subclass declared there fails rather than registering.
5. **Correct service package** — `cls.__module__` must be `...services.<svc>.checks.sra_<svc>_NN` with `<svc>` matching the file stem's service segment. This is the one rule catching a *filing* mistake: `services/guardduty/checks/sra_shield_01.py` is self-consistent under rules 1–4, yet would inherit `GuardDutyCheck`, use GuardDuty's namespace and client, and report `Service=Shield` on every row.
6. **No check inherits another check** — two classes would answer to one metadata lineage and a `Finding` would no longer be attributable to exactly one check ID.
7. **No class attribute shadows a metadata property** — `check_id`, `service`, `severity`, `account_type`. These are read-only properties delegating to `meta`; a class attribute of the same name shadows the property and silently wins. Checked on `cls` and every intermediate base below `SecurityCheck`.
8. **A check may not declare `NOT_CONFIGURED_ERRORS`.** It is the one class attribute a *service base class* may declare that a check may not, and it is enforced here rather than left to convention. The table's whole purpose is that two checks reading the same error result from the same operation cannot classify it differently; a check declaring its own would re-create exactly the per-check classification the contract removes.

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

## The fan-out trap

**A guard placed above a per-resource loop collapses every row that loop would
have produced.** This was hit twice during the client-error-contract migration,
in Batches 3 and 4, and it is the one mistake in this file that a green test suite
will not catch — the rows simply are not there to be wrong about.

The shape of a fanning-out check:

```python
for region in self.regions:
    protections = self.list_protections(region)     # enumerate
    if "Error" in protections:
        yield self.error(...)                        # one row for the Region
        continue
    for protection in protections.get("Protections", []):
        web_acl = self.get_web_acl_for_resource(region, protection["ResourceArn"])
        if "Error" in web_acl:
            yield self.error(...)                    # one row for THIS resource
            continue                                 # <- not `return`
        ...
```

Two rules follow from it.

**Put the per-resource error branch inside the loop, and `continue`, not
`return`.** One undetermined resource costs one row; a `return` costs every
resource after it, and a `return` above the loop costs all of them. A check that
fanned out to 40 protected resources and now emits one ERROR row for the Region has
not become more concise — it has stopped reporting 40 resources.

**Where the batch is an implementation detail, keep the fan-out anyway.**
`SRA-SECURITYINCIDENTRESPONSE-04` batches accounts in hundreds because
`BatchGetMemberAccountDetails` caps at 100. When a batch call fails it yields one
ERROR row **per account in that batch**, not one for the batch: coverage is asserted
per account, and collapsing the batch would drop up to 100 accounts out of the
report.

The reverse case is also a trap, and it bites after this contract rather than
before it: **a post-loop global verdict that fires when every Region errored.**
Five Config checks ended with a "not found in any Region" FAIL that rested on
Regions which had never answered. Each now tracks an `undetermined` flag and
returns, because the per-Region ERROR rows already report the gap.

Contrast with the **missing-input** guard, which genuinely belongs above the loop:
see Region labelling above. The distinction is whether the guard's condition can be
changed by an AWS call. A missing `--audit-account` cannot, so nothing is lost by
deciding it first. An error result can, and is per-resource.

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
- **Never cache a failure, and return it unchanged.** If the client returns an error result, leave the slot empty *and* hand the error result back. Both halves matter: an accessor that swallowed it and returned `[]` would satisfy "did not cache a failure" while handing the check exactly the ambiguous value this contract removes.
- `_set` refuses an error result and logs a warning, as a backstop. Do not rely on it — the accessor is the control, and the contract tests hold it per accessor.
- `get_client(region)` can return `None`, and a missing wrapper for that region is the only reason it does. Return `no_client_result(service="<Display Name>", region=region)` — never `{}`, never `[]`. Its `Code` is `NoClient`, and it is never cached.
- The accepted cost: where two checks call the same failing accessor, the call is issued once per calling check rather than once per scan. That is the price of a retry being possible, and it is bounded. The alternative was replaying one failure for the rest of the scan.

## Logging, and the stdout contract

Use the single shared logger. **Never `print()` from check, base, or client code**,
and never add a stdout handler. `core/logging.py` strips the root logger's handlers
at import and installs a **stderr-only** handler, with `propagate = False`.

```python
from sraverify.core.logging import logger
```

`logger.debug(f"ServiceName: <message>")` in base classes, `logger.warning` for a
missing client, and **`logger.debug` — not `logger.error` — for a failed AWS
call.** (An earlier revision of this line said `error`, contradicting the "Never
raise the level" paragraph below it and the reasoning in `tech.md`. `debug` is
correct: this tier cannot know whether the failure is semantic.)

**The default level is `ERROR`, so a scan without `--debug` writes nothing to
stderr.** The package makes no `logger.info` calls, so relative to the old `INFO`
default this suppresses only `WARNING` — and every condition a warning describes
already reaches the report as a row. Write the call sites at their honest level
anyway; `--debug` is what makes them visible, and raising a level to be seen by
default breaks the `logger.error`-means-an-ERROR-row correspondence.

This is a contract, not a convention, and it is asserted:
`tests/property/test_stdout_contract_property.py` holds that nothing in the package
writes to stdout. Two consumers depend on it. The MCP server speaks JSON-RPC over
stdout, so one stray `print` corrupts the protocol. And a scan's diagnostics are
only separable from its report because the report goes to a file and the
diagnostics go to stderr — which is what lets you redirect one without losing the
other.

`AWSClient.aws_error` emits exactly one record per failure, in one line, at `debug`:

```
aws_call_failed operation=<Op> region=<Region> code=<Code> message=<JSON>
```

`message` is last and `json.dumps`-encoded, so an AWS message containing a newline
cannot break the one-line promise: one failed call is always one line. Do not add a
second log record for the same failure — "exactly one" is asserted per client method.

**Never raise the level.** `logger.error` means an ERROR row was produced. A failed AWS
call is not one on its own: `AccessDeniedException: Macie is not enabled` is a normal
observation that becomes a FAIL, and this tier cannot tell it from a broken scan —
only `is_not_configured`, one tier up, can. Logging it at `error` is classifying before
the information exists, and it made an audit-account scan print five ERROR lines and
then report `Error: 0`.

## Error handling: three tiers

1. **Client** — catch `AWS_EXCEPTIONS`, `return self.aws_error(e)`. Clients never raise for an AWS outcome, and never classify one. `structure.md` carries the canonical client shape and the reasoning behind the parameterless handler.
2. **Check** — inspect for the `"Error"` key and decide FAIL vs ERROR through `self.is_not_configured(error)`, against the service's declared table. Never by comparing a code inline.
3. **Orchestrator** — anything escaping `execute()` is caught per check in `run_checks`, logged with `exc_info=True`, and converted into exactly one synthetic ERROR row by `_synthetic_error`. A broken check degrades one row, not the whole scan. The synthetic row carries `region=GLOBAL_REGION`, `resource_id=None`, the check's **real** `severity` from `meta` (the pre-change row carried `"UNKNOWN"`, which was never a legal `Severity`), and `actual_value` naming the exception type as well as its message. It falls back to `meta.remediation.text` — the one place that is allowed, because the orchestrator knows only that something broke, and a cell naming the control beats an empty one.

Note that a check raising midway contributes one synthetic ERROR row **and nothing else**: the rows it yielded before failing go with the discarded generator.

### FAIL vs ERROR

- A semantic AWS code meaning "the thing isn't configured" (e.g. `AWSOrganizationsNotInUseException`) is a **FAIL**.
- A permission or transport failure is an **ERROR**.
- **Missing required input is an ERROR, not a FAIL.** Six checks got this wrong and have been fixed. A missing `--audit-account` means the control could not be evaluated; reporting it as FAIL asserts a negative the scan never established.

The judgement is **declared, not coded**. Every check's error branch has the same
two arms:

```python
if "Error" in response:
    error = response["Error"]
    if self.is_not_configured(error):
        yield self.failed(
            region="global",
            resource_id=self.account_id,
            actual_value="No organization exists",
        )
    else:
        yield self.error(
            region=region,
            resource_id=self.account_id,
            actual_value=(
                f"{error['Operation']} failed: {error['Code']}: "
                f"{error['Message']}"
            ),
            remediation=self._remediation_for(error),
        )
    return
```

Three things in that shape are contractual.

**`self.is_not_configured(error)`, never an inline code compare.** It reads
`type(self).NOT_CONFIGURED_ERRORS` — declared on the **service base class**, never
on a check, and `__init_subclass__` enforces that. Shield had the same
`error_code == "ResourceNotFoundException"` compare in all fourteen of its checks,
and `macie` had a `staticmethod` predicate that judged a code with no idea which
operation produced it. One table means two checks reading the same error result from
the same operation cannot classify it differently, *and* that the same code can be
classified differently by two operations where they warrant it —
`BadRequestException` means "not configured" through
`guardduty:DescribeOrganizationConfiguration` and "wrong account" through
`guardduty:ListOrganizationAdminAccounts`.

**The ERROR `ActualValue` is `f"{Operation} failed: {Code}: {Message}"`.** Not a
bare message. It is what lets a reader tell a permission gap from an unreachable
endpoint without opening the build log, and
`test_every_error_row_names_the_failed_operation_and_code` asserts the shape over
all 167 checks.

**The ERROR remediation is `self._remediation_for(error)`.** An ERROR row reports
that the control could not be evaluated, so its remediation concerns fixing the
*scan*, not fixing the control — which is why `error()` has no metadata fallback.
`_remediation_for` picks wording by `Code` class in four buckets: transport,
`NoClient`, access-denied, and everything else. The first two name the **service**,
because neither carries an operation; the last two name the **operation**, because
AWS answered and botocore attached one.

### Declaring a `NOT_CONFIGURED_ERRORS` entry

```python
class OrganizationsCheck(SecurityCheck):
    NAMESPACE = "organizations"

    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {
        "DescribeOrganization": {
            "AWSOrganizationsNotInUseException": NotConfigured(
                evidence=(
                    "https://docs.aws.amazon.com/organizations/latest/APIReference/"
                    "API_DescribeOrganization.html -- returned when the account is "
                    "not a member of an organization."
                ),
            ),
        },
    }
```

Keyed **operation first**, then code, then optionally a case-insensitive `message`
substring for an *overloaded* code — one AWS returns for both a semantic condition
and an access failure, so the code alone cannot separate them. `macie2` returns
`AccessDeniedException` both when Macie is disabled in a Region and when the caller
lacks the permission; only the message tells them apart.

`evidence` is **required and non-blank**, and it is a structural field validated at
construction rather than a comment. An entry converts an ERROR into a FAIL — it
turns "we could not tell" into "we established the control is absent" — so an entry
without evidence is an assertion, and a wrong one fabricates a finding out of a
permission failure. Two forms count: the AWS API reference page that documents the
code's meaning **for that operation**, or an observed `aws_call_failed` line from a
controlled account. `test_discriminator_property.py` rejects a placeholder.

**Anything undeclared resolves to ERROR.** That asymmetry is the whole design: a
code AWS introduces later, or a known code arriving from an operation nobody
considered, produces an honest "could not determine" rather than a fabricated FAIL.
An empty table is legal and means "this service has no semantic codes" —
`auditmanager`, `config`, `cloudtrail`, `ec2` and `iam` all declare `{}`, each with
its reason recorded on the base class. `auditmanager`'s is the instructive one: the
"Please complete AWS Audit Manager setup" condition could not be confirmed against
a not-yet-set-up account, so it was **omitted** rather than declared on inference.

**Under-declaring is a real failure mode, and the property suite cannot see it.**
An undeclared code resolving to ERROR is the conservative default and violates
nothing. `shield` shipped a table that omitted `ListProtections` and
`DescribeDRTAccess` on the reasoning that "no protections" arrives as a successful
empty list — true of a subscribed account, false of an unsubscribed one, where both
calls fail with `ResourceNotFoundException: The subscription does not exist.` Ten
controls would have stopped being reported as findings. What caught it was running
a full organization scan and diffing the verdicts against the previous run — which
is the only thing that can, and is worth doing for any change that can move a
`Status` cell.

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
- **`sra_macie_07` builds its `ActualValue` by joining a `set`** (`missing_accounts` is a set difference), so the cell's ordering is non-deterministic across runs and undiffable.
- **`services/securityincidentresponse/base.py` declares no `NAMESPACE`**, and `get_delegated_administrators()`, `get_organization_accounts()` and `get_role()` all pin `self.regions[0]` while the sibling `discover_sir_region()` resolves the region correctly. The Region *sweep* is fixed and cached — one `ListMemberships` sweep per scan rather than one per call — but the labelling is not, and `test_securityincidentresponse_declares_no_namespace` asserts the absence so it cannot be "fixed" by accident. Relabelling moves the `Region` cell on genuine PASS and FAIL rows, which makes the change impossible to separate from a regression when diffing two scans.
- **`ShieldClient.list_protections` reads the first page only.** Paginating would change which resources the per-resource fan-out covers, and a row-count change cannot be separated from a verdict change when diffing two scans.
- **`IAMCheck._validate_metadata` is dead and unusable.** It validates `check_name`, `description`, and `check_logic` as instance attributes; `check_name` no longer exists on a check at all, and the other two live on `meta`. Nothing calls it.
- **`SRA-CONFIG-08`'s ex-WARN branch is reachable but has never been observed.** It fires when the audit account is the Config delegated administrator for exactly one of `config.amazonaws.com` and `config-multiaccountsetup.amazonaws.com`. Exercising it needs an org configured that way.

Follow these patterns to create consistent, efficient, and maintainable security checks.
