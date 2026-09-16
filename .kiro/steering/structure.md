# Project Structure & Patterns

## Workspace layout

This workspace holds **two separate git repos** side by side:

```
sraverify/                          <- workspace root (not itself a git repo)
├── sra-verify/                     <- git repo: the scanner (awslabs/sra-verify)
│   └── .kiro/
│       ├── steering/               <- these docs
│       └── specs/                  <- check-contract-formalization,
│                                      scan-context-refactor, iam-user-detection
└── sra-verify-mcp/                 <- git repo: the MCP server (awslabs/sra-verify-mcp)
```

The workspace root holds no `.kiro/` directory. The only one lives inside the
scanner repo: the four-file steering set at `sra-verify/.kiro/steering/` and the
specs at `sra-verify/.kiro/specs/`. The four steering files are `product.md`
(what the tool is and why), `tech.md` (stack, commands, logging, deployment),
this file (layout, architecture, contracts), and
`creating_checks_best_practices.md` (authoritative for check-authoring detail).

`sra-verify/.kiro/` is tracked in git — 16 files, the four steering docs plus
the three specs and their `.config.kiro` files. Edits to steering and specs are
therefore part of a commit like any other change.

## The scanner repo

```
sra-verify/
├── .kiro/steering/                     # the four steering docs
├── .kiro/specs/                        # check-contract-formalization,
│                                       #   scan-context-refactor, iam-user-detection
├── 1-sraverify-member-roles.yaml       # StackSet: SRAMemberRole + managed policies
├── 2-sraverify-codebuild-deploy.yaml   # CodeBuild project + findings bucket + starter Lambda
├── docs/checks.txt                     # verbatim `sraverify --list-checks` output
├── sra-verify-dashboard.html           # standalone HTML findings viewer
├── sra-verify-comparison-dashboard.html
├── generated_sraverify_iam_policy.json # output of util/generate_iam_policy.py
├── generated_sraverify_cf_policy.yaml
├── util/generate_iam_policy.py         # derives the least-privilege member policy
├── sratester/prompt.md                 # agent prompt for manual validation (see below)
└── sraverify/                          # pip project root (setup.py lives here)
    ├── setup.py, requirements.txt
    └── sraverify/                      # the Python package
        ├── main.py                     # SRAVerify class, _select, CLI, exit codes
        ├── core/
        │   ├── check.py                # SecurityCheck: meta, registration, finding helpers
        │   ├── metadata.py             # CheckMeta, Remediation (validated, frozen)
        │   ├── finding.py              # Finding, Finding.FIELDS, GLOBAL_REGION
        │   ├── enums.py                # Status, Severity, AccountType (StrEnum)
        │   ├── errors.py               # SRAVerifyError hierarchy
        │   ├── registry.py             # _REGISTRY, register, all_checks
        │   ├── discovery.py            # import_check_modules, import_service_packages
        │   ├── scan_context.py         # ScanContext: all per-scan state
        │   ├── aws_errors.py           # error-result shape, is_error, is_not_configured
        │   ├── aws_client.py           # AWSClient: AWS_EXCEPTIONS + aws_error
        │   ├── availability.py         # service_available_in_region (offline, cached)
        │   ├── logging.py              # shared stderr-only logger
        │   └── session.py              # profile + assume-role session builder
        ├── utils/
        │   ├── outputs.py              # write_csv_output
        │   └── banner.py, progress.py
        ├── services/
        │   ├── __init__.py             # import_service_packages(__name__)
        │   └── <service>/
        │       ├── __init__.py         # import_check_modules(f"{__name__}.checks")
        │       ├── base.py             # <Service>Check: NAMESPACE,
        │       │                       #   NOT_CONFIGURED_ERRORS, cached accessors
        │       ├── client.py           # <Service>Client(AWSClient): raw boto3 calls
        │       └── checks/sra_<service>_NN.py
        └── tests/
            ├── conftest.py             # silences boto3/botocore/urllib3 loggers
            ├── unit/{core,cli,util}/
            └── property/               # ~26 modules + strategies.py
```

Note the tripled `sraverify` in paths. Package code is at
`sra-verify/sraverify/sraverify/`, and the test suite is one level deeper still
at `sra-verify/sraverify/sraverify/tests/`. The old outer
`sra-verify/sraverify/tests/` directory is gone; do not recreate it.

`sratester/` is **not** a test framework and no longer holds artifacts. It is a
single `prompt.md`: the agent prompt for the 5-phase manual validation
methodology (baseline → misconfigure → detect → fix → validate, CSV snapshot per
phase). Not packaged.

`tests/unit/mcp/` and `tests/unit/services/` exist but hold only `__init__.py`.

## Architecture: three layers plus a per-scan context

```
SecurityCheck            core/check.py                     meta, registration, passed/failed/error,
    ↑ extends                                              context delegation
<Service>Check           services/<svc>/base.py            _setup_clients + cached typed accessors
    ↑ extends
SRA_<SERVICE>_NN         services/<svc>/checks/sra_<svc>_NN.py   meta = CheckMeta(...) + execute()
                              ↓ uses
<Service>Client          services/<svc>/client.py          raw boto3, paginators, error normalization
```

Orthogonal to the hierarchy: **`ScanContext`** owns every piece of per-scan
state, and the **registry** owns the catalog.

### Registration is automatic

A check module's presence on disk is the whole of its registration. There is no
`CHECKS` dict in any service `__init__.py`, no `ALL_CHECKS` in `main.py`, and no
decorator.

- `services/<svc>/__init__.py` is three lines: a docstring, an import of
  `import_check_modules`, and `import_check_modules(f"{__name__}.checks")`.
- `services/__init__.py` is the aggregator: `import_service_packages(__name__)`.
  `import sraverify.services` therefore registers all 158 checks. `main.py`
  carries that import purely for its side effect — drop it and every scan
  selects nothing.
- Discovery picks up only modules whose name starts with `sra_`, sorted
  ascending lexicographically. Non-package modules at the `services` level and
  subpackages inside `checks/` are skipped.
- `SecurityCheck.__init_subclass__` does the registering, at class-creation
  (import) time. It cross-checks four independent expressions of identity — the
  module file stem (the authority, from which the expected check ID is derived),
  `meta.check_id`, the class name, and the containing service package — then
  applies two shape rules (no check inherits another check, no class attribute
  shadows a metadata property), and registers last. See
  `creating_checks_best_practices.md` for the full rule list and the exact
  errors.
- `all_checks()` is the only read path. It returns a `MappingProxyType` over a
  sorted copy, so the catalog is ordered by ascending check ID and cannot be
  mutated by a caller.

Consequence worth stating plainly: **the catalog is validated by importing it.**
A defective `CheckMeta` or a mis-filed module is a boot failure, not a silent
skip — the failure mode where a check is written, looks correct, and never runs
cannot occur. Nothing on the discovery or registration path opens a file or
issues an AWS call, which makes `--list-checks` a credential-free, I/O-free
catalog validation pass.

### ScanContext is the single owner of per-scan state

A fresh `ScanContext` is built per `run_checks()` call and `del`'d in a `finally`
block so its boto3 clients become collectible. This is what gives the
long-running MCP server per-scan isolation.

It owns: the boto3 `Session`, the region list, `audit_accounts`,
`log_archive_accounts`, the bounded `Client_Config`, a `(service, region)` boto3
client cache, a two-level namespaced response cache, and one `threading.Lock`.
All public accessors use double-checked locking. Execution is single-threaded
today; the thread safety is deliberate headroom.

**Never cache a failure.** If a client returns an error result, leave the cache
slot empty and return the error result unchanged, so a retry re-issues the call.
Both halves matter: an accessor that swallowed the error and returned `[]` would
satisfy "did not cache a failure" while handing the check exactly the ambiguous
value this contract removes. The cost is accepted explicitly — where two checks
call the same failing accessor, the call is issued once per calling check rather
than once per scan. That is the price of a retry being possible at all, and it is
bounded; the alternative was replaying one failure for the rest of the scan.

`_set` carries a **backstop**: it refuses an error result, logs a warning naming
the namespace, key and code, and returns. The accessor discipline is the primary
control and `tests/property/test_accessor_cache_property.py` holds it per
accessor; the backstop is for the accessor written next year by someone who has
not read that contract. One denied `ListSubscribers` call produced 8 wrong rows in
the 2026-09-12 baseline through exactly this path.

`no_client_result(service=…, region=…)` is what an accessor returns when
`get_client(region)` answers `None`. Neither a success nor an AWS failure — no
request was made — so its `Code` is `NoClient`, its `Operation` is
`UNKNOWN_OPERATION`, and it is never cached.

Because the context is per-scan, `run_checks` materializes each check's findings
with `list(check.execute())` inside the per-check guard. That `list()` is
load-bearing: a live generator frame would keep the check — and through it the
whole `ScanContext` and its cached clients — reachable past `del ctx`.

### SecurityCheck contract

Identity and description are a class-level `meta = CheckMeta(...)` declared in
the check's own class body. Check classes define **no** `__init__`;
`SecurityCheck.__init__(self)` takes no arguments beyond `self` and only
initializes `self._ctx = None` and `self._clients = {}`. The old
`account_type=` / `service=` / `resource_type=` constructor parameters are gone,
so a leftover `super().__init__(account_type=...)` raises `TypeError` naming the
argument. `grep "def __init__" services/*/checks/` returns nothing, and no
`services/*/base.py` defines one either. That is the invariant.

`initialize(ctx: ScanContext)` is the only initialization path. It assigns
`self._ctx` then calls `self._setup_clients()`. `def initialize` appears in
exactly one file in the package — `core/check.py`. A service base class or check
that overrides it, or that reads `**kwargs`, is a defect.

`execute()` is the only abstract method and the only source of findings. It
returns `Iterable[Finding]`; generators are the convention, and a bare `return`
is the early-exit idiom for a guard clause.

Read-only properties that delegate to `meta`:

`check_id`, `service`, `severity`, `account_type`

Read-only properties that delegate to the context, each routed through
`_require_ctx` so a read before `initialize(ctx)` names the property and the
check ID:

`session`, `regions`, `account_info`, `account_id`, `account_name`,
`audit_accounts`, `log_archive_accounts`

None of these has a setter, so assignment raises `AttributeError`. Account lists
flow exclusively through the context — `self.audit_accounts` and
`self.log_archive_accounts` are the only correct access path. Never the
underscore attributes on the context, never a `hasattr` / `getattr` probe, never
an `initialize` override reading `**kwargs`. 22 modules did the probe variant
and silently ignored both CLI flags; all are fixed.
`grep -rn "_audit_accounts\|_log_archive_accounts" services/ --include="*.py"`
returns nothing, and `self.params` no longer exists anywhere.

`findings`, `create_finding`, and `get_findings` are listed in `_REMOVED_ATTRS`.
Both reading and assigning them raises `AttributeError` with a pointer to the
replacement — assignment has to fail too, or a re-created `self.findings = []`
would silently collect rows nobody reads.

`get_management_accountId()` takes no argument; the legacy `session` parameter is
accepted and ignored. `get_client(region)` can return `None`. Always handle it.

## Naming conventions

| Thing                | Pattern                                         | Example                                |
| -------------------- | ----------------------------------------------- | -------------------------------------- |
| Check ID             | `SRA-<SERVICE>-NN` (`NN` in `01`–`99`)          | `SRA-GUARDDUTY-01`                     |
| Check class          | `SRA_<SERVICE>_NN` (screaming snake, not PEP 8) | `SRA_ORGANIZATIONS_01`                 |
| Check file           | `sra_<service>_NN.py`                           | `sra_securitylake_17.py`               |
| Service base class   | `<Service>Check`                                | `GuardDutyCheck`                       |
| Client class         | `<Service>Client`                               | `OrganizationsClient`                  |
| Cache namespace      | lowercase service dir name                      | `NAMESPACE = "guardduty"`              |
| `meta.service`       | AWS display name, mixed case                    | `"GuardDuty"`, `"IAM Access Analyzer"` |
| `meta.resource_type` | CloudFormation type string                      | `"AWS::GuardDuty::Detector"`           |

The file stem, the check ID, the class name, and the containing service package
are all derivable from one another and are cross-checked at import. `CHECK_ID_RE`
lives in `core/metadata.py`; `CHECK_MODULE_RE` in `core/check.py`. The `01`–`99`
range caps one service at 99 checks (largest today: GuardDuty at 25).

Legal values are enum members, not strings (`core/enums.py`, all `StrEnum`):

- `Status`: `PASS`, `FAIL`, `ERROR`
- `Severity`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`
- `AccountType`: `application`, `audit`, `log-archive`, `management` — the
  members' values are exactly the `--account-type` choices, so the CLI is fed
  `[t.value for t in AccountType] + ["all"]`

Non-regional checks pass `region=GLOBAL_REGION` (`"global"`, from
`core/finding.py`).

Legacy short IDs (`SRA-GD-1`, `SRA-CT-1`, `SRA-IAA-1`) appear in READMEs, CLI
help text, and docstrings. They are all stale; no such check exists.

## Adding a new check

No registration step exists. Writing the file registers it.

1. **Research the AWS API first.** Use the AWS documentation tools to confirm
   method names, parameters, and response shape. Do not assume.
2. New service? Create `services/<svc>/` with `__init__.py` (the three-line
   discovery call), `base.py`, `client.py`, and `checks/__init__.py`.
3. **`client.py`** — add the raw call to a class inheriting `AWSClient`. Acquire
   the boto3 client in `__init__`, never in the method. Paginate where a paginator
   exists, with the whole loop inside the `try`. The handler is
   `except AWS_EXCEPTIONS as e: return self.aws_error(e)`. Add a `ClientAdapter`
   for it to `tests/property/test_client_contract_property.py`, or that service's
   completeness test fails.
4. **`base.py`** — add a cached typed accessor using `self._ctx._has/_get/_set`
   under the class `NAMESPACE`. Return `no_client_result(...)` on the no-client
   path, and return an error result unchanged without caching it. Reuse an
   existing accessor if one already fetches the data. Add an `AccessorAdapter`
   for it to `tests/property/test_accessor_cache_property.py`, or
   `test_every_public_base_method_is_classified` fails for that service.
4a. **Is any error code from the new call semantic** — does it mean "the control
   is not configured" rather than "we could not look"? If so, declare it in the
   base class's `NOT_CONFIGURED_ERRORS` with its evidence. If unsure, leave it
   out: an undeclared code yields an honest ERROR.
5. **`checks/sra_<svc>_NN.py`** — the check class with `meta = CheckMeta(...)`
   and a yielding `execute()`.
6. Verify: `sraverify --check SRA-<SERVICE>-NN --debug`.
7. New AWS API call? Regenerate the IAM policy via `util/generate_iam_policy.py`
   and update `1-sraverify-member-roles.yaml`.
8. Regenerate `docs/checks.txt` from `sraverify --list-checks`.

## Canonical code shapes

### Check class

```python
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
            "A detector is a resource that represents the GuardDuty service ..."
        ),
        check_logic="Get detector_id in each Region. Check fails if there is no detector_id",
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
        """Execute the check.

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

Use parenthesized implicit string concatenation for multi-line metadata text,
not backslash continuations. `CheckMeta` rule 4 rejects any value that is not
whitespace-normalized, so a continuation is now an import failure rather than a
run of whitespace in a CSV cell.

### Service base class (regional)

```python
class GuardDutyCheck(SecurityCheck):
    """Base class for all GuardDuty security checks."""

    NAMESPACE = "guardduty"          # required class constant

    def _setup_clients(self):
        self._clients.clear()
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = GuardDutyClient(region, ctx=self._ctx)

    def get_detector_id(self, region: str) -> Optional[str]:
        cache_key = f"detector_id:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            return self._ctx._get(self.NAMESPACE, cache_key)
        client = self.get_client(region)
        if not client:
            logger.warning(f"GuardDuty: No client available for region {region}")
            return None
        detector_id = client.get_detector_id()
        if detector_id:
            self._ctx._set(self.NAMESPACE, cache_key, detector_id)
        return detector_id
```

No `__init__`. Metadata belongs to the check subclass, and a service base class
that declared `meta` — or a class attribute named `check_id`, `service`,
`severity`, or `account_type` — would fail the shadowing rule at import.

For a **global** service, build a single client in `_setup_clients`, clear
`self._clients`, and pin the region inside the client wrapper:

```python
def _setup_clients(self):
    # Organizations is global: one client pinned to us-east-1 inside the wrapper.
    self._org_client = OrganizationsClient(ctx=self._ctx)
    self._clients.clear()
```

Cache keys are `"<thing>:<discriminator>"` with no account or session-region
prefix — the context is already per-scan and per-account. (`IAMCheck` is the
exception and keys on `account_id`, because an assumed-role session can in
principle cross account boundaries.)

`_has` / `_get` / `_set` are for **service base classes only**. Individual check
classes must never touch them; they call the typed accessor on their base class.

### Client method

Every `<Service>Client` inherits `AWSClient` (`core/aws_client.py`) and chains
`super().__init__(region, ctx)`. Boto3 clients are acquired **in `__init__` and
nowhere else**.

```python
class OrganizationsClient(AWSClient):
    def __init__(self, ctx: ScanContext):
        # Organizations is global: pinned inside the wrapper.
        super().__init__("us-east-1", ctx)
        self.client = ctx.get_client("organizations", region="us-east-1")

    def list_roots(self) -> Mapping[str, Any]:
        try:
            roots = []
            for page in self.client.get_paginator("list_roots").paginate():
                roots.extend(page.get("Roots", []))
            return {"Roots": roots}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)
```

That `except` clause is byte-identical in all 92 client methods. There is nothing
to type per call site — no operation name, no Region — and therefore nothing that
can be typed wrong. Three rules make it work:

- **`AWS_EXCEPTIONS` is `(ClientError, BotoCoreError)`, named as a tuple** so an
  `except` clause cannot narrow the pair by accident. Writing `except ClientError`
  alone is what let transport failures escape seven clients and cost each affected
  check its whole output for the account. Anything else — `AttributeError`,
  `KeyError` — is a programming defect and must propagate to the orchestrator.
- **`self.aws_error(e)` takes only the exception.** The Region comes from
  `self.region`; the operation comes from `e.operation_name` where botocore has it,
  and is `UNKNOWN_OPERATION` (`"Request"`) for a `BotoCoreError`, which never
  completed a request and so has no operation to claim. It logs exactly one
  `aws_call_failed operation=… region=… code=… message=…` record at `debug`, with
  `message` JSON-encoded so an AWS message containing a newline cannot break the
  one-line promise: one failure is one line, always. `debug` rather than `error`
  because this tier cannot know whether the failure is semantic — an `error` here
  would claim a severity that only `is_not_configured` can assign.
- **Acquisition is constructor-only.** `ctx.get_client` reads bundled endpoint data
  and issues no network call, so its failure is a deterministic defect, not an AWS
  outcome. Inside a `try` it would be caught as a `BotoCoreError` and turned into
  an error result describing a call that was never made. It is also what lets
  `util/generate_iam_policy.py` attribute each `self.<attr>.<method>(...)` to one
  service by reading `__init__`.

Clients never raise for an AWS outcome and never classify one. They return either
a named-key success dict or the **error result** from `core/aws_errors.py` —
`{"Error": {"Code", "Message", "Operation"}}`, every field a non-blank `str`.
`"Error" in result` is the only test that separates success from failure, at every
tier. `is_error(value)` is the strict form, and `error_result()` rejects exactly
the inputs `is_error` would.

There is one legitimate place a client *constructs* an error result rather than
catching one: `ShieldClient.get_web_acl_for_resource`'s CloudFront branch
synthesizes `WAFNonexistentItemException` for a distribution whose `WebACLId` is
empty. AWS answered; the synthesis expresses that answer in the shape `wafv2`
would have used. It has its own test so a reader sweeping for "clients must not
classify" does not delete it.

`tests/property/test_client_contract_property.py` drives every one of the 92
methods through a simulated `ClientError`, `EndpointConnectionError`,
`NoCredentialsError` and `RuntimeError` and asserts the return shape, so a handler
that erases the error or forgets `BotoCoreError` fails a test rather than a scan.

## Error handling: three tiers

1. **Client** — catch `AWS_EXCEPTIONS` → `return self.aws_error(e)`. Never raises
   for an AWS outcome, never decides FAIL versus ERROR.
2. **Check** — inspect for the `"Error"` key and decide FAIL vs ERROR through
   `self.is_not_configured(error)`, which reads the service's declared
   `NOT_CONFIGURED_ERRORS` table. See `creating_checks_best_practices.md` for the
   table, the evidence rule, and the helper semantics.
3. **Orchestrator** — one guarded block per check in `run_checks`, spanning
   construction, `initialize`, and consumption of `execute()`. Anything escaping
   it is logged with `exc_info=True` and converted by `_synthetic_error` into a
   single ERROR row built from `check_class.meta` — never from an instance, since
   construction is one of the things that can fail. That row carries
   `region=GLOBAL_REGION`, `resource_id=None`, the check's real `severity`, the
   scan's account identity, and an `actual_value` naming the exception type as
   well as its message. A broken check degrades one row, not the whole scan.
   `except Exception`, deliberately not `BaseException`: a Ctrl-C must not
   produce a full-looking report from an aborted scan.

   **After this feature a synthetic ERROR row means a programming defect.** A
   client returns normally for every `ClientError` and every `BotoCoreError`, so
   nothing an AWS outcome can do reaches this guard. `candidate_synthetic_rows` is
   a gate metric for that reason and its expected value is zero.

## Findings and CSV

`Finding` (`core/finding.py`) is a frozen, slotted dataclass and the only row
type. It is built through `passed()` / `failed()` / `error()` on
`SecurityCheck` — all keyword-only, over one private `_finding` builder.
`create_finding` is gone.

`Finding.__post_init__` coerces the three enum fields, type-checks the twelve
required string fields, allows `resource_id` to be `str | None`, and enforces
that `title` starts with `f"{check_id} "`. `_finding` composes that title in
exactly one place, which is what makes the prefix rule enforceable.

A `Finding` holds no reference to the check or to the `ScanContext` —
`account_id` and `account_name` are copied by value — so findings outlive
`del ctx`.

The authoritative 16-column order is `Finding.FIELDS`, a
`ClassVar[tuple[str, ...]]` in `core/finding.py`. There is no `REQUIRED_FIELDS`
in `utils/outputs.py` any more.

```python
FIELDS: ClassVar[tuple[str, ...]] = (
    "AccountId", "AccountName", "Region", "CheckId", "Status", "Severity",
    "Title", "Description", "ResourceId", "ResourceType", "CheckedValue",
    "ActualValue", "Remediation", "Service", "CheckLogic", "AccountType",
)
```

`Finding.to_row()` renders one row keyed by `FIELDS`, in `FIELDS` order. Enum
fields are rendered with an explicit `.value` so output does not depend on
`StrEnum.__str__` behavior, and `resource_id=None` renders as `""`. No quoting,
escaping, or truncation happens there — that belongs to the CSV writer.

`write_csv_output` always creates the file, even for an empty findings list, so a
consumer can tell "scan ran, nothing found" from "scan did not run". Dialect is
pinned explicitly (UTF-8, `\r\n`, `QUOTE_MINIMAL`, doubled quotes) so the emitted
bytes do not vary by platform or locale. There is no missing-field backfill and
no legacy `CheckType` migration — a `Finding` has no uncertain shape. An
unopenable path raises `OSError`; no directory is created.

The 16 names and their order are a public contract parsed by
`sra-verify-dashboard.html` and `sra-verify-comparison-dashboard.html`. Do not
reorder.

## CLI exit codes

`main.py` owns selection (`_select`), the synthetic ERROR row
(`_synthetic_error`), and near-miss suggestions (`_near_misses`).

| Exit | Meaning                                                                                                                                                                                             |
| ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0    | A report was written. Holds regardless of how many FAIL or ERROR rows it contains — a FAIL is the tool working, and the CodeBuild fan-out would abort on a non-zero status from one member account. |
| 1    | The scan succeeded but the output file could not be written. Path and reason are logged; no summary is printed, because the summary is the operator's evidence that a usable report exists.         |
| 2    | Usage error: an unknown `--check` ID (`UnknownCheckError`, carrying up to three near-miss suggestions) or a real-but-empty filter combination (`NoChecksSelectedError`). **No file is created.**    |

Exit 2 replaces the old "log, return `[]`, write a header-only CSV, exit 0",
which was indistinguishable from a clean scan and silently under-reported a whole
account in the fan-out.

`--check` *narrows* the selection rather than replacing it, so an ID that
contradicts a supplied `--account-type` or `--service` yields zero matches and
reaches `NoChecksSelectedError`. `--service` is a full-value, ASCII-lowercased
comparison: `--service Security` matches nothing. Selection reads `cls.meta` only
and instantiates nothing.

The exit-2 guard spans both the banner and the scan, because both resolve the
filters — the banner's check count calls `_select` directly.

`_near_misses` is hand-rolled rather than `difflib.get_close_matches` because
that function selects with `heapq.nlargest` over `(ratio, key)` tuples, so
equally-similar keys come back in *descending* key order
(`SRA-GUARDDUTY-02` before `SRA-GUARDDUTY-01`). Computing the ratios locally
keeps difflib's scoring and its `quick_ratio` short-circuits while making the tie
order ascending and reproducible.

## Tests

The suite lives at `sra-verify/sraverify/sraverify/tests/` and currently collects
**7867 tests**, with 410 skips and no xfails. It is no longer thin.

- `tests/unit/core/` — `test_check_registration.py`, `test_enums.py`,
  `test_finding.py`, `test_metadata.py`, `test_registry.py`, `test_select.py`
- `tests/unit/cli/` — `test_exit_codes.py`, `test_exit_codes_scan.py`
- `tests/property/` — ~26 hypothesis and reflection modules plus `strategies.py`,
  covering metadata validation, `Finding` immutability / value types / row
  contract, CSV round-trip, helper signatures, the accumulator ban, context
  isolation, registry bijection, and selection

The client-error-contract modules are the largest block and are worth knowing by
name, because between them they hold the whole contract:

| Module                                  | What it holds                                                                                                                                                                                                                                                             |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `test_client_contract_property.py`      | All 92 client methods driven through a `ClientError`, an `EndpointConnectionError`, a `NoCredentialsError` and a `RuntimeError`; plus AST rules over all 18 `client.py` files — handler shape, `AWSClient` inheritance, constructor-only acquisition, no `-> bool` return |
| `test_accessor_cache_property.py`       | Every public base method classified as `accessor`, `accessor_uncached`, `helper`, `client_lookup` or `derived`, proven total and exact against the real classes; then never-cache-a-failure, re-issue-on-retry, the no-client result, and the cache key                   |
| `test_check_classification_property.py` | Catalog-wide over all 158 checks: an error result reaches `error()` with an `ActualValue` naming the operation and code, never `failed()`; a declared semantic code reaches `failed()`; an unsupported Region yields no row and issues no call                            |
| `test_discriminator_property.py`        | Every `NOT_CONFIGURED_ERRORS` entry: shape, non-blank evidence, no placeholders, and `is_not_configured` conservative on anything undeclared                                                                                                                              |
| `test_no_confessing_fail_property.py`   | Static, by AST, over all 158 check modules: no confessing `failed()` wording, no `except` inside `execute()`, no direct SDK access                                                                                                                                        |
| `test_availability_property.py`         | `service_available_in_region` is offline, cached, and fails open                                                                                                                                                                                                          |
| `test_stdout_contract_property.py`      | Nothing in the package writes to stdout                                                                                                                                                                                                                                   |

Two of these carry an **adapter table** that is *prescriptive*, not descriptive:
the `ClientAdapter` tables in `test_client_contract_property.py` name the boto3
method, operation and success shape each client method is contracted to produce,
and the `AccessorAdapter` tables in `test_accessor_cache_property.py` do the same
for base accessors. A new client method or base accessor must be added to its
table or `test_the_adapter_table_is_complete_and_exact` /
`test_every_public_base_method_is_classified` fails for that service. That is
deliberate: the tables are how the suite knows what to drive, so an unlisted
method would be silently untested.

Several property modules are **catalog-wide**: they enumerate the real 158
registered checks with `pytest.mark.parametrize` rather than sampling, so a
failure names the offending check ID in the test ID. None of them needs
credentials or issues an AWS call.

`conftest.py` silences the boto3/botocore/urllib3 logger trees. There is no
pytest config file.

## Data-structure gotchas

- An empty dict `{}` is truthy. Use `"key" in config` for existence checks, not
  `if config.get("key")`.
- Prefer `config.get("field")` over `config.get("field", {})` so a missing field
  stays distinguishable from an empty one.
- AWS responses omit fields entirely when a feature is disabled. Do not assume a
  key is present.
- Filter resources early to cut downstream work and API calls.

## Known structural oddities (do not "fix" blind)

- `services/securityincidentresponse/base.py` declares no `NAMESPACE`, and three
  of its accessors pin `self.regions[0]` while the sibling `discover_sir_region()`
  resolves the Region correctly. The Region sweep itself is cached now — one
  `_discover_memberships` per scan under a module-level `_CACHE_NAMESPACE` rather
  than a `ListMemberships` sweep per call — but the labelling defect stays.
  Deferred deliberately: relabelling moves the `Region` cell on genuine PASS and
  FAIL rows, which makes the change impossible to separate from a regression when
  reviewing two scans of the same organization.
  `test_securityincidentresponse_declares_no_namespace` asserts the absence so the
  deferral cannot be undone by accident.
- `sra_firewallmanager_01` hardcodes `region = "us-east-1"` and has no Region loop.
  Firewall Manager's admin API is genuinely single-Region, but the literal means
  `--regions` has no effect on that row's `Region` cell. Same deferral.
- `ShieldClient.list_protections` reads the **first page only**. Paginating would
  change which resources the per-resource fan-out covers, and a row-count change
  is exactly what cannot be separated from a verdict change when reviewing two
  scans.
- `IAMCheck._validate_metadata` is dead and unusable: it validates `check_name`,
  which no longer exists on any check.
- The version lives in two hand-maintained places, `setup.py` and
  `sraverify/__init__.py` (`__version__`), both `0.2.0`. Nothing single-sources
  it and they have drifted once already, so change both together.
- `requirements.txt` pins boto3 differently from `setup.py`.
- `build/`, `dist/`, and `*.egg-info/` are checked into the working tree.

For the current check-authoring anti-pattern list, see
`creating_checks_best_practices.md`.
