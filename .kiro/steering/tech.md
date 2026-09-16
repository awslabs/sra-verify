# Tech Stack & Commands

## Stack

- **Python** — `python_requires>=3.11` in `setup.py`. The floor is load-bearing, not cosmetic: the code uses `StrEnum` (3.11+), `@dataclass(slots=True)`, and `X | None` annotations. The CodeBuild image runs 3.11; the working venv at `sra-verify/.venv` is 3.14.7.
- **boto3 / botocore** — the only AWS access path. Every AWS call goes through `ScanContext.get_client()`, never `boto3.client()` directly.
- **colorama** — used by `utils/banner.py` and `utils/progress.py` for terminal output.
- **pytest + hypothesis** — declared in `extras_require` under `dev` and `test`.
- **CloudFormation** — deployment (IAM roles via StackSets, and the CodeBuild scanner project).

Build system is **setuptools** (`sra-verify/sraverify/setup.py`), packaged with a console-script entry point:

```python
entry_points={"console_scripts": ["sraverify=sraverify.main:main"]}
```

There is no `pyproject.toml`, no Makefile, no tox/nox, no pytest config file, and no CI workflow in the `sra-verify` repo. The separate `sra-verify-mcp` repo *does* use `pyproject.toml` + hatchling + uv, with `ruff` and `pyright` as dev tools.

### Known inconsistencies (do not "fix" without asking)

- `sra-verify-mcp/pyproject.toml` declares `requires-python = ">=3.10"`, which cannot satisfy the scanner's 3.11 floor. The MCP repo's declared floor and its dependency are in conflict.
- `requirements.txt` pins `boto3>=1.40.5`; `setup.py` says `boto3>=1.26.0`.
- **Several client methods read the first page only, and the deferral is deliberate.** `ShieldClient.list_protections` is the clearest case: `shield` publishes a `list_protections` paginator, and the method does not use it. Most of `WAFClient`'s enumeration calls are the same shape, and `wafv2:ListWebACLs` has no botocore paginator at all — it takes a `NextMarker`/`Limit` pair that would have to be looped by hand. Fixing any of them changes *which resources* the per-resource fan-out covers, and a row-count change cannot be separated from a verdict change when reviewing two scans of the same organization, so all of them were held back rather than folded into the client-error-contract work. Where a call *does* paginate, the whole paginator loop belongs inside the `try`: a failure on page three has to arrive as an error result, because a short list is indistinguishable from a smaller organization.
- `build/`, `dist/`, and `*.egg-info/` are present in the working tree as stale artifacts. They are gitignored and untracked, so they are local debris rather than committed content — but they shadow a fresh build if you read from them.

The version is `0.2.0` in **two** places that must be kept in step by hand — `setup.py` and `sraverify/__init__.py` (`__version__`). Nothing single-sources it, and they have already drifted once (`0.1.4` vs `0.1.0`), so change both together. `sra-verify-mcp/pyproject.toml` pins `sraverify>=0.1.4` and is a third copy, in the other repo.

`sra-verify/sraverify/README.md` is the developer guide and is current as of the check-contract branch: it documents `ScanContext`, automatic registration and the four-way identity cross-check, `CheckMeta`, the three keyword-only finding helpers, FAIL-vs-ERROR, and `Finding.FIELDS`. It agrees with this file and with `creating_checks_best_practices.md`; if the three ever disagree, the steering files win and the README is the one to correct.

## Commands

All commands below assume you are at the workspace root. The pip project root is `sra-verify/sraverify/` (note the doubled name: the package itself is `sra-verify/sraverify/sraverify/`).

### Environment

```bash
uv venv                                        # or: python -m venv .venv
source .venv/bin/activate
pip install -r sra-verify/sraverify/requirements.txt
pip install -e ./sra-verify/sraverify          # editable install for development
```

### Run

```bash
sraverify --regions us-east-1,us-west-2
sraverify --list-checks                        # inventory; this is the exact format of docs/checks.txt
sraverify --list-services
sraverify --check SRA-GUARDDUTY-01 --debug     # verify a single check while developing
sraverify --service GuardDuty                  # case-insensitive, full-value service filter
sraverify --account-type audit --audit-account 111122223333
```

### Test

From the workspace root, the suite needs `PYTHONPATH` pointed at the pip project root:

```bash
PYTHONPATH=sra-verify/sraverify sra-verify/.venv/bin/python -m pytest sra-verify/sraverify/sraverify/tests/ -q
```

Bare `pytest` from the pip project root reaches the same tests and needs no `PYTHONPATH`:

```bash
cd sra-verify/sraverify && pytest -q
```

Both report **7854 passed, 411 skipped**, and no xfails — the client-error-contract migration ledger that produced them is deleted, so every property is now asserted unconditionally. The suite is `tests/property/` (~26 hypothesis and reflection modules, including catalog-wide properties that iterate the real 158 registered checks and the 92 real client methods) plus `tests/unit/{core,cli,util}/`. `tests/unit/mcp/` and `tests/unit/services/` hold only `__init__.py`. `tests/conftest.py` silences the boto3/botocore/urllib3 logger trees and nothing else.

Add `-p no:logging` when you want readable output: several modules assert on log records, and pytest's live-log capture floods the terminal otherwise.

```bash
PYTHONPATH=sra-verify/sraverify sra-verify/.venv/bin/python -m pytest sra-verify/sraverify/sraverify/tests/ -q --tb=line -p no:logging
```

The 410 skips are almost all one property: `test_a_declared_semantic_error_result_reaches_failed` parametrizes over every (check, declared `(operation, code)` pair) and skips a pair the check cannot reach — one whose operation is issued only *after* a successful enumeration, which the "every accessor fails" harness cannot set up. Its docstring says what reaching them would take.

### Regenerating `docs/checks.txt`

Use the installed console script, **not** `-m`:

```bash
sra-verify/.venv/bin/sraverify --list-checks > sra-verify/docs/checks.txt
```

`python -m sraverify.main` emits a `runpy` `RuntimeWarning` on stderr — `sraverify/__init__.py` imports `main`, so the module is already in `sys.modules` when runpy executes it — which contaminates a capture that redirects stderr. The console script produces a 0-byte stderr. This artifact has drifted from the code twice; a stale `docs/checks.txt` is a real failure mode, so verify with `cmp` after regenerating.

### Build

```bash
cd sra-verify/sraverify && python setup.py sdist bdist_wheel
```

## CLI surface

| Flag                               | Notes                                                                                                                                                                                                                                                                            |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--profile`                        | AWS profile                                                                                                                                                                                                                                                                      |
| `--role`                           | Role ARN to assume (session name `sraverify-session`)                                                                                                                                                                                                                            |
| `--regions`                        | Comma-separated. Omitted → lazy `ec2:DescribeRegions` for enabled regions                                                                                                                                                                                                        |
| `--output`                         | Default `sraverify_findings.csv`; **when the value equals that default**, a `_YYYYmmdd_HHMMSS` timestamp is injected before the extension. An explicitly supplied path that happens to match the default gets a timestamp too — deliberate, and it preserves pre-change behavior |
| `--check`                          | Single check ID, e.g. `SRA-GUARDDUTY-01`. Matched exactly and case-sensitively. **Narrows** the selection rather than replacing it, so it still intersects `--account-type` and `--service`                                                                                      |
| `--service`                        | Case-insensitive but **full-value** match on the check's `service` metadata. `--service Security` matches nothing                                                                                                                                                                |
| `--account-type`                   | `application` \| `audit` \| `log-archive` \| `management` \| `all` (default `all`)                                                                                                                                                                                               |
| `--audit-account`                  | Comma-separated account IDs; reaches checks via `self.audit_accounts`                                                                                                                                                                                                            |
| `--log-archive-account`            | Comma-separated account IDs; reaches checks via `self.log_archive_accounts`                                                                                                                                                                                                      |
| `--list-checks`, `--list-services` | Inventory, then exit 0. `--list-checks` honors `--account-type`                                                                                                                                                                                                                  |
| `--debug`                          | DEBUG on the `sraverify` logger                                                                                                                                                                                                                                                  |
| `--connect-timeout`                | boto3 connect timeout, default 10s                                                                                                                                                                                                                                               |
| `--read-timeout`                   | boto3 read timeout, default 30s                                                                                                                                                                                                                                                  |
| `--max-attempts`                   | boto3 retry attempts, default 3, `standard` mode                                                                                                                                                                                                                                 |
| `--max-pool-connections`           | default 50                                                                                                                                                                                                                                                                       |

The `--account-type` choices are generated in `parse_args` as `[t.value for t in AccountType] + ['all']`, and the help text from the same list, so the CLI holds no second copy of the account-type strings to drift from `core/enums.py`.

The four boto3 tuning flags default to `None` at the argparse layer and are forwarded into the per-scan `ScanContext`, which owns the bounded `botocore.config.Config`; `None` means "keep the context default". Those defaults live as module constants in `core/scan_context.py` (`DEFAULT_CONNECT_TIMEOUT = 10`, `DEFAULT_READ_TIMEOUT = 30`, `DEFAULT_MAX_ATTEMPTS = 3`, `DEFAULT_RETRY_MODE = "standard"`, `DEFAULT_MAX_POOL_CONNECTIONS = 50`) and are what the help text quotes.

## Exit codes

| Code  | Meaning                                                                                                                   |
| ----- | ------------------------------------------------------------------------------------------------------------------------- |
| **0** | A report was written. Holds regardless of how many FAIL or ERROR rows it contains                                         |
| **1** | The scan ran but the output file could not be written (`OSError`). Path and reason are logged; no scan summary is printed |
| **2** | Usage error. **No file is created**                                                                                       |

Exit 0 on a report full of FAILs is load-bearing, and the instinct runs the other way. A FAIL is the tool working. The buildspec fans `sraverify` out across every ACTIVE account with GNU `parallel`, so a non-zero status from one member account would make `parallel` treat that account as a failed job. Non-zero means only "this invocation produced no usable report" — exactly the signal the pandas consolidation step needs to tell a missing CSV from an empty one.

Exit 2 covers two cases, both raised out of check selection before any AWS call:

- An unknown `--check` ID. Up to three near-miss registry keys are logged as suggestions.
- A real-but-empty filter combination, e.g. `--account-type audit --service CloudTrail`. The three filter values are logged.

Both previously logged an error, wrote a header-only CSV, and exited 0 — indistinguishable from a clean scan, and in the CodeBuild fan-out that silently under-reported a whole account.

`1` rather than `2` for a write failure is deliberate: a full disk or a stale working directory is often transient and worth a retry, whereas 2 is reserved for arguments that will not work on a second run.

## Registration and discovery

There is no manual check registration. `import sraverify.services` walks every service subpackage and every `sra_*` module with `pkgutil`, and each check class body fires `SecurityCheck.__init_subclass__`, which registers it. A defective check is therefore a boot failure rather than a silent skip, and adding a file to `checks/` is the whole of its registration. See `structure.md` for the layout and the authoring order.

## Logging, and the stdout contract

Use the single shared logger. **Never call `print()` from library or check code**, and never add a stdout handler.

```python
from sraverify.core.logging import logger
```

`core/logging.py` strips the root logger's handlers at import time and installs a **stderr-only** handler. `logger.propagate = False`; boto3/botocore/urllib3 are forced to WARNING and propagate to the stderr root handler.

Conventions: `logger.debug(f"ServiceName: <message>")` in service base classes, `logger.warning` for a missing client, and `logger.debug` for a failed AWS call.

**`logger.error` is reserved for something that produced an ERROR row.** A failed AWS call is not one: `AccessDeniedException: Macie is not enabled` is a normal observation the check tier turns into a FAIL. The client tier cannot tell that from a broken scan — only `is_not_configured` can — so a client that logged at `error` would be classifying one tier before the information exists. An audit-account scan did exactly that: five ERROR lines, then `Error: 0` in the summary. `test_no_error_level_records_without_error_rows` holds the correspondence.

**stdout being empty is a contract, and it is asserted** — `tests/property/test_stdout_contract_property.py` holds that nothing in the package writes to it. Two consumers depend on it:

- The **MCP server** speaks JSON-RPC over stdout, so one stray `print` corrupts the protocol.
- **Diagnostics stay greppable.** `AWSClient.aws_error` emits exactly one record per failed AWS call:

  ```
  aws_call_failed operation=<Op> region=<Region> code=<Code> message=<JSON>
  ```

  at **`debug`**, with `message` last and `json.dumps`-encoded, so an AWS message containing an embedded newline cannot break the one-line promise. One failed call is one line, which is what lets `grep -c aws_call_failed` answer "how many calls failed" on a `--debug` log. It sits at `debug` because the report is the artefact that carries the verdict: a semantic failure's FAIL row states the reason, an ERROR row carries the operation, code and message verbatim, and the summary counts the ERROR rows.

  Keep it that way, and resist adding a second record per failure or a per-check progress line. On a 13-account organization a scan already emits ~528 of these; anything emitted per check rather than per failure adds ~900 more and drowns them. A `check_done` marker at `info` did exactly that and was removed.

## Deployment

- **`1-sraverify-member-roles.yaml`** — creates `SRAMemberRole` plus the `SRAVerifyCheckPermissions` and `SRAVerifyLeastPrivilege` managed policies. Deployed org-wide via service-managed StackSets, and separately in the management account (StackSets do not target it).
- **`2-sraverify-codebuild-deploy.yaml`** — the CodeBuild project, findings bucket, and a Lambda-backed custom resource that starts the first build at deploy time. Parameters: `AuditAccountID`, `LogArchiveAccountID`, `ParallelAccounts` (default 5), `IncludeRegions`, `GitBranch`.

The inline buildspec is the canonical execution model, and it explains what `--account-type` means in practice:

1. `--account-type management` against the org management account
2. `--account-type audit` per audit account
3. `--account-type log-archive` per log-archive account
4. `--account-type application` for every ACTIVE org account, fanned out with GNU `parallel -j ${PARALLEL_ACCOUNTS:-5}`
5. Consolidate all `sraverify*.csv` files with a pandas step; results land in S3 under `sraverify/reports/{raw,consolidated}/`, alongside a copy of `sra-verify-dashboard.html`

The buildspec does **not** capture stderr per account. Under `parallel -j5` five
processes interleave into one CloudWatch stream, so a diagnostic cannot be
attributed to an account from the merged log alone. A buildspec edit to write one
stderr file per invocation was written and then withdrawn: the template is
published publicly and the artefact had no consumer outside our own tooling.

If you need per-account diagnostics, run `sraverify` once per account locally and
redirect stderr yourself — the CLI takes `--profile`, `--account-type` and
`--regions`, which is all the buildspec does.

Parallelism is **process-level** (one `sraverify` process per account), not threads inside a single scan. The build runtime is `python: 3.11`, which is the declared floor — raising the floor again means editing the buildspec.

## IAM policy generation

`sra-verify/util/generate_iam_policy.py` derives the least-privilege member-role policy from the API calls the checks make, producing `generated_sraverify_iam_policy.json` and `generated_sraverify_cf_policy.yaml`. If you add a new AWS API call to any client, regenerate these and update `1-sraverify-member-roles.yaml`.

The account-flags fix newly exercises exactly one AWS operation, `organizations:ListAccountsForParent` (the `SRA-ORGANIZATIONS-08` / `-09` Security-OU membership comparison), and it was already granted at line 203 of `1-sraverify-member-roles.yaml` — so no regeneration was needed there. The standing rule is unchanged.
