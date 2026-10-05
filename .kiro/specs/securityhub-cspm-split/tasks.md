# Implementation Plan: Security Hub CSPM split and missing CSPM checks

## Overview

One change, in the authoring order `structure.md` prescribes — client method → base accessor → `NOT_CONFIGURED_ERRORS` decision → check module → adapter rows → `sraverify --check` verification → IAM regeneration → `docs/checks.txt` regeneration → ASH scan — preceded by the **read-only API probe** that `testing_checks.md` puts first ("each step is cheaper than the next and usually settles something the next one would otherwise waste time on"), and followed by the live validation of `testing_checks.md` as a final phase. Implementation language is Python 3.11; stack as locked in `design.md` (boto3/botocore ≥ 1.43.96, pytest + hypothesis, hatchling/uv). No new dependency, no new package, no new lock entry.

Paths use the repository's tripled directory name. The repo root is `sra-verify/` (holds `1-sraverify-member-roles.yaml`, `util/`, `docs/`, `.kiro/`); the pip project root is `sra-verify/sraverify/` (holds `pyproject.toml` and `.venv`); the package is `sra-verify/sraverify/sraverify/`. Below, a package-relative path such as `services/securityhub/base.py` means `sraverify/sraverify/services/securityhub/base.py` from the repo root, and `tests/...` means `sraverify/sraverify/tests/...`.

### Order matters in four places

- **Task 1.5 (the read-only probe) before any code.** Four facts in `design.md` are deferred to it — whether `GetFindingAggregator` answers from a non-home Region, whether inherited accounts are listed as their own `ACCOUNT` summaries (which decides the shape of `-22`), and whether entries A and B are observable. Each changes code written in tasks 2, 3 and 5. The probe issues `List*`/`Get*` calls only and mutates nothing.
- **Task 2 (client) before task 3 (base) before task 5 (checks).** A check module that imports an accessor the base does not yet have is an import failure, and `import sraverify.services` is how the catalog is validated, so the suite would fail at collection rather than at one test.
- **The adapter rows (task 6) land in the same commit as the methods they describe.** Between task 2 and task 6, `test_the_adapter_table_is_complete_and_exact` and `test_every_public_base_method_is_classified` fail for `securityhub`, by design: the tables are prescriptive. Do not mark the suite green until task 6 is done.
- **The member-role template deploys before the CodeBuild run (task 12.6 before 12.7)**, per `tech.md`. Expect one transitional run of `AccessDeniedException` ERROR rows from `-21` and `-22` if it does not.

### What is not in this plan

No step mutates AWS before Phase 12 (task 1.5 reads only), and Phase 12 mutates only what `design.md`'s live-validation table names, after a snapshot, with restoration proven field by field. Nothing deregisters or re-designates a delegated administrator, disables Security Hub anywhere, or touches a Control Tower resource. Nothing is committed: the owner reviews and commits after task 13.

### Conventions used below

- Every command runs from the repo root unless it starts with `cd`. The suite is `cd sraverify && uv run pytest -q -p no:logging`. The console script is `sraverify/.venv/bin/sraverify`.
- Redirect long output to files under `.tmp/sratester/securityhub-cspm-split/` and read them back; `.tmp/` and `sratester/` are gitignored.
- Account IDs and profile names live only in `sratester/accounts.md`. Resolve IDs at run time with `aws sts get-caller-identity --profile <profile> --query Account --output text`. Never write either into a tracked file, including this one.
- "Requirement X.Y" refers to `requirements.md`; "Property N" to the numbered correctness properties in `design.md`.

---

## Tasks

- [ ] 1. Baseline
  - [ ] 1.1 Confirm a clean tree apart from the untracked `.kiro/specs/securityhub-cspm-split/` and the untracked, un-ignored `.worktrees/` entry (an unrelated `sir-log-readiness-checks` worktree; leave it alone, do not add it to `.gitignore` in this change): `git status --short`
    - _Requirements: 2.1_

  - [ ] 1.2 Baseline the suite: `cd sraverify && uv run pytest -q -p no:logging 2>&1 | tail -3 > ../.tmp/sratester/securityhub-cspm-split/baseline-pytest.txt`. Expected: **10081 passed, 1238 skipped**. Every later count is measured against this
    - _Requirements: 10.8_

  - [ ] 1.3 Baseline the catalog and the generator: `sraverify/.venv/bin/sraverify --list-checks > .tmp/sratester/securityhub-cspm-split/checks-before.txt && cmp .tmp/sratester/securityhub-cspm-split/checks-before.txt docs/checks.txt` (expected identical, 182 checks); `cd sraverify && uv run python ../util/generate_iam_policy.py --base-dir . --out-json ../.tmp/sratester/securityhub-cspm-split/pre-policy.json --out-yaml ../.tmp/sratester/securityhub-cspm-split/pre-policy.yaml --quiet` and `cmp` both against the local `generated_*` files at the repo root (gitignored by `generated*`; if absent, this baseline is simply the first generation and the `cmp` is skipped — the tracked mirror is `1-sraverify-member-roles.yaml`)
    - _Requirements: 10.6, 10.7_

  - [ ] 1.4 Confirm the two operations exist in the installed botocore and one has a paginator: `cd sraverify && uv run python -c "import boto3; c=boto3.client('securityhub', region_name='us-east-1', aws_access_key_id='x', aws_secret_access_key='y'); print(c.can_paginate('list_configuration_policy_associations'), hasattr(c, 'get_finding_aggregator'), hasattr(c, 'start_configuration_policy_disassociation'))"` → `True True True`
    - _Requirements: 8.1_

  - [ ] 1.5 **Probe the API live, read-only** (`testing_checks.md` § Order of work, step 1). Write `.tmp/sratester/securityhub-cspm-split/probe.sh` that, with the audit, management and one application profile from `sratester/accounts.md`, in the home Region and one non-home scanned Region, runs `aws securityhub list-finding-aggregators`, `get-finding-aggregator --finding-aggregator-arn <arn>` (where `<arn>` is the delegated administrator's aggregator ARN from the audit profile's `list-finding-aggregators`; the application and management accounts own no aggregator, so from those profiles the expected answer is an error, and its code and message are what the probe records), `list-configuration-policy-associations`, `get-enabled-standards`; plus `list-finding-aggregators` with the application profile in a Region where CSPM is not subscribed; plus `aws organizations list-accounts --query 'Accounts[?Status==\`ACTIVE\`].Id'` with the management profile. Capture every response and every error code and message to `probe.txt`, and append five explicit answers at the end:
    1. does `get-finding-aggregator` answer from the non-home Region (response or error code)?
    2. does the count of `TargetType=ACCOUNT` summaries from the audit profile in the home Region equal the active-account count? list every gap and its explanation. **If unexplained gaps exist, stop and rewrite `design.md` § SRA-SECURITYHUB-22 to the fallback resolver (Requirement 4.5a) before task 5.2**
    3. entry A — did the unsubscribed-Region `list-finding-aggregators` return `InvalidAccessException` with the "not subscribed" message? (quote it)
    4. entry B — did `list-configuration-policy-associations` with the management profile in the home Region return `AccessDeniedException` with the "with central configuration enabled" message? (quote it)
    5. what did `list-finding-aggregators` return with the management profile — an empty list, or an aggregator? (decides the expected `-22` row in task 12.2)
    Also read `https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_StartConfigurationPolicyDisassociation.html` and confirm `--configuration-policy-identifier SELF_MANAGED_SECURITY_HUB` is the identifier for disassociating a self-managed target (`disassociate-policy.html` says so); record it. Nothing in this task writes to AWS
    - _Requirements: 4.4, 4.5a, 9.2, 9.3, 12.1_

- [ ] 2. `services/securityhub/client.py` — two methods
  - [ ] 2.1 Add `get_finding_aggregator(self, aggregator_arn: str) -> Mapping[str, Any]` exactly as `design.md` § Components shows: `self.client.get_finding_aggregator(FindingAggregatorArn=aggregator_arn)` inside `try`, handler `except AWS_EXCEPTIONS as e: return self.aws_error(e)`, docstring citing `API_GetFindingAggregator.html`. No new `ctx.get_client` binding
    - _Requirements: 8.1, 8.2_

  - [ ] 2.2 Add `list_configuration_policy_associations(self) -> Mapping[str, Any]`: paginator `list_configuration_policy_associations`, every page's `ConfigurationPolicyAssociationSummaries` merged into `{"ConfigurationPolicyAssociationSummaries": [...]}`, the whole loop inside the `try`, same handler, docstring citing `API_ListConfigurationPolicyAssociations.html` and `API_ConfigurationPolicyAssociationSummary.html`
    - _Requirements: 8.1, 8.2_

  - [ ] 2.3 Run `cd sraverify && uv run pytest -q -p no:logging tests/property/test_client_contract_property.py 2>&1 | tail -5`. Expected: the AST rules pass; `test_the_adapter_table_is_complete_and_exact[securityhub]` fails naming the two unlisted methods. That failure is the prescriptive table working and is cleared in task 6.1
    - _Requirements: 10.1_

- [ ] 3. `services/securityhub/base.py` — constants, accessors, helpers
  - [ ] 3.1 Add the module constants beside `V2_FINDINGS_DETAIL_TYPE`: `CSPM_FINDINGS_DETAIL_TYPE = "Security Hub Findings - Imported"` (cite `securityhub-cwe-integration-types.html`) and `SELF_MANAGED_POLICY_ID = "SELF_MANAGED_SECURITY_HUB"` (cite `API_StartConfigurationPolicyAssociation.html`)
    - _Requirements: 8.4_

  - [ ] 3.2 Add the accessor `get_finding_aggregator(self, region, aggregator_arn)` → `self._cached_call(region, f"finding_aggregator:{region}:{aggregator_arn}", "get_finding_aggregator", aggregator_arn)`, placed after `get_finding_aggregators`
    - _Requirements: 8.3_

  - [ ] 3.3 Add the accessor `get_configuration_policy_associations(self, region)` → `self._cached_call(region, f"configuration_policy_associations:{region}", "list_configuration_policy_associations")`, placed after `get_configuration_policy`
    - _Requirements: 8.3_

  - [ ] 3.4 Add the three `@staticmethod` helpers from `design.md`: `cspm_unlinked_regions(aggregator, regions)` beside `unlinked_regions` (CSPM field names `FindingAggregationRegion` / `Regions`, modes `ALL_REGIONS`, `ALL_REGIONS_EXCEPT_SPECIFIED`, `SPECIFIED_REGIONS`, `NO_REGIONS`; unrecognized mode links nothing; result sorted); `association_of(summaries, account_id)` (first `TargetType == "ACCOUNT"` and `TargetId == account_id`, else `None`); `matches_cspm_findings(rule)` beside `matches_v2_findings` (valid-JSON dict, `aws.securityhub` in `source`, then `detail-type` absent → `True`, else `CSPM_FINDINGS_DETAIL_TYPE in detail-type`)
    - _Requirements: 8.4_

  - [ ] 3.5 Decide entries A and B **now, from the task 1.5 probe output** (probe answers 3 and 4). For each entry whose exact code and needle were observed: add the entry to `NOT_CONFIGURED_ERRORS` as written in `design.md` § `NOT_CONFIGURED_ERRORS`, filling in the observation date, account role and Region in the `evidence`; add the golden row `('SecurityHubCheck', <op>, <code>, <needle>, hashlib.sha256(evidence.encode()).hexdigest())` with `# pragma: allowlist secret` to `_NON_OWNED_NOT_CONFIGURED_ENTRIES` in `tests/property/test_discriminator_property.py` **in sorted `(base, operation, code, needle)` position** — `_live_non_owned_entries()` sorts by that tuple and the test compares the two sequences element-wise, so entry A (`ListFindingAggregators`) goes between the `ListEnabledProductsForImport` and `ListMembers` rows and entry B (`ListConfigurationPolicyAssociations`) between `ListConfigurationPolicies` and `ListEnabledProductsForImport`; and bump `assert len(_NON_OWNED_NOT_CONFIGURED_ENTRIES) == 46` (line 671) by one per entry added. For each entry **not** observed: leave it out, and add a comment above the table's `ListConfigurationPolicies` entry naming the candidate, the probe date and "not observed", so a reader of the table knows it was considered. Nothing is declared on inference
    - _Requirements: 9.1, 9.2, 9.3, 9.4_

  - [ ] 3.6 Run `cd sraverify && uv run pytest -q -p no:logging tests/property/test_accessor_cache_property.py tests/property/test_layering_property.py tests/property/test_discriminator_property.py 2>&1 | tail -5`. Expected: layering passes; discriminator passes (with the golden and its length assertion updated in 3.5 if an entry landed); `test_every_public_base_method_is_classified[securityhub]` fails naming the five new public methods, cleared in task 6.2
    - _Requirements: 10.2_

- [ ] 4. The soft split — twenty one-line edits
  - [ ] 4.1 In `services/securityhub/checks/sra_securityhub_01.py` through `_13.py`, change `service="SecurityHub",` to `service="Security Hub CSPM",`. One line per file, nothing else
    - _Requirements: 1.1, 1.2, 1.6_

  - [ ] 4.2 In `sra_securityhub_14.py` through `_20.py`, change `service="SecurityHub",` to `service="Security Hub",`
    - _Requirements: 1.1, 1.2, 1.6_

  - [ ] 4.3 Confirm the split is visible and complete: `sraverify/.venv/bin/sraverify --list-services` lists `Security Hub` and `Security Hub CSPM` and not `SecurityHub`; `sraverify/.venv/bin/sraverify --list-checks | grep -c "(Security Hub CSPM)"` → 13 (18 after task 5); `grep -c "(Security Hub)"` → 7; `grep -rn '"SecurityHub"' sraverify/sraverify/services/securityhub/checks/` → nothing
    - _Requirements: 1.3, 1.5_

  - [ ] 4.4 Confirm the old value is a loud failure: `sraverify/.venv/bin/sraverify --service SecurityHub --regions us-east-1 --profile <audit profile>; echo $?` → `2`, one ERROR line, no file created (`ls sraverify_findings_*.csv` unchanged). No AWS call is made before exit 2, so this needs no live account beyond a configured profile
    - _Requirements: 1.4_

- [ ] 5. The five check modules
  - [ ] 5.1 `services/securityhub/checks/sra_securityhub_21.py` — `SRA_SECURITYHUB_21`, every `CheckMeta` field as `design.md` § SRA-SECURITYHUB-21 tabulates, `execute()` as its flow listing: `get_finding_aggregators(self.regions[0])` → two-arm error branch (the `is_not_configured` FAIL wording claims only that `{probe_region}` cannot be linked, not that no aggregator exists) → `home_region_of` → no-aggregator FAIL (`global`) → not-scanned ERROR (`global`, names `--regions`) → `get_finding_aggregator(home_region, arn)` → one-arm ERROR → `cspm_unlinked_regions` → PASS or FAIL labelled `home_region`. `checked_value` on every call
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6_

  - [ ] 5.2 `sra_securityhub_22.py` — `SRA_SECURITYHUB_22`. Precondition: task 1.5 probe answer 2 confirmed inherited accounts are listed as their own `ACCOUNT` summaries (otherwise the fallback design must already be in `design.md`, and this task implements that instead). Order of calls is load-bearing: `get_finding_aggregators` **first**, then `get_configuration_policy_associations(home_region)`, then `self.organization.accounts()` (exactly one occurrence of that literal in the file), then one row per active account (sorted by ID, `is_active_account` filter, DA and management account included) with the three FAIL wordings and the PASS. Before the loop, read `self.organization.management_account_id()` once (`is_error` → no hint) and append the enable-CSPM-first sentence from `design.md` § SRA-SECURITYHUB-22 to the management account's no-association and FAILED remediations; the verdict must not depend on that lookup. Import `is_active_account` from `sraverify.core.accounts`, `is_error` from `sraverify.core.aws_errors`, and `SELF_MANAGED_POLICY_ID` from the base module
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8_

  - [ ] 5.3 `sra_securityhub_23.py` — `SRA_SECURITYHUB_23`. Copy `sra_securityhub_12.py`; rename the class and ID; replace `AI_STANDARD_SUFFIX` with `FSBP_STANDARD_SUFFIX = "standards/aws-foundational-security-best-practices/v/1.0.0"`; replace the metadata with the `-23` table; replace the `checked_value` and every "AI Security Best Practices" phrase in row text. Keep the `READY` / transient / settled logic and `standard_name_of` listing untouched
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_

  - [ ] 5.4 `sra_securityhub_24.py` — `SRA_SECURITYHUB_24`. From `-23`: `CIS_STANDARD_MARKER = "cis-aws-foundations-benchmark/v/"` matched with `in`; filter the subscriptions to the CIS ones; empty → FAIL; any `READY` → PASS naming every CIS version and status; else FAIL with transient wording only if every CIS subscription is `PENDING`/`DELETING`. Metadata from the `-24` table
    - _Requirements: 6.1, 6.2, 6.3, 6.4_

  - [ ] 5.5 `sra_securityhub_25.py` — `SRA_SECURITYHUB_25`. Copy `sra_securityhub_20.py`; substitute `get_finding_aggregators` / `home_region_of` for `get_aggregators_v2` / `aggregation_region_of`, `matches_cspm_findings` for `matches_v2_findings`, `CSPM_FINDINGS_DETAIL_TYPE` for `V2_FINDINGS_DETAIL_TYPE`; keep `_evaluate_region`'s structure (first ENABLED matching rule with a target PASSes and returns; an ERROR if any candidate's targets call failed and none passed; else one FAIL with the three-way detail). Metadata from the `-25` table
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

  - [ ] 5.6 Validate the five declarations offline: `sraverify/.venv/bin/sraverify --list-checks | grep -c "SRA-SECURITYHUB-2[1-5]"` → 5, with an empty stderr. A `MetadataError` or `CheckIdentityError` here is a declaration defect; fix it before continuing
    - _Requirements: 1.2, 10.7_

  - [ ] 5.7 Self-check each module against the steering rules before running the suite: no `__init__`, no `initialize`, no `_ctx` / `_has` / `_get` / `_set`, no `NOT_CONFIGURED_ERRORS`, no `hasattr`/`getattr` on account lists, no inline error-code compare, every ERROR `actual_value` is `f"{error['Operation']} failed: {error['Code']}: {error['Message']}"` with `remediation=self._remediation_for(error)`, every `passed()` has no `remediation=`, titles' first token is not `Ensure`/`Check`, multi-line strings use parenthesized concatenation. `grep -n "def __init__\|_audit_accounts\|_log_archive_accounts\|hasattr\|getattr\|_ctx\." services/securityhub/checks/sra_securityhub_2*.py` → nothing
    - _Requirements: 8.6, 9.5, 9.6_

- [ ] 6. Adapter rows, goldens and counts
  - [ ] 6.1 `tests/property/test_client_contract_property.py`, `securityhub` `ClientAdapter` table: add `get_finding_aggregator` (`boto_service="securityhub"`, `boto_method="get_finding_aggregator"`, `operation="GetFindingAggregator"`, `args=(f"arn:aws:securityhub:us-east-1:{_TEST_ACCOUNT}:finding-aggregator/abc",)`, `success={"FindingAggregationRegion": "us-east-1", "FindingAggregatorArn": <same ARN>, "RegionLinkingMode": "ALL_REGIONS", "Regions": []}`) and `list_configuration_policy_associations` (`operation="ListConfigurationPolicyAssociations"`, `paginated=True`, `success=({"ConfigurationPolicyAssociationSummaries": [{"TargetId": _TEST_ACCOUNT, "TargetType": "ACCOUNT", "ConfigurationPolicyId": "abc", "AssociationType": "INHERITED", "AssociationStatus": "SUCCESS"}]},)`). The module holds no literal method count; the 96 → 98 figure is updated in steering (task 10.2)
    - _Requirements: 10.1_

  - [ ] 6.2 `tests/property/test_accessor_cache_property.py`, `securityhub` table: two `accessor` rows (`get_finding_aggregator`, `args=(_TEST_REGION, "<arn>")`, `client_method="get_finding_aggregator"`, `cache_key=f"finding_aggregator:{_TEST_REGION}:<arn>"`; `get_configuration_policy_associations`, `args=(_TEST_REGION,)`, `client_method="list_configuration_policy_associations"`, `cache_key=f"configuration_policy_associations:{_TEST_REGION}"`) and three `helper` rows (`cspm_unlinked_regions`, `association_of`, `matches_cspm_findings`) with the representative `args` from `design.md` § Testing strategy
    - _Requirements: 10.2_

  - [ ] 6.3 `tests/property/test_catalog_identity_property.py` and `tests/property/test_registry_bijection_property.py`: `EXPECTED_CHECK_COUNT = 187`
    - _Requirements: 10.3_

  - [ ] 6.4 `tests/property/test_layering_property.py`: add `"securityhub/checks/sra_securityhub_22.py"` to `_CONSUMERS` in sorted position; change `assert len(_CONSUMERS) == 15` to `16`; rename `test_there_are_exactly_fifteen_consumers` to `test_there_are_exactly_sixteen_consumers` and update its docstring and the module docstring's "fifteen"
    - _Requirements: 4.7, 10.4_

  - [ ] 6.5 Add `tests/unit/services/test_securityhub_cspm_helpers.py`: table-driven tests for `cspm_unlinked_regions` (each of the four modes, absent `Regions`, unknown mode, home Region always covered), `association_of` (match, OU entry ignored, absent), `matches_cspm_findings` (detail-type match, source-only, `detail`-only, V2-only → `False`, Custom-Action-only → `False`, invalid JSON → `False`), and `standard_name_of` on the v1.2.0 `ruleset/` ARN (returns the whole ARN). Pure functions, no mocks
    - _Requirements: 3.5, 4.4, 6.3, 7.4_

  - [ ] 6.6 Run the full suite: `cd sraverify && uv run pytest -q -p no:logging 2>&1 | tail -3 > ../.tmp/sratester/securityhub-cspm-split/after-pytest.txt`. Expected: 0 failed; passed count up by the five checks' catalog-wide parametrizations, the two client rows × four drives, the five accessor rows, and the helper tests; skipped count up by the five checks' unreachable declared pairs. Record both totals for task 10.2
    - _Requirements: 10.8_

- [ ] 7. Verify each check with the CLI
  - [ ] 7.1 For each of `SRA-SECURITYHUB-21` … `-25`: `sraverify/.venv/bin/sraverify --check SRA-SECURITYHUB-2N --account-type <audit|application> --regions <scanned Regions incl. the home Region> --profile <audit profile> --output .tmp/sratester/securityhub-cspm-split/check-2N.csv --debug 2> .tmp/sratester/securityhub-cspm-split/check-2N.stderr`. Apply the scan gates: 0 synthetic rows, 0 `- ERROR -` records, no `No client available`, every ERROR row explained, `grep -c aws_call_failed` plausible
    - _Requirements: 12.9_

  - [ ] 7.2 Read every row's `ActualValue` and ask why it PASSed or FAILed, per `testing_checks.md`'s "a baseline PASS can be the defect". For `-22` confirm the row count equals the active account count and that the DA and management account each have a row. For `-25` read the matching rule's `EventPattern` and confirm it is a CSPM pattern, not a bare-source pattern passing by accident
    - _Requirements: 4.3, 7.4_

- [ ] 8. IAM
  - [ ] 8.1 Regenerate: `cd sraverify && uv run python ../util/generate_iam_policy.py --base-dir . --out-json ../generated_sraverify_iam_policy.json --out-yaml ../generated_sraverify_cf_policy.yaml`. Expected stderr: empty. `diff` against the task 1.3 copies: exactly `securityhub:GetFindingAggregator` and `securityhub:ListConfigurationPolicyAssociations` added
    - _Requirements: 10.6_

  - [ ] 8.2 Add the two actions to `SRAVerifyLeastPrivilege` in `1-sraverify-member-roles.yaml`, in sorted position within the `securityhub:` block (after `securityhub:GetEnabledStandards` and after `securityhub:ListConfigurationPolicies` respectively). `aws cloudformation validate-template --template-body file://1-sraverify-member-roles.yaml --profile <management profile>`
    - _Requirements: 10.6_

- [ ] 9. `docs/checks.txt` and `docs/check-report.md`
  - [ ] 9.1 `sraverify/.venv/bin/sraverify --list-checks > docs/checks.txt 2> .tmp/sratester/securityhub-cspm-split/list-checks.stderr`; stderr must be 0 bytes; `sraverify/.venv/bin/sraverify --list-checks | cmp - docs/checks.txt`. Diff against task 1.3's copy: 20 changed lines (the `(Service)` token) and 5 added
    - _Requirements: 10.7_

  - [ ] 9.2 `docs/check-report.md`: header count 187; CSPM table items 6 → `SRA-SECURITYHUB-22` Covered, 9 → `-21` Covered, 11 → `SRA-SECURITYHUB-01, -23` Covered, 12 → `-01, -24` Covered, 16 → `-25` Covered; items 4, 10, 13, 14, 15, 17 unchanged with a note "not added — see `.kiro/specs/securityhub-cspm-split`"; CSPM summary row **17 / 11 / 3 / 3** (Covered: items 1, 2, 3, 5, 6, 7, 8, 9, 11, 12, 16; Partial: 4, 10, 13; Missing: 14, 15, 17 — count them from the table, do not compute by delta); total row recomputed by summing the per-service rows (224 / 124 / 13 / 87 if no other row changed); the "Check source" bullet names the five
    - _Requirements: 11.3, 13.2_

- [ ] 10. Steering and READMEs
  - [ ] 10.1 `product.md`: "187 checks across 18 AWS services", `securityhub 25`; add a scope bullet stating the soft split (two display names, one package, `--service` selects either) and listing `-21` – `-25` with one clause each
    - _Requirements: 11.1, 11.2_

  - [ ] 10.2 `structure.md` and `tech.md`: every `182` → `187`, `96` client methods → `98` (and "86 across the 17 service clients" → `88`), the pytest totals from task 6.6, and `--service "Security Hub CSPM"` added to the CLI examples. `creating_checks_best_practices.md`: the two `182` mentions
    - _Requirements: 11.1_

  - [ ] 10.3 `README.md` line 5: the service list names "Security Hub CSPM" and "Security Hub" in place of "Security Hub", and "158 automated security checks" becomes "187". Leave the `--service CloudTrail` example at line 231 alone; it does not break. `sraverify/README.md`: one paragraph that two display names may coexist in one package and that `meta.service` is the `--service` boundary; the test-count line
    - _Requirements: 11.4, 11.5_

- [ ] 11. Security scan
  - [ ] 11.1 `uv tool run --from automated-security-helper==3.7.0 ash --source-dir . --mode local`; read `.ash/ash_output/reports/ash.summary.md`. Every enabled scanner PASSED, none ERROR or MISSING. If `detect-secrets` flags a new sha256 in the discriminator golden (task 3.5, if an entry landed), use `# pragma: allowlist secret -- sha256 of public evidence text, not a credential` on that line as the existing rows do
    - _Requirements: 10.9_

- [ ] 12. Live validation (`testing_checks.md`), then the report
  - [ ] 12.1 **Re-run the probe.** Run task 1.5's `probe.sh` again unchanged, to `probe-recheck.txt`, and diff the five answers against `probe.txt`. Expected: identical. If anything moved (an entry now observable that was not, or the reverse; the `ACCOUNT` summary count changed), go back to task 3.5 / 5.2, then re-run the suite (task 6.6) and the ASH scan (task 11.1) before continuing
    - _Requirements: 12.1_

  - [ ] 12.2 **Read-only negatives.** `--regions` without the home Region for `-21`, `-22`, `-25` → ERROR naming it; `--check SRA-SECURITYHUB-23` and `-24` with a Region where CSPM is not subscribed → FAIL "not enabled". Run `--account-type audit --check SRA-SECURITYHUB-22` with the management profile and record the row it actually produces: if probe answer 5 was "empty list", expect the no-aggregator FAIL (`global`, "so central configuration is not in use") and note that `ListConfigurationPolicyAssociations` was never issued (confirm from the `--debug` stderr: no `aws_call_failed operation=ListConfigurationPolicyAssociations`); if the management account listed an aggregator, expect the `ListConfigurationPolicyAssociations` ERROR (or FAIL, if entry B landed). Pre-mark the `ListConfigurationPolicyAssociations` ERROR arm 🔄 ATTEMPTED in the status table if the first case holds, with the reason "no account in the test org owns a finding aggregator without being the DA". Keep each CSV and stderr
    - _Requirements: 12.2_

  - [ ] 12.3 **Snapshot** to `.tmp/sratester/securityhub-cspm-split/snapshot.json`: the chosen application account's association summary from `list-configuration-policy-associations` in the home Region with the audit profile — `ConfigurationPolicyId`, `TargetId`, `TargetType`, **`AssociationType`**, `AssociationStatus`, and `UpdatedAt` for the record; the matching EventBridge rule's `describe-rule` and `list-targets-by-rule`; and, if `-21` will be mutated, `get-finding-aggregator`. The snapshotted `AssociationType` chooses the `-22` restore in 12.4
    - _Requirements: 12.3, 12.4, 12.5_

  - [ ] 12.4 **Five phases, one script per check, strictly sequential per check.** `-22`: baseline → `start-configuration-policy-association --configuration-policy-identifier SELF_MANAGED_SECURITY_HUB --target AccountId=<app account> --region <home>` → poll `get-configuration-policy-association --target AccountId=<app account>` until not PENDING, saying how long → re-scan: that account's row FAIL "self-managed (APPLIED, SUCCESS)", all other rows unchanged → **restore by the snapshotted `AssociationType`**: if `INHERITED`, `start-configuration-policy-disassociation --configuration-policy-identifier SELF_MANAGED_SECURITY_HUB --target AccountId=<app account> --region <home>` (the account resumes inheriting from its closest parent; `API_StartConfigurationPolicyDisassociation.html`); if `APPLIED`, `start-configuration-policy-association --configuration-policy-identifier <snapshotted policy ARN> --target AccountId=<app account> --region <home>` → poll until `AssociationStatus=SUCCESS` **and** `AssociationType` and `ConfigurationPolicyId` equal the snapshot → re-scan PASS with the `ActualValue` showing the snapshotted kind. Do not re-associate the parent's policy to an INHERITED account: that leaves it `APPLIED`, moves the `ActualValue` cell, and detaches the account from future root/OU policy changes. `-25`: baseline → pick the rule to disable: a matching rule that is not named `aws-controltower-*` and that `describe-rule` reports without `ManagedBy` and `list-tags-for-resource` reports without an `aws:cloudformation:stack-name` tag; if every matching rule is managed, or the baseline is FAIL, use `put-rule`+`put-targets` with `sraverify-test-cspm` instead → `disable-rule` (or the temporary rule) → re-scan → `enable-rule` (or `remove-targets`+`delete-rule`) → re-scan. Never disable a Control Tower or stack-owned rule (`testing_checks.md` § Do not mutate). `-21`: prefer the read-only FAIL (a scanned Region the aggregator does not link); if none exists and the owner signs off, `update-finding-aggregator --region-linking-mode SPECIFIED_REGIONS --regions <linked minus one>` → re-scan → run the row's recommended `ALL_REGIONS` CLI as the Phase 4 fix → restore the snapshotted mode and list → re-scan; otherwise mark 🔄 with the central-configuration-scope reason. `-23`, `-24`: baseline PASS plus the not-subscribed FAIL from 12.2 are both verdicts; mark the standard-absent arm 🔄 (centrally-managed accounts refuse `BatchDisableStandards`; an org-wide policy edit is out of scope)
    - _Requirements: 12.3, 12.4, 12.5, 12.6, 12.7_

  - [ ] 12.5 **Restoration proof.** `.tmp/sratester/securityhub-cspm-split/verify-restore.py` re-reads every snapshotted resource and compares it **field by field** against `snapshot.json`: for the `-22` account, `ConfigurationPolicyId`, `TargetId`, `TargetType`, `AssociationType`, `AssociationStatus` must be equal and `UpdatedAt` is excluded (it changes on every correct restore, so a raw `cmp` would fail for the wrong reason); for the `-25` rule, `State`, `EventPattern` and the sorted target list; for `-21`, if mutated, `RegionLinkingMode` and sorted `Regions`. Print one `OK`/`DIFF` line per field and exit non-zero on any `DIFF`. Include its output verbatim in the report
    - _Requirements: 12.3, 12.4, 12.5, 12.10_

  - [ ] 12.6 **IAM.** `aws iam simulate-principal-policy --policy-source-arn <SRAMemberRole ARN> --action-names securityhub:GetFindingAggregator securityhub:ListConfigurationPolicyAssociations` → both `allowed` after deploy; `simulate-custom-policy` against the edited `SRAVerifyLeastPrivilege` statement. Deploy `1-sraverify-member-roles.yaml` as the StackSet and as the management-account stack, and wait for propagation before 12.7
    - _Requirements: 12.8_

  - [ ] 12.7 **CodeBuild end to end.** Tar `sraverify/` and `sra-verify-dashboard.html` (exclude `.venv`, `build`, `dist`, `*.egg-info`, `__pycache__`, `.hypothesis`), upload to the findings bucket, start one build with a `buildspecOverride` whose only change replaces the `git clone -b $GIT_BRANCH …` line with the tarball copy, then delete the tarball. From the consolidated CSV: `-21`, `-25` one row per audit account; `-22` one per active account; `-23`, `-24` one per account per Region; zero ERROR rows from the five; total ERROR delta explainable by the new rows. Then the Requirement 2 diff: join the previous consolidated report to this one on (`CheckId`, `AccountId`, `Region`, `ResourceId`), normalize `Service` on Security Hub rows, and count rows whose other cells differ (expected 0; ERROR-row `Remediation` wording from `_remediation_for` is the one admitted difference and must be listed)
    - _Requirements: 2.6, 12.8_

  - [ ] 12.8 **Report.** Write `sratester/securityhub-cspm-split-test-report.md`: a status table per check (✅ / 🔄 / ❌ with reason), the phase table per check with the exact mutation and observed row text, the gate results per scan, the probe findings and the entry A / entry B decision, IAM simulation output, the CodeBuild comparison and Requirement 2 diff, defects found and fixed, and the restoration verification output. Reference raw files by path under `.tmp/sratester/securityhub-cspm-split/`
    - _Requirements: 12.10_

- [ ] 13. Hand-off
  - [ ] 13.1 Re-run `git status --short` and confirm the changed set is: `services/securityhub/base.py`, `client.py`, the 20 edited and 5 new check modules, the test modules edited or added in tasks 3.5 and 6 (five property modules edited, `tests/unit/services/test_securityhub_cspm_helpers.py` added, and `test_discriminator_property.py` only if an entry landed), `1-sraverify-member-roles.yaml`, the two `generated_*` files (gitignored; confirm they do not appear), `docs/checks.txt`, `docs/check-report.md`, the four steering files, the two READMEs, and `.kiro/specs/securityhub-cspm-split/`. Nothing under `sratester/` or `.tmp/` appears
    - _Requirements: 2.1_

  - [ ] 13.2 Propose the one-line commit message to the owner; do not commit. Suggested: `Split Security Hub CSPM from Security Hub by display name and add SRA-SECURITYHUB-21..25`
    - _Requirements: —_

## Notes

- **Why `-22` calls `get_finding_aggregators` before `accounts()`.** `test_a_declared_semantic_error_result_reaches_failed` drives every accessor with one error result and judges a declared pair only when the check's *first* accessor issues that operation. With `ListFindingAggregators` first (undeclared today), every pair is skipped for `-22` and no `_PROVIDER_PAIRS_WITHOUT_FAIL_ARM` edit is needed. If entry A lands in task 3.5, the harness then observes `-21`, `-22` and `-25` reaching their FAIL arm for it, which is the behaviour wanted.
- **The same call order is why the management-profile run of `-22` does not reach the `ListConfigurationPolicyAssociations` arm** unless the management account lists an aggregator (probe answer 5). From an account with no aggregator the check resolves at the no-aggregator FAIL. Entry B is therefore observed from the raw CLI in task 1.5, never from the check.
- **If entry A lands, `SRA-SECURITYHUB-13` gains a reachable FAIL arm** it already has in code (its `is_not_configured` branch on `get_finding_aggregators`). In an organization whose audit account is not subscribed in `regions[0]`, that row moves ERROR → FAIL. The test organization's audit account is subscribed, so the live gate is expected to show no such row; say so in the report.
- **`standard_name_of` and the v1.2.0 CIS ARN.** `arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0` has no `standards/` segment, so the helper returns it whole. That is accurate; do not special-case it.
- **Severity of `-24` is MEDIUM**, below `-23`'s HIGH, because the SRA lists CIS after FSBP and many organizations adopt one baseline. If the owner wants parity, it is a one-token change before the first live run; after it, it moves a `Severity` cell.
