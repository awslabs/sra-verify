# Implementation Plan: SIR log-readiness checks

Implements `design.md` (approved) against `requirements.md`. Order follows
`structure.md` "Adding a new check": research → package scaffolding → client →
base → checks → counts → IAM → `docs/checks.txt` → full suite → ASH → template
validation. Live validation and the MR follow in their own tasks.

Conventions for every task:

- Worktree root `W=/Users/schiefj/code/wwps-security-developer/sraverify/sra-verify/.worktrees/sir-log-readiness-checks`.
  Absolute paths only; never touch the main checkout. Package paths below are
  relative to `$W/sraverify/sraverify/` unless they start with `$W`.
- Test command: `cd $W/sraverify && uv run pytest -q --tb=line -p no:logging > $W/.tmp/pytest-<task>.txt 2>&1`
  then read the file (the shell tool often returns empty output). Branch baseline:
  10080 passed, 1239 skipped.
- Every task ends with the suite at zero failures. Where adding a file breaks a
  count literal, the literal is fixed in the same task.
- Line numbers quoted from `design.md` are against the base tree; locate by text, not by number.

---

- [x] 1. Confirm research inputs and record the three unfetched doc pages. (Req 6.1, 8.1)
      Research is done: `.agents/tasks/sir-log-readiness-checks/probe-findings.md` is authoritative.
      Re-read it, then confirm from the worktree venv's botocore that the four operations exist with
      the paginators the design uses: `ec2` `describe_vpcs`, `describe_flow_logs`; `route53resolver`
      `list_resolver_query_log_config_associations`; `events` `list_rules`
      (`client.can_paginate(...)` is `True` for each). Attempt to fetch the three doc URLs named in the
      design's "Evidence status of the live plan" and note the outcome in `$W/.tmp/sratester/doc-checks.md`.
      Files: `$W/.tmp/sratester/doc-checks.md` (scratch, untracked)
      Verify: a one-off `uv run python -c` script printing the four `can_paginate` results shows `True` ×4.

- [x] 2. Scaffold the `route53resolver` service package and fix the 18 → 19 service-count literals it breaks. (Req 5.1)
      Create `services/route53resolver/__init__.py` (docstring + `import_check_modules(f"{__name__}.checks")`,
      matching `services/ec2/__init__.py`), `services/route53resolver/checks/__init__.py` (docstring only),
      `client.py` with `Route53ResolverClient(AWSClient)` whose `__init__` chains `super().__init__(region, ctx)`
      and binds `self.client = ctx.get_client('route53resolver', region=region)` and
      `self.ec2_client = ctx.get_client('ec2', region=region)` (with the design's comment), and `base.py`
      with `Route53ResolverCheck(SecurityCheck)`: `NAMESPACE = "route53resolver"`,
      `NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {}` with the `UnrecognizedClientException`
      rationale comment (Req 5.10), `_setup_clients` (one wrapper per Region, regional shape from `services/ec2/base.py`)
      and `get_client(region)`. Add the `route53resolver` key to `ADAPTERS` in
      `tests/property/test_client_contract_property.py` (empty `_ROUTE53RESOLVER` tuple for now) and the
      `route53resolver` accessor table with `A("get_client", "client_lookup", args=(_TEST_REGION,))` in
      `tests/property/test_accessor_cache_property.py`. Rename and re-count the tests whose assertions now
      change: both `test_eighteen_services_are_discovered` → `test_nineteen_services_are_discovered`
      (`== 19`, message "expected 19 service packages"); `test_registry_bijection_property.py`
      `EXPECTED_SERVICE_COUNT = 19` and `test_exactly_eighteen_service_subpackages_are_discovered` →
      `test_exactly_nineteen_service_subpackages_are_discovered` (docstring "holds 19");
      `test_discriminator_property.py` `test_eighteen_services_declare_a_table_attribute` →
      `test_every_service_declares_a_table_attribute`; `tests/unit/util/test_generate_iam_policy.py`
      `len(modules) == 19`. If a completeness test rejects an empty client adapter table, move task 3's
      `_ROUTE53RESOLVER` rows (and the two client methods) into this task rather than adding an exemption.
      Files: `services/route53resolver/{__init__.py,client.py,base.py,checks/__init__.py}`,
      `tests/property/test_client_contract_property.py`, `tests/property/test_accessor_cache_property.py`,
      `tests/property/test_registry_bijection_property.py`, `tests/property/test_discriminator_property.py`,
      `tests/unit/util/test_generate_iam_policy.py`
      Verify: full pytest, zero failures; `$W/sraverify/.venv/bin/sraverify --list-services` lists `Route 53 Resolver`
      only after task 5 (no check yet), and `--list-checks` still exits 0 with 182 checks.

- [x] 3. Add the five raw client methods and their `ClientAdapter` rows. (Req 2.2, 4.2, 5.3, 6.2)
      `services/ec2/client.py`: `describe_vpcs()` → `{"Vpcs": [...]}` and `describe_flow_logs()` →
      `{"FlowLogs": [...]}` (no `Filter`, Req 4.3), each paginator loop wholly inside `try`,
      `except AWS_EXCEPTIONS as e: return self.aws_error(e)`, using the existing `self.client`.
      `services/route53resolver/client.py`: `list_resolver_query_log_config_associations()` →
      `{"ResolverQueryLogConfigAssociations": [...]}` via `self.client`, and `describe_vpcs()` via
      `self.ec2_client`, same shape. `services/securityincidentresponse/client.py`: add
      `self.events_client = ctx.get_client('events', region=region)` to `__init__` and
      `list_event_rules()` → `{"Rules": [...]}` via the `list_rules` paginator, no `EventBusName`
      (shape of `SecurityHubClient.list_event_rules`); module docstring "Four methods across two" →
      "Five methods across three". Add the adapter rows exactly as in the design: two in `_EC2`, one in
      `_SECURITYINCIDENTRESPONSE`, two in `_ROUTE53RESOLVER`, all `paginated=True`.
      Files: `services/ec2/client.py`, `services/route53resolver/client.py`,
      `services/securityincidentresponse/client.py`, `tests/property/test_client_contract_property.py`
      Verify: `uv run pytest -q -p no:logging sraverify/tests/property/test_client_contract_property.py` passes
      (101 targets), then full pytest zero failures.

- [x] 4. Add the cached base accessors, their `AccessorAdapter` rows, the dedicated SIR cache test, and the `NOT_CONFIGURED_ERRORS` evidence edits. (Req 1.5, 2.2, 2.8, 4.2, 4.10, 5.3, 5.10, 6.3)
      `services/ec2/base.py`: `get_vpcs(region)` (`vpcs:{region}`) and `get_flow_logs(region)`
      (`flow_logs:{region}`) in the `get_ebs_encryption_by_default` shape — cache under `NAMESPACE`,
      `no_client_result(service="EC2", region=region)` with no wrapper, never cache an error result;
      extend the empty-table comment with the design's DescribeVpcs/DescribeFlowLogs sentence (table stays `{}`).
      `services/route53resolver/base.py`: `get_vpcs(region)` and `get_query_log_config_associations(region)`
      (`query_log_config_associations:{region}`), same shape, `no_client_result(service="Route 53 Resolver", ...)`.
      `services/securityincidentresponse/base.py`: `get_event_rules(region)` caching under the module-level
      `_CACHE_NAMESPACE` with key `event_rules:{region}` via `self._sir_client(region).list_event_rules()`,
      returning an error result unchanged and uncached; append the probe sentence from the design to the
      existing `GetRole`/`NoSuchEntity` evidence (no new entry, no `ListRules` entry); update the module
      docstring and `_CACHE_NAMESPACE` comment with the design's replacement text. Do not add a `NAMESPACE`.
      Tests: in `test_accessor_cache_property.py` add two `accessor` rows for `ec2`, two for `route53resolver`,
      and the SIR `derived` row with `client_method="list_event_rules"` and `error_bearing=True` exactly as the
      design gives; add `test_securityincidentresponse_get_event_rules_never_caches_a_failure` (error returned
      unchanged and not cached; second call re-issues; success cached under
      `("securityincidentresponse", "event_rules:us-east-1")`; warm cache skips the client); rename
      `test_securityincidentresponse_discover_memberships_is_the_one_caching_site` →
      `test_securityincidentresponse_discover_memberships_caches_under_the_module_namespace` and update its
      docstring, the SIR adapter-table comment and the `test_securityincidentresponse_declares_no_namespace`
      docstring per the design. Recompute the `SecurityIncidentResponseCheck` sha256 in
      `_NON_OWNED_NOT_CONFIGURED_ENTRIES` (`test_discriminator_property.py`), keep its
      `# pragma: allowlist secret` comment, row count stays 46. Update the
      `test_check_classification_property.py` l.437–439 comment ("seven public methods … `get_event_rules`
      declares `client_method="list_event_rules"`").
      Files: `services/{ec2,route53resolver,securityincidentresponse}/base.py`,
      `tests/property/test_accessor_cache_property.py`, `tests/property/test_discriminator_property.py`,
      `tests/property/test_check_classification_property.py`
      Verify: `uv run pytest -q -p no:logging sraverify/tests/property/test_accessor_cache_property.py sraverify/tests/property/test_discriminator_property.py`
      passes, including `test_every_public_base_method_is_classified`; then full pytest zero failures.

- [x] 5. Write the five check modules and fix the 182 → 187 check-count literals. (Req 1.1–1.8, 2.1, 2.3–2.11, 3.1–3.11, 4.1, 4.3–4.12, 5.2, 5.4–5.13, 6.1, 6.4)
      Each module declares `meta = CheckMeta(...)` with the exact title, severity, account type, service,
      resource type, check_logic, remediation (text/cli/console), sra_sections and additional_urls from the
      design, has no `__init__`, no `except` inside `execute()`, reads every AWS field with `.get()` and type
      guards, sorts every listed value, and follows the normative snippets:
      - `services/securityincidentresponse/checks/sra_securityincidentresponse_06.py` — one `global` row; PASS with `Role.Arn`, FAIL/ERROR keyed on the expected SLR ARN; two-arm error branch.
      - `services/securityincidentresponse/checks/sra_securityincidentresponse_07.py` — per Region, `ResourceId` `events:<region>:<account_id>`; static `event_sources` (catches only `(TypeError, ValueError)`) and `rule_name`; identification by `ManagedBy` only; missing/disabled/PASS texts as designed; no availability lookup.
      - `services/cloudtrail/checks/sra_cloudtrail_15.py` — `usable` trail filter, one `global` row per usable org trail keyed by ARN, single `organization/<account_id>` FAIL when none, two-arm branches for `DescribeTrails` and `GetEventSelectors` (`continue` per trail); static `management_event_gap` with the stated precedence and reason order.
      - `services/ec2/checks/sra_ec2_02.py` — static `owned_vpcs`; Region-level `ec2:<region>:<account_id>` rows for VPC-listing error and no-owned-VPC PASS (no second call); one ERROR per owned VPC when `DescribeFlowLogs` fails; dynamic `create-flow-logs` FAIL remediation.
      - `services/route53resolver/checks/sra_route53resolver_01.py` — same structure with `route53resolver:<region>:<account_id>`, its own copy of `owned_vpcs`, association matching by `ResourceId`/`Status == "ACTIVE"` ignoring config ownership, dynamic `associate-resolver-query-log-config` remediation.
      Literals the new checks break: `EXPECTED_CHECK_COUNT = 187` in `test_registry_bijection_property.py`
      and `test_catalog_identity_property.py`.
      Files: the five check modules; `tests/property/test_registry_bijection_property.py`,
      `tests/property/test_catalog_identity_property.py`
      Verify: `$W/sraverify/.venv/bin/sraverify --list-checks > $W/.tmp/list-checks.txt` exits 0 and shows 187
      checks including the five IDs; full pytest zero failures (catalog-wide classification, confessing-fail,
      layering, discriminator suites cover the new modules).

- [x] 6. Add the per-arm unit test module. (Req 1.2–1.7, 2.3–2.11, 3.2–3.11, 4.3–4.12, 5.4–5.13, 6.5)
      Create `tests/unit/services/test_sir_log_readiness_checks.py` following
      `tests/unit/services/test_inspector_batching.py`: real `ScanContext(session=MagicMock(), regions=[...])`,
      `patch.object(ScanContext, "get_account_info", ...)`, accessors patched on the base class returning
      canned dicts or `error_result(...)`. Cover every case listed in the design's Testing Strategy for each
      check (including the malformed-shape cases, the precedence case, the split-selector texts, the RAM-shared
      VPC, the N-ERROR fan-out, the second accessor never called for a VPC-less Region), the remediation-command
      assertions (Req 1.7, 2.11, 3.11, 4.12, 5.13), the source-read assertion that neither SIR-07, ROUTE53RESOLVER-01
      nor either base references `service_available_in_region` (Req 2.9, 5.11), and the hypothesis properties for
      `event_sources` and `management_event_gap`.
      Files: `tests/unit/services/test_sir_log_readiness_checks.py`
      Verify: `uv run pytest -q -p no:logging sraverify/tests/unit/services/test_sir_log_readiness_checks.py` passes;
      full pytest zero failures and passed > 10080.

- [x] 7. Count sweep across test prose, READMEs and steering, then run the three closing grep gates. (Req 7.5)
      Apply every comment/docstring/message edit in the design's "Edited files" table not already done in tasks
      2–5: `test_client_contract_property.py` (all `92` → `101`, `18` → `19` client/service prose, l.1673 "17" → "18",
      target-set docstring/message "101 client methods across the 19 clients"), `test_aws_client.py` (three `92` → `101`),
      `test_registry_bijection_property.py` l.95/l.415, `test_catalog_identity_property.py` l.115,
      `test_select.py` l.75, `test_catalog_meta_property.py` l.758–759, `test_catalog_executable_property.py` l.105,
      `test_availability_property.py` l.122, `test_generate_iam_policy.py` l.257, `test_discriminator_property.py`
      l.113/l.116; `$W/README.md` l.5 and `$W/sraverify/README.md` l.10/234/617/1067/1078/1094.
      Leave `docs/check-report.md`, `test_service_migration_property.py` l.8/27, `test_check_classification_property.py`
      l.551 and standalone `158` drift untouched. Steering (`$W/.kiro/steering/`): `product.md` (187 / 19, re-sorted
      per-service list from the design, one new bullet for the five checks and their SIR config-validation origin),
      `structure.md` (182 → 187, 96/86/17 → 101/91/18, `tests/unit/services/` listing — it currently also holds
      `test_securityhub_organization.py`, so list all three files), `tech.md` (182/96 → 187/101, the three new actions
      under the deploy-member-role-first paragraph), `creating_checks_best_practices.md` (two 182 → 187). Test totals
      in steering are written in task 10 from the measured run.
      Files: the test modules and docs named above
      Verify: run the three gates from the design's "Closing gate for the count sweep" from `$W`, output to
      `$W/.tmp/count-gates.txt`: gate 1 returns exactly the three exempt lines, gates 2 and 3 return nothing;
      full pytest zero failures.

- [x] 8. Regenerate the IAM policy and add the three actions to `SRAVerifyLeastPrivilege`, under 6,144 characters. (Req 7.1, 7.2, 7.3)
      Run `cd $W/sraverify && uv run python ../util/generate_iam_policy.py --base-dir . 2> $W/.tmp/sratester/iam-generator.stderr`;
      assert stderr is empty and the generated JSON contains `ec2:DescribeVpcs`, `ec2:DescribeFlowLogs`,
      `route53resolver:ListResolverQueryLogConfigAssociations` (and `events:ListRules`, already granted). Edit
      `$W/1-sraverify-member-roles.yaml`: add `ec2:DescribeFlowLogs` and `ec2:DescribeVpcs` alphabetically to
      `Ec2Permissions`, and the `Route53resolverPermissions` statement between `OrganizationsPermissions` and
      `S3Permissions`, exactly as the design shows. No other action changes; `SRAVerifyCheckPermissions` untouched.
      Measure the edited `SRAVerifyLeastPrivilege` `PolicyDocument` minified with a scratch script
      (`yaml` load with a CFN-tag-tolerant loader, `json.dumps(doc, separators=(",", ":"))`) and assert
      `len < 6144`; record before/after (5,338 baseline) in `$W/.tmp/sratester/policy-size.txt`. If ≥ 6,144, stop and
      report: splitting the policy is a design change.
      Files: `$W/1-sraverify-member-roles.yaml` (generated_* outputs stay untracked)
      Verify: size script prints < 6144; `git -C $W diff --stat` (via `arch -arm64`) shows only the intended YAML lines.

- [x] 9. Regenerate `docs/checks.txt` from the worktree venv and `cmp` it. (Req 7.4)
      From `$W`: `sraverify/.venv/bin/sraverify --list-checks > docs/checks.txt`, then
      `sraverify/.venv/bin/sraverify --list-checks | cmp - docs/checks.txt`, the 187-row `grep -cE` assertion and the
      five-ID grep from the design.
      Files: `$W/docs/checks.txt`
      Verify: `cmp` exits 0, count is 187, five-ID grep returns 5.

- [x] 10. Full suite and measured test totals in steering. (Req 6.4, 6.6, 7.5)
      Run the full pytest; record passed/skipped/collected. Write the measured totals and the new skip count (with the
      "for every one of the 187 checks" explanation) into `tech.md` and `structure.md` wherever they state
      10081/1238/11319 or similar.
      Files: `$W/.kiro/steering/tech.md`, `$W/.kiro/steering/structure.md`
      Verify: `uv run pytest -q --tb=line -p no:logging` reports 0 failed and passed > 10080; the numbers in steering
      equal the run's numbers.

- [x] 11. ASH scan clean. (Req 8.7)
      From `$W`: `uv tool run --from automated-security-helper==3.7.0 ash --source-dir . --mode local`
      (version must match the `.ash.yaml` header). Fix any finding in code; suppress only confirmed false positives,
      one line or resource each, with the reason inline.
      Files: any file a finding points to
      Verify: `$W/.ash/ash_output/reports/ash.summary.md` shows every enabled scanner PASSED, none ERROR/MISSING,
      only the deliberately disabled scanners SKIPPED.

- [x] 12. Template validation and IAM simulation of the edited policy. (Req 7.3)
      `aws cloudformation validate-template --template-body file://$W/1-sraverify-member-roles.yaml` with a profile from
      `sratester/accounts.md` (main checkout path in the brief). Extract the `SRAVerifyLeastPrivilege` document to
      `$W/.tmp/sratester/least-privilege.json` and run `aws iam simulate-custom-policy` for the three new actions
      (plus `events:ListRules` and `iam:GetRole` as controls). Save outputs under `$W/.tmp/sratester/`.
      On mwinit/expired-credential errors, pause with `send_message` severity `warning`.
      Verify: `validate-template` succeeds; every simulated action `EvalDecision` is `allowed`.

- [ ] 13. Live validation per `testing_checks.md` and the design's per-check sequences. (Req 1.7, 4.12, 5.13, 8.1–8.6)
      Probe re-run read-only, read-only negative runs, snapshot to `$W/.tmp/sratester/snapshot.json`, then each check's
      sequence from the design strictly sequentially in one script per check: SIR-06 (log-archive FAIL → SLR create → PASS → delete
      and poll), SIR-07 (codeprod PASS, management FAIL, disabled-rule arm attempted), CLOUDTRAIL-15 (read-only arms; the
      organization-trail arm only after `send_message` severity `warning` sign-off, else 🔄), EC2-02 and
      ROUTE53RESOLVER-01 (temporary S3 destinations with the stated fallbacks). Every scan with `--debug`, stderr kept, gates
      applied (0 synthetic rows, 0 `- ERROR -` records, every ERROR explained, `aws_call_failed` counted). Deploy
      `1-sraverify-member-roles.yaml` (StackSet + management stack — pause for sign-off if `accounts.md` does not cover it),
      `simulate-principal-policy` on `SRAMemberRole`, then one CodeBuild run with a `buildspecOverride` tarball
      (`sraverify/` + `sra-verify-dashboard.html`, excluding `.venv`, `build`, `dist`, `*.egg-info`, `__pycache__`,
      `.hypothesis`; tarball deleted after) and compare the consolidated CSV. Run the restoration-verification script.
      Any defect found: fix, re-run full pytest, re-test the affected check from Phase 1.
      Files: scratch under `$W/.tmp/sratester/`; report at
      `/Users/schiefj/code/wwps-security-developer/sraverify/sra-verify/sratester/sir-log-readiness-checks-test-report.md`
      Verify: report has the per-check status table (✅/🔄/❌), phase tables with observed row text, gate results, IAM
      simulation, CodeBuild comparison with 0 ERROR rows from the five checks, defects, and restoration output showing every
      resource identical.

- [ ] 14. Commit, push and open the GitLab merge request. (Req 8.8)
      After tasks 10–11 are green on the final tree (re-run both if task 13 changed code), stage specific files only: the new
      and edited package and test files, `1-sraverify-member-roles.yaml`, `docs/checks.txt`, `README.md`,
      `sraverify/README.md`, `.kiro/steering/*` edits, `.kiro/specs/sir-log-readiness-checks/*` (including `.config.kiro`
      and this file); never `sratester/`, `.tmp/`, `.ash/`, `generated_*`, `.worktrees/`, `.agents/`. Commit with a one-line
      message, `arch -arm64 git push -u origin feature/sir-log-readiness-checks` (origin = gitlab.aws.dev, never github), then
      `glab mr create` targeting `main`, title < 70 chars, description covering checks added, checks dropped with reasons,
      spec path, live-test summary, IAM changes with "deploy 1-sraverify-member-roles.yaml before CodeBuild", and every 🔄 item.
      Do not merge.
      Verify: `glab mr view` shows the MR open against `main` from `feature/sir-log-readiness-checks`; `git status` shows no
      staged scratch files.
