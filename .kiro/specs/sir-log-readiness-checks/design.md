# Design Document: SIR log-readiness checks

## Overview

This change adds five read-only checks that turn the automatable steps of the AWS Security Incident Response configuration-validation procedure (<https://docs.aws.amazon.com/security-ir/latest/userguide/config-validation.md>) into SRA Verify controls: `SRA-SECURITYINCIDENTRESPONSE-06` (SIR service linked role in the audit account), `SRA-SECURITYINCIDENTRESPONSE-07` (SIR proactive-response EventBridge rules, per Region), `SRA-CLOUDTRAIL-15` (organization trail logs all management events), `SRA-EC2-02` (every owned VPC has an active VPC-level flow log) and `SRA-ROUTE53RESOLVER-01` (every owned VPC has an active Resolver query logging association). The last introduces a nineteenth service package, `services/route53resolver/`. The catalog moves from 182 checks across 18 services to 187 across 19, and the client-method count from 96 to 101.

Nothing in the framework changes. Every addition fits the existing three tiers — a client method that returns a success dict or an error result, a cached base accessor that never caches a failure, and a check that yields `passed()` / `failed()` / `error()` — and is registered by the file's presence on disk. No existing check's rows move. The technology stack is the existing one and is locked: Python ≥ 3.11, boto3/botocore (`boto3>=1.43.96` floor already covers every operation used here; the four operations exist in far older botocore), pytest + hypothesis for tests, CloudFormation for the member role.

The design is built on the observed AWS behaviour in `.agents/tasks/sir-log-readiness-checks/probe-findings.md`. Where that file and botocore disagree, the probe wins.

### Goals

- Five checks whose PASS, FAIL and ERROR arms are each reachable, with FAIL used only where AWS has told us the control is absent.
- Per-VPC fan-out for the two network checks, so one undetermined listing never drops VPCs from the report.
- The contract suites (client, accessor, classification, discriminator, confessing-fail, layering, registry) cover the new code without exemptions.
- Three new IAM actions, and only three.

### Non-Goals

1. No change to any existing check's verdict, Region label or pagination, including the known deferrals in `structure.md` (the SIR `regions[0]` labelling, the missing SIR `NAMESPACE`).
2. No shared cross-service VPC accessor. `ec2:DescribeVpcs` is issued from the `ec2` and the `route53resolver` packages independently (see Decision 4).
3. No coverage gating for `SRA-SECURITYINCIDENTRESPONSE-07` (requirements Out of Scope 6).
4. No change to `SRA-SECURITYINCIDENTRESPONSE-05`, despite the probe's management-account observation (Out of Scope 5).

## Architecture

```
SecurityCheck (core/check.py)
├── SecurityIncidentResponseCheck   services/securityincidentresponse/base.py   (+ get_event_rules)
│     ├── SRA_SECURITYINCIDENTRESPONSE_06   get_role                  -> 1 row, global
│     └── SRA_SECURITYINCIDENTRESPONSE_07   get_event_rules(region)   -> 1 row per Region
├── CloudTrailCheck                 services/cloudtrail/base.py                 (unchanged)
│     └── SRA_CLOUDTRAIL_15                 get_organization_trails, get_event_selectors -> 1 row per org trail, global
├── EC2Check                        services/ec2/base.py                        (+ get_vpcs, get_flow_logs)
│     └── SRA_EC2_02                        -> 1 row per owned VPC per Region, or 1 row per Region
└── Route53ResolverCheck  (NEW)     services/route53resolver/base.py            (get_vpcs, get_query_log_config_associations)
      └── SRA_ROUTE53RESOLVER_01            -> 1 row per owned VPC per Region, or 1 row per Region

Clients (all inherit AWSClient, acquire in __init__, `except AWS_EXCEPTIONS as e: return self.aws_error(e)`)
  SecurityIncidentResponseClient  + events binding, + list_event_rules()
  EC2Client                       + describe_vpcs(), describe_flow_logs()
  Route53ResolverClient (NEW)     route53resolver + ec2 bindings; list_resolver_query_log_config_associations(), describe_vpcs()
```

None of the five checks reads Organizations data, so `self.organization` is not touched and no Organizations binding is added anywhere.

## Module inventory

### New files

| Path (under `sraverify/sraverify/`)                                           | Content                                                               |
| ----------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| `services/route53resolver/__init__.py`                                        | Docstring + `import_check_modules(f"{__name__}.checks")`, three lines |
| `services/route53resolver/checks/__init__.py`                                 | Docstring only, matching the other `checks/__init__.py` files         |
| `services/route53resolver/client.py`                                          | `Route53ResolverClient(AWSClient)`                                    |
| `services/route53resolver/base.py`                                            | `Route53ResolverCheck(SecurityCheck)`                                 |
| `services/route53resolver/checks/sra_route53resolver_01.py`                   | `SRA_ROUTE53RESOLVER_01`                                              |
| `services/securityincidentresponse/checks/sra_securityincidentresponse_06.py` | `SRA_SECURITYINCIDENTRESPONSE_06`                                     |
| `services/securityincidentresponse/checks/sra_securityincidentresponse_07.py` | `SRA_SECURITYINCIDENTRESPONSE_07`                                     |
| `services/cloudtrail/checks/sra_cloudtrail_15.py`                             | `SRA_CLOUDTRAIL_15`                                                   |
| `services/ec2/checks/sra_ec2_02.py`                                           | `SRA_EC2_02`                                                          |
| `tests/unit/services/test_sir_log_readiness_checks.py`                        | Per-arm unit tests for all five checks (Testing Strategy)             |

`services/__init__.py` needs no edit: `import_service_packages` walks every subpackage.

### Edited files

Paths starting `services/` or `tests/` are under `sraverify/sraverify/`; all others are relative to the worktree root.

| Path                                                   | Edit and replacement text                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `services/securityincidentresponse/client.py`          | `events` binding in `__init__`; `list_event_rules()`; module docstring "Four methods across two" → "Five methods across three"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `services/securityincidentresponse/base.py`            | `get_event_rules(region)`; `GetRole`/`NoSuchEntity` evidence extended. Module docstring, last paragraph, "The one caching site is the private :meth:`_discover_memberships`, under the module-level ``_CACHE_NAMESPACE``." → "Two caching sites, both under the module-level ``_CACHE_NAMESPACE``: the private :meth:`_discover_memberships` and the public :meth:`get_event_rules`, whose contract is held by ``test_securityincidentresponse_get_event_rules_never_caches_a_failure``." `_CACHE_NAMESPACE` comment, "The private _discover_memberships is the only writer, so nothing here goes through the accessor-caching contract the class attribute would advertise." → "Its writers are the private _discover_memberships and get_event_rules; neither goes through the NAMESPACE-keyed accessor harness the class attribute would advertise, so each has a dedicated test."                                                                                                                                                                                                                                                                                                                                                                                                         |
| `services/ec2/client.py`, `services/ec2/base.py`       | Two client methods, two accessors, docstrings, `NOT_CONFIGURED_ERRORS` comment extended                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `tests/property/test_client_contract_property.py`      | Five `ClientAdapter` rows, `_ROUTE53RESOLVER` table, `ADAPTERS` key. **Rename** `test_eighteen_services_are_discovered` (l.1397) → `test_nineteen_services_are_discovered`, assert `len(_SERVICE_NAMES) == 19`, message "expected 18 service packages" → "expected 19 service packages". `test_the_target_set_is_not_trivially_small` docstring "92 client methods across the 18 clients" → "101 client methods across the 19 clients" and message "the tree holds 92" → "holds 101" (the `>= 90` floor stays; `len(_TARGETS)` is 96 today and 101 after). Comments and docstrings: l.6–7 "for all 92 methods across the 18 clients" → "for all 101 methods across the 19 clients"; l.13 "The cost is 92 copies" → "101 copies"; l.14 "failure mode of 92 copies" → "101 copies"; l.190 "one per service, all 18" → "all 19"; l.1173 "All 18, so Property 3a" → "All 19, so Property 3a"; l.1241 "Every one of the 92 client methods" → "101"; l.1673 "The 17 ``services/*/client.py`` files" → "The 18 ``services/*/client.py`` files"; l.1690 "All 18 client modules" → "All 19 client modules"; l.1746 "repeat across 92 methods" → "101 methods"; l.1845 "a value typed 92 times" → "101 times"                                                                                           |
| `tests/property/test_accessor_cache_property.py`       | Six `AccessorAdapter` rows (4 `accessor`, 1 `derived`, 1 `client_lookup`), `route53resolver` key. **Rename** `test_eighteen_services_are_discovered` (l.1420) → `test_nineteen_services_are_discovered`, assert `== 19`, message "expected 18 service packages" → "expected 19 service packages", matching the client-contract module. New test `test_securityincidentresponse_get_event_rules_never_caches_a_failure`. The SIR adapter-table comment "The one caching site is _discover_memberships, covered by its own test below." → "The caching sites are _discover_memberships and get_event_rules, each covered by its own test below." **Rename** `test_securityincidentresponse_discover_memberships_is_the_one_caching_site` → `test_securityincidentresponse_discover_memberships_caches_under_the_module_namespace`; its docstring "it is the only place that base writes the cache" → "it is one of the two places that base writes the cache (the other is get_event_rules)". `test_securityincidentresponse_declares_no_namespace` docstring "its accessors do no caching" → "its two caching sites write the module-level _CACHE_NAMESPACE rather than a class NAMESPACE". The rename is chosen over a docstring-only fix because the test ID itself would state a falsehood. |
| `tests/property/test_discriminator_property.py`        | `SecurityIncidentResponseCheck` golden hash (with the `# pragma: allowlist secret` comment its neighbours carry; row count stays 46). Comments l.113 "the eighteen service keys" and l.116 "the eighteen service base tables" → "nineteen". **Rename** `test_eighteen_services_declare_a_table_attribute` → `test_every_service_declares_a_table_attribute`; no count is added, because the body has none                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `tests/property/test_registry_bijection_property.py`   | `EXPECTED_CHECK_COUNT = 187`, `EXPECTED_SERVICE_COUNT = 19`; comment l.95 "158 checks across 18 services" → "187 checks across 19 services"; **rename** `test_exactly_eighteen_service_subpackages_are_discovered` → `test_exactly_nineteen_service_subpackages_are_discovered`, docstring "holds 18 service subpackages" → "holds 19"; comment l.415 "the 158 files are spread across all 18 of them" → "the 187 files are spread across all 19 of them"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `tests/property/test_catalog_identity_property.py`     | `EXPECTED_CHECK_COUNT = 187`; comment l.115 "the walk over 18 service packages and 158 check modules" → "the walk over 19 service packages and 187 check modules"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `tests/unit/util/test_generate_iam_policy.py`          | l.235 `len(modules) == 19`; l.257 message "the 18 clients reach roughly 30" → "the 19 clients reach roughly 30"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `tests/unit/core/test_select.py`                       | l.75 docstring "walks 18 service packages and 158 check modules" → "walks 19 service packages and 187 check modules"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `tests/unit/core/test_aws_client.py`                   | l.5 "relied on 92 times" → "relied on 101 times"; l.645 "in 92 hand-written ``except`` clauses" → "in 101"; l.686 "every one of the 92 handlers" → "every one of the 101 handlers" (true of today's tree too: no handler passes `operation=` or `region=`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `tests/property/test_check_classification_property.py` | l.437–439 comment "``securityincidentresponse``'s six public methods are classified ``derived`` and declare no ``client_method``, because they route through a private helper rather than through ``self._clients`` -- but their names are the client method names, so ``client_method or method`` resolves them." → "``securityincidentresponse``'s seven public methods are classified ``derived``, because they route through a private helper rather than through ``self._clients``. Six declare no ``client_method`` because their names are the client method names; ``get_event_rules`` declares ``client_method="list_event_rules"``. Either way ``client_method or method`` resolves them." l.551 stays (see below)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `tests/property/test_catalog_meta_property.py`         | l.758–759 comment "walks 18 service packages and executes … 158 check class bodies" → "walks 19 service packages and executes … 187 check class bodies"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `tests/property/test_catalog_executable_property.py`   | l.105 docstring "discovery over the 18 service" → "discovery over the 19 service"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `tests/property/test_availability_property.py`         | l.122 message "18 services with 158 checks" → "19 services with 187 checks"; `_CANDIDATE_SERVICE_IDS` and `_REJECTED_SERVICE_IDS` unchanged (Property 20)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `1-sraverify-member-roles.yaml`                        | Three actions in `SRAVerifyLeastPrivilege`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `docs/checks.txt`                                      | Regenerated from the worktree venv (Documentation section)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `.kiro/steering/product.md`                            | "Currently **182 checks across 18 AWS services**" line → 187 / 19 with the re-sorted per-service list; one new bullet for the five checks                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `.kiro/steering/structure.md`                          | Every 182 → 187; l.104 and l.695 "`tests/unit/services/` holds `test_inspector_batching.py`" → "holds `test_inspector_batching.py` and `test_sir_log_readiness_checks.py`"; l.517 "96 client methods: 86 across the 17 service clients" → "101 client methods: 91 across the 18 service clients"; l.707 "All 96 client methods … over the 17 `services/*/client.py` files" → "All 101 … over the 18"; every other "17 service clients" → 18; test totals as measured                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `.kiro/steering/tech.md`                               | Test totals and skip count with its explanation ("for every one of the 182 checks" → 187), "the real 182 registered checks and the 96 real client methods" → 187 / 101, the three new actions under the deploy-the-member-role-first paragraph                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `.kiro/steering/creating_checks_best_practices.md`     | l.136 and l.479 "182" → "187". The l.177 "79 of 158 checks" is a historical figure and stays                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `README.md`                                            | l.5 "**158 automated security checks across 18 AWS services**: Account, … Organizations, S3, …" → "**187 automated security checks across 19 AWS services**: Account, … Organizations, Route 53 Resolver, S3, …"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `sraverify/README.md`                                  | l.10 "**158 checks across 18 services**" → "**187 checks across 19 services**"; l.234 "validation pass over all 158 checks" → "over all 187 checks"; l.617 "byte-identical in all 96 client methods" → "in all 101 client methods"; l.1067 "`tests/unit/services/` — Inspector's `BatchGetAccountStatus` batching" → "… batching, and per-arm tests for the five SIR log-readiness checks"; l.1078 "All 96 client methods … the 17 `services/*/client.py` files" → "All 101 … the 18"; l.1094 "all 182 registered checks" → "all 187"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |

`docs/check-report.md` ("182 checks across 18 services") is **not** edited: it is a dated report ("retrieved 2026-09-16", "at the time of writing"), and rewriting its counts would misstate what it measured.

Test renames follow one rule: a test is renamed when its name would state something false after the change, and in no other case. `test_eighteen_services_declare_a_table_attribute` becomes count-free because its body never had a count; the two `test_eighteen_services_are_discovered` tests keep a count because their bodies assert one.

Comments, docstrings and assertion messages follow one rule too: **every one that states the current size of the tree — service packages, clients, client modules, client methods or checks — is updated to the new size, and a stale figure in the same sentence (`158`, `92`) is corrected with it.** Standalone `92` client-method figures are treated the same way, not as drift: all nine (`test_client_contract_property.py` l.6, l.13, l.14, l.1241, l.1746, l.1845; `test_aws_client.py` l.5, l.645, l.686) become `101`, as listed in the table, so after the change `grep -rnE --include='*.py' "\b92\b" sraverify/sraverify/tests` returns nothing. Two kinds of site are left alone because they do not state the current tree: `test_service_migration_property.py` l.8 and l.27 ("each of the 17 service base classes"), which enumerate by name the set migrated in the scan-context-refactor spec; and `test_check_classification_property.py` l.551 ("Twelve of the eighteen declared pairs"), which counts declared `NOT_CONFIGURED_ERRORS` pairs, a number this change does not alter (no entry is added or removed). The closing gates in "Documentation and count updates" check the sweep for the patterns they name; they are a calibrated net for the forms found in this tree, not a proof that no other phrasing exists.

## Components and Interfaces

### Shared conventions for all five checks

- Every ERROR row: `actual_value=f"{error['Operation']} failed: {error['Code']}: {error['Message']}"`, `remediation=self._remediation_for(error)`.
- Every check uses `self.is_not_configured(error)` for any error it could classify; no inline code compare.
- **Error-branch shape rule.** The two-arm branch (`is_not_configured` → `failed()`, else `error()`) is used wherever the error lands on a row whose `failed()` text could truthfully state "the control is absent" for that row: SIR-06 (`GetRole`), SIR-07 (`ListRules`, per Region), CLOUDTRAIL-15 (`DescribeTrails` and `GetEventSelectors`). A future table entry then needs no check edit. The single-arm branch (`error()` only) is used in EC2-02 and ROUTE53RESOLVER-01 for `DescribeVpcs` and for the second listing, because (a) their tables are empty by Req 4.10 / 5.10 and (b) no `failed()` text can be phrased for them: a failed `DescribeVpcs` has no VPC to name, and a failed second listing is the same fact for every VPC in the Region, so "this VPC has no flow log" would be a claim AWS never made. Both shapes pass the classification suite, which asserts only that an undeclared error reaches `error()`.
- No `except` inside any `execute()`; JSON parsing (Decision 2) and selector evaluation (CLOUDTRAIL-15) live in `@staticmethod` helpers on the check class, which are pure and cannot raise for any input shape.
- Every `ActualValue` that lists items sorts them, never joins a `set`.
- No FAIL wording matches the `_CONFESSING_PATTERNS` in `test_no_confessing_fail_property.py`.
- Region-level `ResourceId` strings use the form `<service>:<region>:<account_id>` (`events:us-east-1:111122223333`, `ec2:us-east-1:111122223333`, `route53resolver:us-east-1:111122223333`). The same string is used by PASS, FAIL and ERROR rows for that Region, so the `(Region, ResourceId)` key is stable across status changes (Req 2.10, 4.11, 5.12).

### SRA-SECURITYINCIDENTRESPONSE-06 — SIR service linked role exists

**AWS operation:** `iam:GetRole`, `RoleName="AWSServiceRoleForSecurityIncidentResponse"`. Already granted (member role l.184).

**Client / accessor:** reuses `SecurityIncidentResponseClient.get_role` and `SecurityIncidentResponseCheck.get_role`. No new client method, no `ClientAdapter` row, no `AccessorAdapter` row (both already exist; `get_role` is classified `derived`, `error_bearing=True`).

**NOT_CONFIGURED_ERRORS:** the existing `GetRole` / `NoSuchEntity` entry. Its `evidence` string gains one sentence:

> `Observed 2026 in the test organization: GetRole for AWSServiceRoleForSecurityIncidentResponse answered NoSuchEntity "The role with name AWSServiceRoleForSecurityIncidentResponse cannot be found." in the management, log-archive and an application account, none of them the SIR delegated administrator.`

Because the golden in `test_discriminator_property.py` pins a sha256 of the evidence text, the `SecurityIncidentResponseCheck` row's hash is recomputed and updated in the same commit. The row count stays 46.

**Logic:**

```python
ROLE_NAME = "AWSServiceRoleForSecurityIncidentResponse"
ROLE_PATH = "/aws-service-role/security-ir.amazonaws.com/"

def execute(self):
    response = self.get_role(ROLE_NAME)
    expected_arn = f"arn:aws:iam::{self.account_id}:role{ROLE_PATH}{ROLE_NAME}"
    if "Error" in response:
        error = response["Error"]
        if self.is_not_configured(error):
            yield self.failed(region="global", resource_id=expected_arn,
                              actual_value=f"Service linked role {ROLE_NAME} does not exist in this account")
        else:
            yield self.error(region="global", resource_id=expected_arn, actual_value=..., remediation=self._remediation_for(error))
        return
    yield self.passed(region="global", resource_id=response.get("Role", {}).get("Arn") or expected_arn,
                      actual_value=f"Service linked role {ROLE_NAME} exists")
```

The ERROR row uses `expected_arn` as its `ResourceId` too, so the row key is the same in all three states (the PASS ARN from AWS equals `expected_arn` in the commercial partition). The `arn:aws:` prefix is literal, per Req 1.5 and matching `SRA-SECURITYINCIDENTRESPONSE-05`; in GovCloud or China the FAIL/ERROR `ResourceId` would carry the wrong partition. Accepted: the scanner has no partition helper for ARNs today and introducing one is a cross-cutting change.

No `--audit-account` guard (Req 1.8). No Region loop.

**CheckMeta:**

| Field             | Value                                                                                                                                                                                                                                                                                                                             |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `title`           | `Security Incident Response service linked role exists`                                                                                                                                                                                                                                                                           |
| `severity`        | `Severity.MEDIUM`                                                                                                                                                                                                                                                                                                                 |
| `account_type`    | `AccountType.AUDIT`                                                                                                                                                                                                                                                                                                               |
| `service`         | `SecurityIncidentResponse`                                                                                                                                                                                                                                                                                                        |
| `resource_type`   | `AWS::IAM::Role`                                                                                                                                                                                                                                                                                                                  |
| `check_logic`     | `Call iam:GetRole for AWSServiceRoleForSecurityIncidentResponse. Passes if the role exists. Fails if IAM answers NoSuchEntity.`                                                                                                                                                                                                   |
| `remediation`     | text: `Create the AWSServiceRoleForSecurityIncidentResponse service linked role in the Security Incident Response delegated administrator account.`; cli: `aws iam create-service-linked-role --aws-service-name security-ir.amazonaws.com`; console: `IAM console, Roles, Create role, AWS service, Security Incident Response.` |
| `sra_sections`    | `("Security Tooling account", "AWS Security Incident Response")`                                                                                                                                                                                                                                                                  |
| `additional_urls` | the config-validation URL; `https://docs.aws.amazon.com/security-ir/latest/userguide/using-service-linked-roles.html`                                                                                                                                                                                                             |

### SRA-SECURITYINCIDENTRESPONSE-07 — proactive-response EventBridge rules enabled

**AWS operation:** `events:ListRules` on the default bus (no `EventBusName`), paginated via botocore's `list_rules` paginator. Already granted (l.162).

**Client method** — `SecurityIncidentResponseClient.list_event_rules(self) -> Mapping[str, Any]`. `__init__` gains `self.events_client = ctx.get_client('events', region=region)`, so the IAM generator attributes `events:ListRules` to this client. Body is the `SecurityHubClient.list_event_rules` shape: whole paginator loop inside `try`, return `{"Rules": rules}`.

**ClientAdapter row** (in `_SECURITYINCIDENTRESPONSE`):

```python
ClientAdapter(
    method="list_event_rules",
    boto_service="events",
    boto_method="list_rules",
    operation="ListRules",
    success=({"Rules": [{
        "Name": "SIRGuardDutyRule", "State": "ENABLED", "EventBusName": "default",
        "ManagedBy": "triage.security-ir.amazonaws.com",
        "EventPattern": '{"source":["aws.guardduty"],"detail-type":["GuardDuty Finding"]}',
    }]},),
    paginated=True,
),
```

**Base accessor** — `SecurityIncidentResponseCheck.get_event_rules(self, region: str) -> Mapping[str, Any]`.

This base has no `NAMESPACE`, and `test_securityincidentresponse_declares_no_namespace` asserts the absence (structure.md, Non-Goal 1). Adding one is therefore off the table. The accessor caches under the existing module-level `_CACHE_NAMESPACE` (`"securityincidentresponse"`) with key `f"event_rules:{region}"`, the same mechanism `_discover_memberships` uses:

```python
def get_event_rules(self, region: str) -> Mapping[str, Any]:
    key = f"event_rules:{region}"
    if self._ctx._has(_CACHE_NAMESPACE, key):
        return self._ctx._get(_CACHE_NAMESPACE, key)
    result = self._sir_client(region).list_event_rules()
    if is_error(result):
        return result            # never cached
    self._ctx._set(_CACHE_NAMESPACE, key, result)
    return result
```

`_sir_client(region)` creates the wrapper on demand, so there is no no-client path to return `no_client_result` from — the same as every other SIR accessor. A Region-specific wrapper is required here (unlike `get_role`) because EventBridge rules are regional.

**AccessorAdapter row and classification:** `accessor` is impossible — the harness asserts the write namespace equals `cls.NAMESPACE`, which does not exist on this class. It is classified like its siblings:

```python
A("get_event_rules", "derived", args=(_TEST_REGION,),
  client_method="list_event_rules",
  why="caches under the module-level _CACHE_NAMESPACE via _sir_client; this base "
      "declares no NAMESPACE (known deferral), so Properties 7-9 cannot reach it -- "
      "held by test_securityincidentresponse_get_event_rules_never_caches_a_failure",
  error_bearing=True),
```

Because `derived` excludes it from Properties 7–9, a dedicated test in `test_accessor_cache_property.py` holds the contract directly: an error result is returned unchanged and not cached; a second call re-issues the client call; a success is cached under `("securityincidentresponse", "event_rules:us-east-1")`; a warm cache skips the client. `error_bearing=True` makes `test_check_classification_property` drive it with error results. `client_method="list_event_rules"` is declared even though `derived` rows do not need it, because `test_check_classification_property._OPERATION_OF_ACCESSOR` joins a SIR accessor to its operation through `accessor.client_method or accessor.method`; the six existing SIR methods share their client method's name, this one does not, and without the field `_operation_of("securityincidentresponse", "get_event_rules")` would be `None`. Nothing rejects `client_method` on a `derived` row. The comment above that join is updated to match (Edited files).

**NOT_CONFIGURED_ERRORS:** nothing added. `ResourceNotFoundException` was observed only for a named nonexistent bus and cannot arise on the default bus (Req 2.8). Every `ListRules` error is an ERROR.

**Rule classification** — pure static helpers on the check:

```python
SIR_MANAGED_BY = "triage.security-ir.amazonaws.com"

@staticmethod
def event_sources(rule) -> frozenset[str]:
    """`source` values from EventPattern; empty for absent/invalid JSON, non-dict, or non-list/str source."""
```

`event_sources` calls `json.loads` inside a `try` that catches only `(TypeError, ValueError)` (`json.JSONDecodeError` is a `ValueError`), returns `frozenset()` on failure, accepts `source` as a `str` or a `list` of `str`, and ignores anything else. It lives on the check class as a staticmethod, outside `execute()`, so the no-`except`-in-`execute` rule holds. GuardDuty_Rule ⇔ `"aws.guardduty" in sources`; SecurityHub_Rule ⇔ `"aws.securityhub" in sources`. A rule matching both counts as both. Identification is by `rule.get("ManagedBy") == SIR_MANAGED_BY` only (Req 2.3). The probe's second discriminator, `EventBusName == "default"`, is dropped on documentary evidence rather than a guard: the `ListRules` API reference (<https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_ListRules.html>) says of `EventBusName`, "If you omit this, the default event bus is used", and the same sentence is in botocore 1.43.105's `events` model (`ListRules.EventBusName` documentation, read from the worktree venv). The client never passes `EventBusName`, so every returned rule is a default-bus rule and the second test could only ever be true. A guard was considered and rejected because it would be dead code the unit suite could exercise only with a response AWS cannot send.

**Per-Region logic:**

The snippet below is normative for every field access: nothing is indexed with `[...]` on an AWS-shaped value, so no response shape can raise `KeyError` or `AttributeError` and become a synthetic ERROR row.

```python
@staticmethod
def rule_name(rule) -> str:
    name = rule.get("Name")
    return name if isinstance(name, str) and name else "<unnamed>"

def execute(self):
    for region in self.regions:
        rid = f"events:{region}:{self.account_id}"
        rules = self.get_event_rules(region)
        if "Error" in rules:
            error = rules["Error"]
            if self.is_not_configured(error):          # table empty today; kept for the two-arm shape
                yield self.failed(region=region, resource_id=rid,
                                  actual_value="EventBridge reports no default event bus in this Region")
            else:
                yield self.error(region=region, resource_id=rid,
                                 actual_value=f"{error['Operation']} failed: {error['Code']}: {error['Message']}",
                                 remediation=self._remediation_for(error))
            continue
        managed = sorted(
            (r for r in rules.get("Rules") or [] if isinstance(r, dict) and r.get("ManagedBy") == SIR_MANAGED_BY),
            key=self.rule_name,
        )
        gd = [r for r in managed if "aws.guardduty" in self.event_sources(r)]
        sh = [r for r in managed if "aws.securityhub" in self.event_sources(r)]
        missing = [label for label, group in (("GuardDuty", gd), ("Security Hub", sh)) if not group]
        disabled = sorted({(self.rule_name(r), str(r.get("State"))) for r in gd + sh if r.get("State") != "ENABLED"})
        ...  # verdict below
```

`error['Operation']` etc. index the Error_Result, whose three fields `error_result()` guarantees. Verdict: `missing` non-empty → FAIL `No SIR-managed EventBridge rule for <GuardDuty and/or Security Hub> findings` (plus `; not ENABLED: <name> (<state>), …` when `disabled` is also non-empty); else `disabled` non-empty → FAIL `SIR-managed rules not ENABLED: SIRGuardDutyRule (DISABLED), …`; else PASS `SIR-managed rules ENABLED: SIRGuardDutyRule (GuardDuty), SIRSecurityHubRule (Security Hub)`. A rule with no `State` renders as `(None)`. One row per Region carries every fact (Req 2.5–2.7). The two-arm error branch is kept, rather than a single `error()`, because every check's error branch has that shape and a future `ListRules` declaration then needs no check edit; its `failed()` text is the only thing a declared `ListRules` code could mean on the default bus.

**Availability:** no `service_available_in_region` call, per the amended Req 2.9; see Decision 5.

**FAIL remediation** (dynamic text): `Confirm this account is covered by the Security Incident Response membership with proactive response (triage) enabled. In the management account, create the triage service linked role manually: aws iam create-service-linked-role --aws-service-name triage.security-ir.amazonaws.com` (Req 2.11). This is also `meta.remediation.text`, so `failed()` needs no override.

**CheckMeta:** title `Security Incident Response proactive response EventBridge rules are enabled`; `MEDIUM`; `APPLICATION`; service `SecurityIncidentResponse`; resource type `AWS::Events::Rule`; check_logic `For each Region list default event bus rules with events:ListRules and select rules ManagedBy triage.security-ir.amazonaws.com. Passes if a GuardDuty-sourced and a Security Hub-sourced managed rule exist and every one is ENABLED.`; sra_sections `("Security Tooling account", "AWS Security Incident Response")`; additional_urls: the config-validation URL, `https://docs.aws.amazon.com/security-ir/latest/userguide/setup-monitoring-and-investigation-workflows.html`.

### SRA-CLOUDTRAIL-15 — organization trail logs all management events

**AWS operations:** `cloudtrail:DescribeTrails` (via `get_organization_trails`) and `cloudtrail:GetEventSelectors` (via `get_event_selectors(trail["HomeRegion"], trail["TrailARN"])`). No new client method, accessor, adapter row or IAM action (Req 3.2). The control flow mirrors `SRA-CLOUDTRAIL-14` exactly: trail-list error → one row (`organization/<account_id>`, global, two-arm); empty list → one FAIL; per-trail selector error → one row for that trail and `continue`, FAIL for the declared `GetEventSelectors`/`TrailNotFoundException`, ERROR otherwise.

`DescribeTrails` has no declared code, so its error arm always resolves ERROR today; the two-arm shape is kept so a future declaration needs no check edit (Req 3.9). Its `failed()` text is the `SRA-CLOUDTRAIL-14` wording: `No CloudTrail trail exists for this account, so no organization trail logs management events`, `resource_id=f"organization/{self.account_id}"`. Trail fields are read as `trail.get("TrailARN")` and `trail.get("HomeRegion")`. The evaluated set is `usable = [t for t in org_trails if isinstance(t, dict) and isinstance(t.get("TrailARN"), str) and t["TrailARN"] and isinstance(t.get("HomeRegion"), str) and t["HomeRegion"]]`; a trail outside it (AWS always returns both fields) is skipped, not indexed. **If `usable` is empty — whether the trail list was empty or every trail was skipped — the check yields the single "no organization trail" FAIL** (`organization/<account_id>`, global), so a row always exists and a malformed response never silently yields zero rows.

`get_event_selectors` is called with `trail.get("HomeRegion")` — if that Region is not in `--regions`, there is no client and the accessor returns `no_client_result` (`NoClient`), which becomes an ERROR row naming the service. This is the existing `SRA-CLOUDTRAIL-14` behaviour and is accepted unchanged.

**Coverage evaluation** — a pure `@staticmethod management_event_gap(response) -> str | None` returning `None` for Management_Event_Coverage or the reason text.

**Precedence, stated once and used everywhere (Property 5, the unit cases, the hypothesis case):**

```python
advanced = response.get("AdvancedEventSelectors") or []
selectors = advanced if advanced else (response.get("EventSelectors") or [])
```

Only the *evaluated* list is consulted. `management_event_gap` returns `None` iff some element of the evaluated list covers — by the basic rule (Req 3.4) when the evaluated list is `EventSelectors`, by the advanced rule (Req 3.5) when it is `AdvancedEventSelectors`. A trail carries one form or the other: the `PutEventSelectors` API reference (<https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_PutEventSelectors.html>) says a trail can use either `AdvancedEventSelectors` or `EventSelectors`, but not both, and that applying advanced selectors overwrites existing basic ones. If a response nevertheless carried both, the advanced list decides — the same precedence `SRA-CLOUDTRAIL-14` uses — so a covering basic selector next to a non-empty, non-covering advanced list yields advanced reason 1. Non-dict elements are ignored.

Basic `EventSelectors`: a selector *covers* iff `IncludeManagementEvents is True`, `ReadWriteType == "All"`, and `not selector.get("ExcludeManagementEventSources")`. If any selector covers → `None`. Otherwise the reason is chosen by the first rule that applies, in this order, so the text is deterministic:

1. no selector has `IncludeManagementEvents is True` → `Management events are not included`;
2. no including selector has `ReadWriteType == "All"`. Let `kinds` be the sorted distinct `str(ReadWriteType)` values among including selectors. One value → `Only <v> management events are recorded` (e.g. `Only ReadOnly management events are recorded`). More than one → `Read and write management events are split across selectors (<kinds, comma-joined>); no single selector records both` (Decision 3);
3. otherwise → `Management events from these sources are excluded: <sorted, comma-joined union of ExcludeManagementEventSources over including All selectors>`.

Advanced `AdvancedEventSelectors`: for each selector, collect its `FieldSelectors` by `Field`. A selector *covers* iff some `eventCategory` field has `"Management" in Equals`, there is no `readOnly` field, and there is no `eventSource` field (any `eventSource` field — `Equals`, `NotEquals`, `StartsWith`, `NotStartsWith` — narrows or excludes sources, Req 3.5). Reasons, in order:

1. no selector with `eventCategory` `Equals` `Management` → `Management events are not included`;
2. every management selector has a `readOnly` field. Let `values` be the sorted distinct `str` elements of the `Equals` lists of those `readOnly` fields. Exactly one value → `Only read-only management events are recorded` when it is `"true"`, `Only write management events are recorded` when it is `"false"`, and `Only readOnly = <v> management events are recorded` for any other single value. More than one value → `Read and write management events are split across advanced selectors (readOnly = <values, comma-joined>); no single selector records both` (Decision 3). No value at all (a `readOnly` field with an empty or non-list `Equals`) → `Management events are filtered by readOnly`;
3. otherwise → `Management event sources are restricted: <sorted, comma-joined description of each eventSource field, e.g. "NotEquals kms.amazonaws.com">`.

Both lists empty or absent → the evaluated list is the empty basic list → basic reason 1.

Per-trail: `None` → PASS `Organization trail logs all read and write management events from every event source`; reason → FAIL with that reason. One row per trail, `region="global"`, `resource_id=trail_arn`.

**FAIL remediation** (`meta.remediation.text`): `Restore full management-event logging on the organization trail with aws cloudtrail put-event-selectors. The call replaces every existing selector on the trail, so include the trail's data-event selectors in the same call.` `cli`: `aws cloudtrail put-event-selectors --trail-name <trail-arn> --region <home-region> --event-selectors '[{"ReadWriteType":"All","IncludeManagementEvents":true,"ExcludeManagementEventSources":[]}]'` and the advanced form `--advanced-event-selectors '[{"Name":"Management events","FieldSelectors":[{"Field":"eventCategory","Equals":["Management"]}]}]'`. The empty-list FAIL overrides with `Create an organization trail in the management account that logs all management events`.

**CheckMeta:** title `Organization trail logs all management events`; `HIGH`; `MANAGEMENT`; service `CloudTrail`; resource type `AWS::CloudTrail::Trail`; sra_sections `("Management account", "AWS CloudTrail")`; additional_urls: the config-validation URL, `https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html`.

### SRA-EC2-02 — VPC Flow Logs enabled for every VPC

**Client methods** on `EC2Client` (existing `self.client` ec2 binding; no new acquisition):

```python
def describe_vpcs(self) -> Mapping[str, Any]:
    try:
        vpcs = []
        for page in self.client.get_paginator('describe_vpcs').paginate():
            vpcs.extend(page.get('Vpcs', []))
        return {"Vpcs": vpcs}
    except AWS_EXCEPTIONS as e:
        return self.aws_error(e)

def describe_flow_logs(self) -> Mapping[str, Any]:
    ...same shape, paginator 'describe_flow_logs', key 'FlowLogs', no Filter (Req 4.3)...
```

**ClientAdapter rows** (`_EC2`):

```python
ClientAdapter(method="describe_vpcs", boto_service="ec2", boto_method="describe_vpcs",
              operation="DescribeVpcs",
              success=({"Vpcs": [{"VpcId": "vpc-1", "OwnerId": _TEST_ACCOUNT, "IsDefault": True}]},),
              paginated=True),
ClientAdapter(method="describe_flow_logs", boto_service="ec2", boto_method="describe_flow_logs",
              operation="DescribeFlowLogs",
              success=({"FlowLogs": [{"FlowLogId": "fl-1", "ResourceId": "vpc-1",
                                      "FlowLogStatus": "ACTIVE", "TrafficType": "ALL"}]},),
              paginated=True),
```

**Accessors** on `EC2Check`, both the `get_ebs_encryption_by_default` shape (cache under `NAMESPACE = "ec2"`, `no_client_result(service="EC2", region=region)` when no wrapper, never cache a failure):

| Accessor                | Client method        | Cache key            |
| ----------------------- | -------------------- | -------------------- |
| `get_vpcs(region)`      | `describe_vpcs`      | `vpcs:{region}`      |
| `get_flow_logs(region)` | `describe_flow_logs` | `flow_logs:{region}` |

**AccessorAdapter rows** (`"ec2"`): `A("get_vpcs", "accessor", args=(_TEST_REGION,), client_method="describe_vpcs", cache_key=f"vpcs:{_TEST_REGION}")` and the same for `get_flow_logs` / `flow_logs:`.

**NOT_CONFIGURED_ERRORS:** stays `{}` (Req 4.10). The class comment gains: `DescribeVpcs and DescribeFlowLogs answer an empty list for "nothing here"; no error code from either was observed or is documented as meaning "not configured".`

**Logic:**

Normative; `vpc["VpcId"]` is indexed only after the owned-VPC filter has proved it a non-empty `str`:

```python
@staticmethod
def owned_vpcs(vpcs, account_id) -> list[dict]:
    """Owned VPCs with a usable VpcId, sorted by VpcId. Shared with ROUTE53RESOLVER-01 by copy."""
    return sorted(
        (v for v in vpcs.get("Vpcs") or []
         if isinstance(v, dict) and v.get("OwnerId") == account_id
         and isinstance(v.get("VpcId"), str) and v["VpcId"]),
        key=lambda v: v["VpcId"],
    )

def execute(self):
    for region in self.regions:
        region_rid = f"ec2:{region}:{self.account_id}"
        vpcs = self.get_vpcs(region)
        if "Error" in vpcs:
            yield self.error(region=region, resource_id=region_rid, ...)       # one Region row (Req 4.8)
            continue
        owned = self.owned_vpcs(vpcs, self.account_id)
        if not owned:
            yield self.passed(region=region, resource_id=region_rid,
                              actual_value="No VPC owned by this account in this Region")
            continue
        flow_logs = self.get_flow_logs(region)
        if "Error" in flow_logs:
            for vpc in owned:                                                   # one per VPC (Req 4.9)
                yield self.error(region=region, resource_id=vpc["VpcId"], ...)
            continue
        active: dict[str, list[tuple[str, str]]] = {}
        for fl in flow_logs.get("FlowLogs") or []:
            if not isinstance(fl, dict):
                continue
            rid = fl.get("ResourceId")
            if fl.get("FlowLogStatus") == "ACTIVE" and isinstance(rid, str) and rid.startswith("vpc-"):
                active.setdefault(rid, []).append((str(fl.get("FlowLogId")), str(fl.get("TrafficType"))))
        for vpc in owned:
            hits = sorted(active.get(vpc["VpcId"], []))
            ...  # PASS "Active flow log fl-1 (traffic type ALL)" (all hits, comma-joined);
                 # FAIL "No active VPC-level flow log" + " (default VPC)" when vpc.get("IsDefault") is True
```

The `startswith("vpc-")` filter is redundant with the dictionary lookup by VPC ID but documents that subnet and ENI logs never count (Req 4.6). A VPC whose `VpcId` is missing, `None`, non-`str` or empty (AWS always returns it) is excluded by `owned_vpcs` and produces no row; a flow log whose `ResourceId` is missing or non-`str` is ignored. `self.account_id` comparisons need no normalization: both are 12-digit strings.

**Model-backed, not observed.** The probe saw `FlowLogs: []` in every account and Region, so the PASS-arm facts — a VPC-level flow log's `ResourceId` equals the `VpcId`, and a healthy flow log reads `FlowLogStatus: "ACTIVE"` — come from the botocore model and the API reference, not from a response. Live Phase 4 saves the raw `describe-flow-logs` response after the mutation to `.tmp/sratester/ec2-02-phase4-describe-flow-logs.json`; any field mismatch with this design is then a defect to fix, not a surprise.

**FAIL remediation:** dynamic, `f"Create a VPC flow log for {vpc_id}: aws ec2 create-flow-logs --resource-type VPC --resource-ids {vpc_id} --traffic-type ALL --log-destination-type s3 --log-destination <bucket-arn> --region {region}"`. `meta.remediation.text`: `Create a VPC-level flow log for every VPC, delivered to the Log Archive account.`; cli: the same command with placeholders.

**CheckMeta:** title `VPC Flow Logs are enabled for every VPC`; `MEDIUM`; `APPLICATION`; service `EC2`; resource type `AWS::EC2::VPC`; check_logic `For each Region list VPCs owned by the account and all flow logs. Passes per VPC with an ACTIVE flow log whose ResourceId is the VPC. A Region with no owned VPC passes once.`; sra_sections `("Application account", "Amazon VPC Flow Logs")`; additional_urls: the config-validation URL, `https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html`.

### SRA-ROUTE53RESOLVER-01 — Resolver query logging for every VPC

**Package:** `services/route53resolver/` per the module inventory. `__init__.py`:

```python
"""Route 53 Resolver checks."""
from sraverify.core.discovery import import_check_modules
import_check_modules(f"{__name__}.checks")
```

**Client** — `Route53ResolverClient(AWSClient)`:

```python
def __init__(self, region: str, ctx: ScanContext):
    super().__init__(region, ctx)
    self.client = ctx.get_client('route53resolver', region=region)
    # The VPC inventory this service's associations are matched against. A second
    # binding rather than an import of EC2Check: no base inherits another base.
    self.ec2_client = ctx.get_client('ec2', region=region)

def list_resolver_query_log_config_associations(self) -> Mapping[str, Any]:
    ...paginator 'list_resolver_query_log_config_associations', key 'ResolverQueryLogConfigAssociations',
       return {"ResolverQueryLogConfigAssociations": [...]}...

def describe_vpcs(self) -> Mapping[str, Any]:
    ...identical to EC2Client.describe_vpcs, via self.ec2_client...
```

No `sts` binding and no `get_account_id`: the account ID comes from `self.account_id`.

**ClientAdapter table** — new `_ROUTE53RESOLVER`, added to `ADAPTERS` under `"route53resolver"`:

```python
_ROUTE53RESOLVER = (
    ClientAdapter(method="describe_vpcs", boto_service="ec2", boto_method="describe_vpcs",
                  operation="DescribeVpcs",
                  success=({"Vpcs": [{"VpcId": "vpc-1", "OwnerId": _TEST_ACCOUNT, "IsDefault": False}]},),
                  paginated=True),
    ClientAdapter(method="list_resolver_query_log_config_associations",
                  boto_service="route53resolver",
                  boto_method="list_resolver_query_log_config_associations",
                  operation="ListResolverQueryLogConfigAssociations",
                  success=({"ResolverQueryLogConfigAssociations": [
                      {"Id": "rqlca-1", "ResolverQueryLogConfigId": "rqlc-1",
                       "ResourceId": "vpc-1", "Status": "ACTIVE"}]},),
                  paginated=True),
)
```

**Base** — `Route53ResolverCheck(SecurityCheck)`, the regional base shape from `structure.md`: `NAMESPACE = "route53resolver"`, `NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {}` with a comment recording why `UnrecognizedClientException` is not declared (Req 5.10: observed only in a Region not enabled for the account, `The security token included in the request is invalid`; a scan covers enabled Regions, and elsewhere the code means a credential problem), `_setup_clients` building one wrapper per Region, a `get_client(region)` lookup, and two accessors:

| Accessor                                    | Client method                                 | Cache key                                | no-client result                                               |
| ------------------------------------------- | --------------------------------------------- | ---------------------------------------- | -------------------------------------------------------------- |
| `get_vpcs(region)`                          | `describe_vpcs`                               | `vpcs:{region}`                          | `no_client_result(service="Route 53 Resolver", region=region)` |
| `get_query_log_config_associations(region)` | `list_resolver_query_log_config_associations` | `query_log_config_associations:{region}` | same                                                           |

**AccessorAdapter rows** (`"route53resolver"`): `A("get_client", "client_lookup", args=(_TEST_REGION,))`, and two `accessor` rows with the client methods and cache keys above.

**Logic:** identical in structure to `SRA-EC2-02`, with `region_rid = f"route53resolver:{region}:{self.account_id}"` and its own copy of the `owned_vpcs` static helper (no import across service packages). Active associations are built with the same guards:

```python
for a in assocs.get("ResolverQueryLogConfigAssociations") or []:
    if not isinstance(a, dict):
        continue
    rid = a.get("ResourceId")
    if a.get("Status") == "ACTIVE" and isinstance(rid, str) and rid:
        active.setdefault(rid, []).append(str(a.get("ResolverQueryLogConfigId")))
```

PASS names the sorted `ResolverQueryLogConfigId` values; ownership of the configuration is not consulted (Req 5.5); FAIL `No active Resolver query logging association` + ` (default VPC)`. The associations call is issued only after `DescribeVpcs` yielded at least one owned VPC (Req 5.7).

**Model-backed, not observed.** The probe saw `ResolverQueryLogConfigAssociations: []` everywhere, so `ResourceId == VpcId` and `Status: "ACTIVE"` on a healthy association come from the model. Live Phase 4 saves the raw `list-resolver-query-log-config-associations` response to `.tmp/sratester/route53resolver-01-phase4-associations.json`.

**FAIL remediation:** dynamic, `f"Associate a Resolver query logging configuration with {vpc_id}: aws route53resolver associate-resolver-query-log-config --resolver-query-log-config-id <id> --resource-id {vpc_id} --region {region} (create one first with aws route53resolver create-resolver-query-log-config --name <name> --destination-arn <arn>)"`. `meta.remediation.text`: `Create a Resolver query logging configuration, ideally shared from the Log Archive account, and associate it with every VPC.`

**CheckMeta:** title `Route 53 Resolver query logging is enabled for every VPC`; `MEDIUM`; `APPLICATION`; service `Route 53 Resolver`; resource type `AWS::EC2::VPC`; check_logic `For each Region list VPCs owned by the account and Resolver query log config associations. Passes per VPC with an ACTIVE association. A Region with no owned VPC passes once.`; sra_sections `("Application account", "Amazon Route 53 Resolver DNS query logging")`; additional_urls: the config-validation URL, `https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs.html`.

## Key decisions

**Decision 1 — the SIR EventBridge accessor caches under the module namespace, classified `derived`.** Three options: add `NAMESPACE` to the SIR base (forbidden by an explicit test guarding a known deferral, and would mislead the accessor harness about the other derived methods); leave the accessor uncached (Req 2.2 asks for a cached accessor, and `SRA-SECURITYINCIDENTRESPONSE-07` is the only caller so the cost is zero today, but the base's documented pattern is `_CACHE_NAMESPACE`); or cache under `_CACHE_NAMESPACE`. The third matches the base's existing caching site, satisfies Req 2.2, and its contract is held by a dedicated test rather than lost to the `derived` exclusion.

**Decision 2 — rule-pattern parsing lives in a static helper that catches `(TypeError, ValueError)` only.** `EventPattern` is customer-shaped JSON in general; Req 2.4 requires no raise on bad input. The no-`except`-in-`execute()` rule is about AWS failures reaching `failed()`; a parse helper outside `execute()` is the precedent `CloudTrailCheck.parse_delivery_time` set.

**Decision 3 — single-selector coverage for CLOUDTRAIL-15, exactly as Req 3.4/3.5 specify.** Two selectors that together record read and write management events (one `ReadOnly`, one `WriteOnly`; or advanced `readOnly=true` + `readOnly=false`) technically cover everything but would FAIL. That configuration was not observed, is unusual (it doubles the selector budget for no gain), and a union rule adds logic that cannot be validated live without mutating the Control Tower trail. Kept per the requirement. The FAIL text for the basic split case says exactly what was found ("split across selectors … no single selector records both"), so an operator who deliberately runs that configuration can recognise it rather than chase a missing control. Recorded under Open Questions.

**Decision 4 — `route53resolver` issues its own `DescribeVpcs`.** Req 5.4 forbids importing another base, and `test_layering_property.py` forbids a base inheriting anything but `SecurityCheck`. The alternatives — a core VPC provider like `OrganizationsProvider`, or reading the `ec2` namespace by key — are a new cross-cutting abstraction or a by-key read of another service's cache. The cost is one extra `DescribeVpcs` per Region per scan when both checks run, which is bounded and cheap. The duplicated four-line client method is the price.

**Decision 5 — no availability lookup in SIR-07 or ROUTE53RESOLVER-01 (Req 2.9 and 5.11, amended in this revision).** Measured against the project venv's botocore 1.43.105, and re-measured by the design review: `events` and `route53resolver` have endpoints in 34/34 `aws` Regions, 2/2 `aws-us-gov` and 2/2 `aws-cn` — identical to `ec2`. `service_available_in_region` can therefore never return `False` for a Region a scan covers, so a guard would be dead code. `test_availability_property.py` also admits a call-site literal only from `_CANDIDATE_SERVICE_IDS`, and its `_REJECTED_SERVICE_IDS` records the rule that full-coverage services are rejected (`accessanalyzer`, 34/34, "the lookup would never answer False"). The requirements now say the checks SHALL NOT call the lookup, citing those numbers. If botocore one day ships a Region without either service, a call there fails and yields an honest ERROR row, the fail-open direction the lookup itself prefers. Property 20 holds it: neither module references `service_available_in_region`, and `_CANDIDATE_SERVICE_IDS` is unchanged.

**Decision 6 — Region-level ResourceIds are `<service>:<region>:<account_id>`.** It satisfies "identifies the account and Region" (Req 2.10, 4.11) and stays identical across PASS/FAIL/ERROR for that Region. Per-VPC rows use the bare VPC ID. A Region whose owned-VPC set is empty uses the Region key; when a VPC is later created, that Region's key changes from Region to VPC IDs — an inherent consequence of Req 4.7 and not a status change of one row.

## Data models

Responses the checks read (only the fields consulted):

| Operation                                | Fields read                                                                                                                                                                                                 |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GetRole`                                | `Role.Arn`                                                                                                                                                                                                  |
| `ListRules`                              | `Rules[].Name`, `.State`, `.ManagedBy`, `.EventPattern` (JSON string)                                                                                                                                       |
| `DescribeTrails` (filtered)              | `trailList[].TrailARN`, `.HomeRegion`, `.IsOrganizationTrail`                                                                                                                                               |
| `GetEventSelectors`                      | `EventSelectors[].IncludeManagementEvents`, `.ReadWriteType`, `.ExcludeManagementEventSources`; `AdvancedEventSelectors[].FieldSelectors[].Field`, `.Equals`, `.NotEquals`, `.StartsWith`, `.NotStartsWith` |
| `DescribeVpcs`                           | `Vpcs[].VpcId`, `.OwnerId`, `.IsDefault`                                                                                                                                                                    |
| `DescribeFlowLogs`                       | `FlowLogs[].FlowLogId`, `.ResourceId`, `.FlowLogStatus`, `.TrafficType`                                                                                                                                     |
| `ListResolverQueryLogConfigAssociations` | `ResolverQueryLogConfigAssociations[].ResourceId`, `.Status`, `.ResolverQueryLogConfigId`                                                                                                                   |

Every field of an AWS response is read with `.get()` and type-checked before use, exactly as the normative snippets in each check section show; a missing, `None` or wrong-typed field never raises. Missing or non-`str` `Name` on a managed rule renders as `<unnamed>`; a VPC without a non-empty `str` `VpcId` produces no row; a flow log or association without a `str` `ResourceId` is ignored; a list element that is not a `dict` is ignored. Only the Error_Result's `Operation`/`Code`/`Message` are indexed directly, because `error_result()` guarantees them.

### Row multiplicity per execution

| Check              | Rows                                                                                                                                                      |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SIR-06             | exactly 1                                                                                                                                                 |
| SIR-07             | exactly `len(regions)`                                                                                                                                    |
| CLOUDTRAIL-15      | 1 if the trail list errored, or if no organization trail carries both a non-empty `TrailARN` and `HomeRegion` (the no-org-trail FAIL); else `len(usable)` |
| EC2-02             | Σ over Regions of `1` (VPC listing error, or no owned VPC) else `len(owned_vpcs)`                                                                         |
| ROUTE53RESOLVER-01 | same as EC2-02                                                                                                                                            |

## Error handling

| Failure                                                                                                 | Where        | Recoverable  | Caller receives                                                                   | Logged                                                  |
| ------------------------------------------------------------------------------------------------------- | ------------ | ------------ | --------------------------------------------------------------------------------- | ------------------------------------------------------- |
| `ClientError` / `BotoCoreError` on any new client call, any page                                        | client       | yes, per row | error result via `aws_error`; never cached                                        | one `aws_call_failed` at `debug`                        |
| No wrapper for Region (`ec2`, `route53resolver` accessors; CloudTrail `HomeRegion` outside `--regions`) | base         | yes, per row | `no_client_result` (`NoClient`), never cached                                     | `warning` at the accessor (suppressed by default level) |
| `GetRole` `NoSuchEntity`                                                                                | check        | n/a          | FAIL via `is_not_configured`                                                      | `debug` only                                            |
| `GetEventSelectors` `TrailNotFoundException`                                                            | check        | n/a          | FAIL for that trail                                                               | `debug` only                                            |
| Any other error result                                                                                  | check        | n/a          | ERROR row, `ActualValue` names operation and code, `_remediation_for` remediation | `debug` only                                            |
| Malformed `EventPattern`                                                                                | check helper | n/a          | rule counts as neither type                                                       | none                                                    |
| Missing / `None` / wrong-typed response field (`Name`, `VpcId`, `ResourceId`, list element)             | check        | n/a          | `<unnamed>`, or the element is skipped; never an exception                        | none                                                    |
| Identity / Region-list failure                                                                          | ScanContext  | per check    | `ScanPreconditionError` → one precondition row from the orchestrator              | existing                                                |
| Programming defect (`AttributeError`, `KeyError`)                                                       | anywhere     | no           | one synthetic ERROR row from `run_checks` (gate metric, expected 0)               | `error`, `exc_info`                                     |

No new call site logs at `error`. Fan-out failures (`DescribeFlowLogs`, `ListResolverQueryLogConfigAssociations`) emit one ERROR row per owned VPC and `continue` to the next Region; nothing returns early above a per-resource loop.

## Validation of external inputs

The checks take no new CLI input. `--regions`, `--audit-account` and `--log-archive-account` are already validated by the CLI; none of the five reads the account lists. AWS response fields are untrusted shapes: every read is `.get()` with type tolerance (Decision 2, `management_event_gap`), so an unexpected shape produces a FAIL reason or a "neither" classification, never an exception.

## IAM and deployment

`util/generate_iam_policy.py --base-dir .` will attribute the new calls from the `__init__` bindings: `ec2:DescribeVpcs`, `ec2:DescribeFlowLogs` (EC2Client and Route53ResolverClient), `route53resolver:ListResolverQueryLogConfigAssociations`, plus the already-granted `events:ListRules`. In `1-sraverify-member-roles.yaml`, `SRAVerifyLeastPrivilege`:

- `Ec2Permissions` gains `ec2:DescribeFlowLogs` and `ec2:DescribeVpcs` (alphabetical with the existing four);
- a new statement between `OrganizationsPermissions` and `S3Permissions`:

```yaml
          - Sid: Route53resolverPermissions
            Effect: Allow
            Action:
              - route53resolver:ListResolverQueryLogConfigAssociations
            Resource: '*'
```

The Sid follows the generator's `service.capitalize()` rule. The policy document is 5,338 characters minified today (measured with `json.dumps(document, separators=(",", ":"))` over the template's `PolicyDocument`); the additions should bring it to roughly 5,500. The ceiling is the IAM quota "Managed policy size … 6,144 characters" (<https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html>; IAM does not count whitespace), and `validate-template` does not check it, so implementation step 5 measures the edited document the same way and asserts it is under 6,144 before `validate-template` runs. If it is not, the change stops there: splitting the policy is a design change, not an implementation detail. No other action is added (Req 7.1); `SRAVerifyCheckPermissions` is untouched. Validation: `aws cloudformation validate-template`, `simulate-custom-policy` on the edited document, then StackSet + management-stack deploy and `simulate-principal-policy` on `SRAMemberRole` before the CodeBuild run (Req 7.3, 8.5).

## Documentation and count updates

| Item                                                                       | Before                                               | After                                              |
| -------------------------------------------------------------------------- | ---------------------------------------------------- | -------------------------------------------------- |
| Checks                                                                     | 182                                                  | 187                                                |
| Services                                                                   | 18                                                   | 19                                                 |
| Client methods                                                             | 96 (86 across 17 service clients + 10 Organizations) | 101 (91 across 18 service clients + 10)            |
| Per-service: securityincidentresponse / cloudtrail / ec2 / route53resolver | 5 / 14 / 1 / —                                       | 7 / 15 / 2 / 1                                     |
| Client modules seen by the IAM generator test                              | 18                                                   | 19                                                 |
| `_NON_OWNED_NOT_CONFIGURED_ENTRIES`                                        | 46 rows                                              | 46 rows, SIR `GetRole` hash updated                |
| Test totals                                                                | 10080 passed / 1239 skipped (branch baseline)        | measured after implementation; written as measured |

`product.md`: the "Currently N checks" line with the re-sorted per-service list (guardduty 26, securityhub 20, securitylake 17, cloudtrail 15, shield 14, organizations 12, inspector 11, config 10, firewallmanager 10, macie 10, waf 9, accessanalyzer 8, securityincidentresponse 7, iam 6, s3 4, account 3, auditmanager 2, ec2 2, route53resolver 1) and a new bullet describing the five checks and their SIR config-validation origin. `structure.md`: 182 → 187 (four sites), 96/86/17 → 101/91/18 (four sites), the test totals, the 46-row golden sentence unchanged. `tech.md`: test totals and the skip count with its explanation, and the three new member-role actions under the "deploy the member role first" paragraph. `creating_checks_best_practices.md`: 182 → 187 (two sites). `sraverify/README.md` and `README.md`: the lines in the Edited files table.

**Regeneration runs from the worktree, never the main checkout.** The main checkout's `sra-verify/sraverify/.venv` imports the main tree (182 checks), so a `cmp` between two runs of it would pass with the wrong inventory. The worktree has its own `sraverify/.venv` (editable install of the worktree package). From the worktree root (`.worktrees/sir-log-readiness-checks/`):

```bash
sraverify/.venv/bin/sraverify --list-checks > docs/checks.txt
sraverify/.venv/bin/sraverify --list-checks | cmp - docs/checks.txt
test "$(grep -cE '^  SRA-[A-Z0-9]+-[0-9]{2}:' docs/checks.txt)" -eq 187
grep -E '^  SRA-(SECURITYINCIDENTRESPONSE-0[67]|CLOUDTRAIL-15|EC2-02|ROUTE53RESOLVER-01):' docs/checks.txt | wc -l   # 5
```

The `grep -cE` pattern returns 182 on the current file, so the 187 assertion is calibrated. The IAM generator is likewise run from the worktree: `cd sraverify && uv run python ../util/generate_iam_policy.py --base-dir .` (`uv run` resolves the worktree's `sraverify/.venv`), with stderr captured to `.tmp/sratester/iam-generator.stderr` and asserted empty.

**Closing gate for the count sweep**, run from the worktree root after every edit above:

```bash
grep -rniE --include='*.py' "eighteen|\b18 (service|client)|all 18\b|\b17 (service|client|\`\`services)" sraverify/sraverify/tests util
grep -rnE --include='*.py' "\b92\b" sraverify/sraverify/tests
grep -nE '\b(158|182)\b|\b96 client|\b17 (service|`services)|\b18 (AWS )?services' sraverify/README.md README.md
```

The first is case-insensitive, so it sees "All 18" at `test_client_contract_property.py` l.1173, and it covers the `17 ``services` form at l.1673. After the edits it must return exactly three lines: `test_check_classification_property.py:551` ("Twelve of the eighteen declared pairs") and `test_service_migration_property.py:8` and `:27` ("the 17 service base classes"), the sites left alone by the comment rule above. Calibrated on the current tree, it returns those three plus only sites that the Edited files table lists (every prose `18`/`17`/`eighteen` site there; the table's code literals such as `len(modules) == 18` are outside the pattern and are covered by the tests they sit in), including the test *names* `test_eighteen_services_are_discovered` (×2), `test_exactly_eighteen_service_subpackages_are_discovered` and `test_eighteen_services_declare_a_table_attribute`, which the renames remove. The second must return nothing after the edits; today it returns exactly the eleven `92` sites in the Edited files table (`test_client_contract_property.py` l.6, l.13, l.14, l.1241, l.1405, l.1408, l.1746, l.1845; `test_aws_client.py` l.5, l.645, l.686). The third must return nothing (calibrated on the current tree: it returns `sraverify/README.md` l.10, 234, 617, 1078, 1094 and `README.md` l.5, exactly the README sites in the Edited files table; l.817's "17-region scan" does not match). `--include='*.py'` keeps `__pycache__` binaries out of the result. Any other hit after the edits is a missed site and is fixed before the commit.

**Declared out of scope: pre-existing `158` drift in tests.** About twenty test comments and docstrings say "158 checks" on a line that names no service or client count (for example `test_select.py` l.35/42, `test_no_accumulator_property.py` l.18, `test_check_classification_property.py` l.235, `test_no_confessing_fail_property.py` l.102/123, `test_registry_bijection_property.py` l.53, `test_catalog_identity_property.py` l.77, `test_unknown_check_exit_property.py` l.253, `test_select_no_instantiation_property.py` l.19). They were already wrong at 182 checks, before this change, so they are not edited here: correcting them is a separate drift fix, and folding it in would bury this change's count edits in unrelated ones. `grep -rnE --include='*.py' "\b158\b" sraverify/sraverify/tests` lists them. A `158` that shares a sentence with an edited count is corrected with it: `test_select.py` l.75, `test_availability_property.py` l.122, `test_registry_bijection_property.py` l.95 and l.415, `test_catalog_identity_property.py` l.115–116, and `test_catalog_meta_property.py` l.758–759 ("walks 18 service packages and executes / 158 check class bodies" → "19 … / 187").

The skip count changes because `test_a_declared_semantic_error_result_reaches_failed` parametrizes over each check × declared pair; five new checks add the provider's four pairs each plus their services' table pairs. The exact number is taken from the run, not predicted.

## Testing Strategy

**Unit tests** — `tests/unit/services/test_sir_log_readiness_checks.py`, following `tests/unit/services/test_inspector_batching.py`. A bare `MagicMock` context will not do: its `account_id` would be a `MagicMock`, which `Finding` rejects as non-`str`. Each test builds a real context and patches only the identity lookup and the accessors:

```python
ctx = ScanContext(session=MagicMock(name="session"), regions=["us-east-1", "us-west-2"])
with patch.object(ScanContext, "get_account_info",
                  return_value={"account_id": "111122223333", "account_name": "test"}):
    check = SRA_EC2_02()
    check.initialize(ctx)
    with patch.object(EC2Check, "get_vpcs", side_effect=...), \
         patch.object(EC2Check, "get_flow_logs", side_effect=...) as flow_logs:
        rows = list(check.execute())
```

Accessors are patched on the base class with `patch.object`, returning canned success dicts or `error_result(...)`. No AWS call is possible (conftest refuses HTTP). Cases:

- SIR-06: success → PASS with `Role.Arn`; `NoSuchEntity` → FAIL with the expected ARN; `AccessDenied` → ERROR; `EndpointConnectionError`-shaped result → ERROR; exactly one row, `global`.
- SIR-07: both rules ENABLED → PASS; management-account shape (no managed rules) → FAIL naming both missing; GuardDuty only → FAIL naming Security Hub; one rule `DISABLED` → FAIL naming it and its state; a customer rule named `SIRGuardDutyRule` without `ManagedBy` → not counted; invalid / absent `EventPattern` → counted as neither, no raise; `ListRules` error in one of two Regions → one ERROR + one verdict row; ResourceId identical across the three states. Malformed shapes, each yielding exactly one non-synthetic row per Region: a managed rule with no `Name` (renders `<unnamed>`), `Name: None`, no `State`, `Rules: None`, and a non-dict element in `Rules`.
- CLOUDTRAIL-15: observed CT baseline → PASS; `IncludeManagementEvents: false`; `ReadOnly` → `Only ReadOnly management events are recorded`; one `ReadOnly` + one `WriteOnly` including selector → the split-selector text; excluded `["rdsdata.amazonaws.com","kms.amazonaws.com"]` → FAIL listing them sorted; advanced Management selector → PASS; advanced with one `readOnly Equals ["true"]` management selector → `Only read-only management events are recorded`; advanced with one `readOnly Equals ["false"]` → `Only write management events are recorded`; advanced with two management selectors, `readOnly Equals ["true"]` and `readOnly Equals ["false"]` → `Read and write management events are split across advanced selectors (readOnly = false, true); no single selector records both`; advanced with `eventSource NotEquals`; advanced with only Data selectors; **a covering basic selector alongside a non-empty, non-covering advanced list → advanced reason 1** (precedence); both lists absent → basic reason 1; no org trail → one FAIL `organization/<id>`; two org trails, one missing `TrailARN` → one row for the other; every org trail missing `TrailARN` or `HomeRegion` → the same single `organization/<id>` FAIL; `DescribeTrails` error → one ERROR; `TrailNotFoundException` for one of two trails → FAIL + verdict row; other selector error → ERROR + continue.
- EC2-02 and ROUTE53RESOLVER-01 (shared parametrized fixtures): owned VPC with ACTIVE log/association → PASS naming it; none → FAIL; default VPC → FAIL text notes it; subnet-level flow log → still FAIL; `FlowLogStatus: ERROR` / association `FAILED` → FAIL; RAM-shared VPC (`OwnerId` other) → no row; no owned VPC → one PASS and the second accessor never called; `DescribeVpcs` error → one Region ERROR; second listing error with three VPCs → three ERROR rows with VPC IDs; config ownership ignored for Resolver. Malformed shapes, none raising: a VPC with no `VpcId`, `VpcId: None` and `VpcId: ""` (no row for it; the other VPCs unaffected); `Vpcs: None`; a flow log / association with no `ResourceId` and with `ResourceId: None` (ignored); a non-dict element in each list.
- The five FAIL remediation commands are asserted to contain the command named in Req 1.7, 2.11, 3.11, 4.12, 5.13.
- Neither `sra_securityincidentresponse_07.py` nor `sra_route53resolver_01.py` (nor either base) contains the name `service_available_in_region`, read from source (Req 2.9, 5.11).

Hypothesis is used for the pure helpers: `event_sources` never raises over `st.one_of(st.none(), st.text(), json-encoded st.recursive(...))`. `management_event_gap` never raises over arbitrary responses built from the field vocabulary (either list absent, empty or populated; elements possibly non-dict). With `evaluated = AdvancedEventSelectors if non-empty else EventSelectors`: inserting a covering selector of the evaluated list's form into the **evaluated** list returns `None`; and whenever no element of the evaluated list covers, it returns a non-`None` reason, whatever the other list holds.

**Contract suites** pick the new code up by reflection once the adapter rows exist: client contract (5 new methods through four failure kinds), accessor cache (4 new `accessor` rows, 1 `derived` SIR row plus its dedicated test, 1 `client_lookup`), check classification (every accessor failing → only ERROR rows naming operation and code, for all 187 checks; the declared `NoSuchEntity` reaches `failed()` for SIR-06), discriminator (route53resolver's empty table; golden), confessing-fail and layering (AST over the new modules), registry bijection and catalog identity (187 / 19).

**Integration (live)** — Req 8, per `testing_checks.md`; not unit-testable. Profiles and account IDs come from `sratester/accounts.md` and `aws sts get-caller-identity` at run time; none is written into a tracked file. Before any mutation, every resource named below that already exists is written byte for byte to `.tmp/sratester/snapshot.json`, and each created resource's identifier is appended to it as it is created, so the restoration script can prove both "what existed is unchanged" and "what was created is gone". Each check's sequence is one script, run strictly sequentially; checks touching different accounts may run in parallel. `<ts>` is a UTC timestamp fixed at script start.

**SRA-SECURITYINCIDENTRESPONSE-06** (Req 1.7) — log-archive account, which is not the SIR delegated administrator, run as `--account-type audit --check SRA-SECURITYINCIDENTRESPONSE-06`.

1. Snapshot: `aws iam get-role --role-name AWSServiceRoleForSecurityIncidentResponse` → expected `NoSuchEntity` (observed in the probe).
2. Phase 1 baseline: FAIL, `ResourceId` the expected SLR ARN. Also run against the audit account (the DA) → PASS. Both verdicts are thereby seen without mutating the DA.
3. Phase 4: run the FAIL row's remediation, `aws iam create-service-linked-role --aws-service-name security-ir.amazonaws.com`, in log-archive. Save the response. Phase 5: re-run → PASS with the returned ARN.
4. Restore: `aws iam delete-service-linked-role --role-name AWSServiceRoleForSecurityIncidentResponse` → `DeletionTaskId`; poll `aws iam get-service-linked-role-deletion-status --deletion-task-id <id>` every 10 s, up to 5 min, until `SUCCEEDED`; then `get-role` → `NoSuchEntity`.
5. Fallback: if `create-service-linked-role` is refused in a non-DA account, record the error verbatim, mark the Phase 4 arm 🔄, and amend Req 1.7 to state that the command is accepted only in the delegated administrator (where it already exists). If deletion reports `FAILED`, record the `Reason` verbatim, mark restoration of the log-archive SLR as unverified in the report, and leave the role in place for manual follow-up. No claim is made about what Security Incident Response does with the role in a non-DA account; nothing observed or documented establishes it.

**SRA-SECURITYINCIDENTRESPONSE-07** — codeprod, one Region (us-east-1). The missing-rule arms need no mutation: baseline PASS in codeprod and FAIL in the management account (natural, all 17 Regions). The disabled-rule arm is attempted, because `sratester/accounts.md` gives the explicit sign-off Req 8.2 asks for on a service-managed SIR rule as a standing instruction (the organization-trail sign-off in Req 8.2 is separate and is requested at the time; see SRA-CLOUDTRAIL-15) ("No additional sign off is required … You don't have any restrictions on mutating actions"):

1. Snapshot: `aws events describe-rule --name SIRGuardDutyRule --region us-east-1` and `list-targets-by-rule --rule SIRGuardDutyRule` into `snapshot.json`.
2. Phase 2: `aws events disable-rule --name SIRGuardDutyRule --region us-east-1`. Save the response or error to `.tmp/sratester/sir07-disable-rule.json`.
3. If refused (a managed rule is expected to answer `ManagedRuleException`, not observed yet), record the code and message verbatim and mark the disabled-rule arm 🔄 citing that observed error; it stays covered by unit tests.
4. If accepted: Phase 3 run `--check SRA-SECURITYINCIDENTRESPONSE-07 --regions us-east-1` → FAIL `SIR-managed rules not ENABLED: SIRGuardDutyRule (DISABLED)`. Phase 4: `aws events enable-rule --name SIRGuardDutyRule --region us-east-1` (accepted the same way the disable was). Phase 5 → PASS. The restoration script compares `describe-rule` `State`, `EventPattern` and the target list with the snapshot.

**SRA-CLOUDTRAIL-15** — management account. The Control Tower trail is never touched (Out of Scope 11). The plan runs every read-only arm first and creates an organization trail only after the user signs off on it at the time (Req 8.2): an organization trail is billable organization-wide, because it delivers a second copy of management events for every account, and `sratester/accounts.md`'s standing permission does not cover that.

Read-only arms (no mutation, no sign-off):

1. Snapshot: `aws cloudtrail describe-trails --include-shadow-trails --region us-east-1` with the management profile, and `get-event-selectors` for every trail it lists, to `snapshot.json`.
2. Baseline: `--account-type management --check SRA-CLOUDTRAIL-15 --regions us-east-1,us-west-2` → PASS `Organization trail logs all read and write management events from every event source` on `aws-controltower-BaselineCloudTrail`, and **no row** for the existing non-organization trail `IsengardTrail-DO-NOT-DELETE` (probe: `IsOrganizationTrail: false`). That pair is the live evidence for Req 3.3's one-row-per-organization-trail rule; it already exists, so no single-account trail is created for it.
3. Home Region not scanned: the same command with `--regions us-west-2` → one ERROR row on the Control Tower trail whose `ActualValue` names `NoClient` (its `HomeRegion` us-east-1 has no client). This is the existing `SRA-CLOUDTRAIL-14` behaviour and is the testing_checks.md "home-Region guard" negative run.
4. Wrong account type: the codeprod profile with `--account-type management --check SRA-CLOUDTRAIL-15 --regions us-east-1`. Expected, not observed: `describe-trails` in a member account lists the organization trail with `IsOrganizationTrail: true`. Whatever `GetEventSelectors` answers there is recorded verbatim to `.tmp/sratester/ct15-codeprod.csv` and its stderr: a PASS, a `TrailNotFoundException` FAIL (Req 3.10's declared arm), or an ERROR, each explained in the report. No verdict is predicted.

A single-account, non-organization trail is **not** used for the FAIL arm, and this is a fact about the check rather than a preference: `get_organization_trails` keeps only `IsOrganizationTrail: true`, so such a trail produces no row at all — which step 2 already shows with the existing non-organization trail. The coverage-gap FAIL text of Req 3.7 is therefore reachable live only through a temporary organization trail, and every one of its texts is held by the unit cases regardless.

Organization-trail arm (sign-off gated):

5. **Pause for sign-off.** Before creating anything, the implementer calls `send_message` with severity `warning` and waits. The message states: the action (a single-Region, never-started organization trail `sraverify-ct15-<ts>` in the management account, us-east-1, with management events excluded, plus its bucket `sraverify-ct15-<acct>-<ts>`); the cost (an extra organization trail is billable organization-wide, as a second copy of management events for every account; this one is never started and `IsLogging` is asserted `false` before any scan, but no claim is made that it therefore costs nothing); the side effects (its copy appears in every member account while it exists, and other management-account CloudTrail checks would FAIL its row if run, which the scans here never do); and the restoration (`delete-trail`, bucket deletion, verified from the management account and from codeprod). On anything other than explicit approval — a decline, or a request to skip — steps 6–10 are not run, and the report marks the coverage-gap FAIL arm 🔄 with the reason "requires a temporary organization trail; sign-off not given; covered by unit tests". The rest of the live run continues meanwhile only for the other checks; nothing in this sequence proceeds past step 5 without the answer.
6. Create bucket `sraverify-ct15-<acct>-<ts>` in us-east-1, block public access on, and apply the organization-trail bucket policy from the CloudTrail user guide ("Amazon S3 bucket policy for CloudTrail", organization-trail variant): `cloudtrail.amazonaws.com` granted `s3:GetBucketAcl` on the bucket and `s3:PutObject` on `AWSLogs/<mgmt-acct>/*` and `AWSLogs/<org-id>/*` with `s3:x-amz-acl = bucket-owner-full-control`, each with `aws:SourceArn = arn:aws:cloudtrail:us-east-1:<mgmt-acct>:trail/sraverify-ct15-<ts>`. No KMS key: SSE-S3 default encryption is enough for a trail that never logs.
7. `aws cloudtrail create-trail --name sraverify-ct15-<ts> --s3-bucket-name <bucket> --is-organization-trail --no-is-multi-region-trail --region us-east-1`, then `put-event-selectors --trail-name <arn> --event-selectors '[{"ReadWriteType":"All","IncludeManagementEvents":false}]'`. **`start-logging` is never called.** Before any scan, run `aws cloudtrail get-trail-status --name <arn> --region us-east-1`, save it to `.tmp/sratester/ct15-trail-status.json`, and assert `IsLogging` is `false`. botocore documents `StartLogging` as the operation that "Starts the recording of … API calls and log file delivery for a trail" and `CreateTrail` as only specifying delivery settings; this read is what turns that into an observation. If `IsLogging` is `true`, run `aws cloudtrail stop-logging --name <arn>`, re-read, and record that `create-trail` started logging.
8. Phase 3: run `--check SRA-CLOUDTRAIL-15` → FAIL `Management events are not included` on the temporary trail's row, PASS unchanged on the Control Tower trail's row.
9. Phase 4: run the FAIL row's remediation `put-event-selectors` command against the temporary trail; Phase 5 → both rows PASS.
10. Restore: `delete-trail --name <arn>`; empty and delete the bucket; re-read `describe-trails --include-shadow-trails --region us-east-1` in the management account and compare to the snapshot. Then run `aws cloudtrail describe-trails --include-shadow-trails --region us-east-1` with the codeprod profile, save it to `.tmp/sratester/ct15-member-trails-after.json`, and have the restoration script assert the temporary trail's ARN is absent from it.

Expected, not observed: the organization trail's copy in member accounts is removed with the trail. The restoration script confirms it from codeprod (step 10); if the ARN is still listed, the script re-reads every 30 s for up to 10 min, and a copy that outlives that is reported as unrestored with the observed output. While the trail exists, other management-account CloudTrail checks (e.g. `SRA-CLOUDTRAIL-07`, "is logging") would see a non-logging organization trail and FAIL its row; steps 8–9 run with `--check SRA-CLOUDTRAIL-15` only, so those rows are never produced. Fallback: the probe never observed AWS accepting an all-false selector set. If `put-event-selectors` rejects it, use `[{"ReadWriteType":"ReadOnly","IncludeManagementEvents":true}]` (expected FAIL `Only ReadOnly management events are recorded`). If `create-trail --is-organization-trail` itself is refused, record the error and mark the FAIL arm 🔄.

**SRA-EC2-02** (Req 4.12) — codeprod, us-east-1, one non-default VPC `<vpc>` chosen at run time.

1. Snapshot: `describe-flow-logs` (expected `[]`) and `describe-vpcs` for the Region.
2. Baseline: FAIL for every owned VPC.
3. Create bucket `sraverify-ec202-<acct>-<ts>` in codeprod us-east-1, block public access on. Phase 4: `aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc> --traffic-type ALL --log-destination-type s3 --log-destination arn:aws:s3:::<bucket> --region us-east-1` (the remediation command). The VPC User Guide page "Amazon S3 bucket permissions for flow logs" (<https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-s3-permissions.html>) documents that, for a bucket the caller owns, log delivery attaches its own bucket policy granting `delivery.logs.amazonaws.com`. Assert the response's `Unsuccessful` is `[]` and save it to `.tmp/sratester/ec2-02-create-flow-logs.json`; save `aws s3api get-bucket-policy --bucket <bucket>` to `.tmp/sratester/ec2-02-bucket-policy.json`. Fallback: if `Unsuccessful` is non-empty, record each item's `Error`, apply the policy that page documents explicitly (`delivery.logs.amazonaws.com` granted `s3:PutObject` on `arn:aws:s3:::<bucket>/AWSLogs/<acct>/*` with `s3:x-amz-acl = bucket-owner-full-control`, and `s3:GetBucketAcl` / `s3:ListBucket` on the bucket, each conditioned on `aws:SourceAccount = <acct>`), and retry `create-flow-logs` once; a second failure marks the PASS arm 🔄 with the recorded error. Save `describe-flow-logs` to `.tmp/sratester/ec2-02-phase4-describe-flow-logs.json`. Phase 5: PASS for `<vpc>` only; every other VPC row unchanged.
4. Restore: `delete-flow-logs --flow-log-ids <id>`; poll `describe-flow-logs` until it is gone; empty and delete the bucket (which removes the policy log delivery added).

**SRA-ROUTE53RESOLVER-01** (Req 5.13) — same account, Region and `<vpc>`.

1. Snapshot: `list-resolver-query-log-configs` and `list-resolver-query-log-config-associations` (both expected empty).
2. Baseline: FAIL for every owned VPC.
3. Create bucket `sraverify-r53r01-<acct>-<ts>`. `aws route53resolver create-resolver-query-log-config --name sraverify-r53r01-<ts> --destination-arn arn:aws:s3:::<bucket> --creator-request-id <ts>`. Phase 4: The Route 53 Developer Guide page "AWS resources that you can send Resolver query logs to" (<https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs-choosing-target-resource.html>) documents the S3 destination permissions. Whether the service attaches a bucket policy itself is not assumed; the saved policy is the observation, and `ACTION_NEEDED` (below) is the modelled signal that the destination was not writable. Save `aws s3api get-bucket-policy --bucket <bucket>` after `create-resolver-query-log-config` to `.tmp/sratester/route53resolver-01-bucket-policy.json`. Phase 4: `associate-resolver-query-log-config --resolver-query-log-config-id <id> --resource-id <vpc>` (the remediation command); poll `get-resolver-query-log-config-association` every 10 s, up to 5 min, and stop on the first terminal `Status`: `ACTIVE`, `FAILED` or `ACTION_NEEDED` (all three are values of botocore's `ResolverQueryLogConfigAssociationStatus` enum, alongside the transient `CREATING` and `DELETING`). A timeout with no terminal status is treated as `FAILED`. Save `list-resolver-query-log-config-associations` to `.tmp/sratester/route53resolver-01-phase4-associations.json`. Phase 5: PASS for `<vpc>` only.
4. Restore: `disassociate-resolver-query-log-config`; poll until the association is no longer listed (it passes through `DELETING`); `delete-resolver-query-log-config`; empty and delete the bucket.
5. Fallback: if the association reaches `FAILED` or `ACTION_NEEDED`, record its `Error`/`ErrorMessage` verbatim and disassociate it. Retry once with a CloudWatch Logs destination: `aws logs create-log-group --log-group-name /sraverify/r53r01-<ts>`, a second `create-resolver-query-log-config` with that log group's ARN, associate, and poll the same way. If the retry also fails, restore everything (both configs, the log group, the bucket) and mark the PASS arm 🔄 with both recorded errors. The log group, if created, is appended to `snapshot.json` and deleted in step 4.
6. The RAM-shared configuration case (Req 5.5, Out of Scope 9) is not exercised; the report lists it as 🔄 with that reason ("no shared query logging configuration exists in the test organization, and creating a RAM share was not attempted"). It stays covered by the unit case "config ownership ignored for Resolver".

The restoration script re-reads the IAM role, the SIR-managed rule's `State`, pattern and targets, the trail list and selectors (and, if the organization-trail arm ran, the codeprod trail list from `ct15-member-trails-after.json`), flow logs, query log configs and associations, and confirms each created bucket returns `NoSuchBucket` and any created log group is gone. Its output goes in the report.

**Evidence status of the live plan.** Every AWS behaviour a step depends on is either read back during the run (`IsLogging`, the member-account trail list after `delete-trail`, `Unsuccessful`, the two bucket policies, the association `Status`, the `disable-rule` response) or carries a fallback. The three documentation URLs above (VPC flow-log S3 permissions, Resolver query-log destinations, `ListRules`) could not be fetched while authoring this design — outbound HTTP from the authoring session timed out — so the implementer opens each before Phase 2 and records in the report that its text matches; the `ListRules` sentence is additionally confirmed verbatim from the local botocore model. A mismatch is a design defect, fixed before the step that relies on it.

## Correctness Properties

These are the invariants the unit and contract tests above assert. Each heading names one invariant; the line under it says which acceptance criteria it validates.

### Property 1: Every new check is registered with its declared metadata

For each of the five IDs, `all_checks()` contains it, its class lives in the file the stem names, `meta` carries the account type, severity, service display name and CloudFormation resource type listed in this design, and `meta.additional_urls` contains the config-validation URL. The registry holds 187 checks across 19 service packages.

**Validates: Requirements 1.1, 2.1, 3.1, 4.1, 5.1, 5.2, 6.1, 6.4**

### Property 2: SIR-06 emits exactly one global row whose status follows GetRole

For any `GetRole` result, the check yields one finding with `region == "global"`: PASS with the returned ARN on success, FAIL with the expected SLR ARN on `NoSuchEntity`, ERROR on every other error result, and never more than one row.

**Validates: Requirements 1.2, 1.3, 1.4, 1.5, 1.6, 1.8**

### Property 3: SIR-07 identifies managed rules by ManagedBy alone

For any list of rules, the rules counted are exactly those with `ManagedBy == "triage.security-ir.amazonaws.com"`; a rule's name never affects the count, and a malformed or absent `EventPattern` makes the rule count as neither type without raising.

**Validates: Requirements 2.3, 2.4**

### Property 4: SIR-07 yields one row per Region with a stable key

For any per-Region mix of success and error results, the check yields exactly `len(regions)` findings, one per Region; the row is PASS iff a GuardDuty-sourced and a Security Hub-sourced managed rule exist and all are `ENABLED`, FAIL otherwise, ERROR on an error result; and its `ResourceId` is `events:<region>:<account_id>` in all three states.

**Validates: Requirements 2.2, 2.5, 2.6, 2.7, 2.8, 2.10**

### Property 5: Management-event coverage is decided per trail by the selector rule

For any `GetEventSelectors` response, let the evaluated list be `AdvancedEventSelectors` when it is non-empty and `EventSelectors` otherwise; the other list is never consulted. `management_event_gap` returns `None` iff some element of the evaluated list covers — for `EventSelectors`, `IncludeManagementEvents` true, `ReadWriteType` `All` and no excluded sources; for `AdvancedEventSelectors`, `eventCategory Equals Management` with no `readOnly` and no `eventSource` field. Otherwise it returns a reason, it never raises, and any list of sources or selector kinds in the reason is sorted.

**Validates: Requirements 3.4, 3.5, 3.6, 3.7**

### Property 6: CLOUDTRAIL-15 row multiplicity and per-trail error isolation

The check yields one global row per organization trail carrying a non-empty `TrailARN` and `HomeRegion`, keyed by trail ARN; exactly one FAIL keyed `organization/<account_id>` when no such trail exists (including when every returned trail lacks one of the two fields); exactly one row when the trail list errors; and a selector error on one trail yields one row for that trail without affecting any other trail's row.

**Validates: Requirements 3.2, 3.3, 3.8, 3.9, 3.10**

### Property 7: VPC checks evaluate exactly the owned VPCs

For any `DescribeVpcs` result, the per-VPC rows of `SRA-EC2-02` and `SRA-ROUTE53RESOLVER-01` are in bijection with the VPCs whose `OwnerId` equals the scanned account, default VPCs included, and their `ResourceId` is the VPC ID.

**Validates: Requirements 4.4, 4.11, 5.4, 5.12**

### Property 8: A VPC passes iff an ACTIVE VPC-level log or association names it

For any flow-log list, an owned VPC is PASS iff some entry has `ResourceId` equal to its ID and `FlowLogStatus == "ACTIVE"`; subnet and ENI entries never satisfy it. For any association list, an owned VPC is PASS iff some entry has its `ResourceId` and `Status == "ACTIVE"`, independent of who owns the configuration. FAIL text notes a default VPC.

**Validates: Requirements 4.3, 4.5, 4.6, 5.5, 5.6**

### Property 9: The fan-out never collapses VPC rows

When the second listing (`DescribeFlowLogs` or `ListResolverQueryLogConfigAssociations`) errors in a Region with N owned VPCs, the check yields exactly N ERROR rows for that Region, one per VPC ID, and continues to the next Region; when `DescribeVpcs` errors it yields one Region ERROR and continues.

**Validates: Requirements 4.8, 4.9, 5.8, 5.9**

### Property 10: A Region without an owned VPC yields one PASS and no second call

When `DescribeVpcs` succeeds with no owned VPC, the check yields exactly one PASS for that Region with the Region-level `ResourceId`, and the flow-log or association accessor is never called for that Region.

**Validates: Requirements 4.7, 5.7**

### Property 11: Every new client method honours the client contract

Each of the five new client methods, driven through a `ClientError`, an `EndpointConnectionError`, a `NoCredentialsError` and a `RuntimeError` on any page, returns an error result for the first three (with the operation for `ClientError` and `Request` otherwise) and lets the `RuntimeError` propagate; on success it returns every page merged under its named key. Each acquires its boto3 client in `__init__` only.

**Validates: Requirements 4.2, 5.3, 6.2**

### Property 12: Every new accessor never caches a failure

Each new accessor returns an error result unchanged and uncached, re-issues the client call on the next request, caches a success under its namespace and key, and returns `no_client_result` when no wrapper exists (the SIR `get_event_rules` has no such path and is held by its dedicated test).

**Validates: Requirements 2.2, 4.2, 5.3, 6.3**

### Property 13: Error rows name the operation and code; declared tables are as specified

For all 187 checks, an error result from any accessor reaches `error()` with `ActualValue` matching `<Operation> failed: <Code>: `; `EC2Check` and `Route53ResolverCheck` declare empty tables; no `ListRules` entry is added; the SIR `GetRole`/`NoSuchEntity` entry's evidence cites the probe observation, and the golden pins it.

**Validates: Requirements 1.5, 2.8, 4.10, 5.10, 6.4**

### Property 14: Remediation names a runnable command

Every FAIL row's remediation from the five checks contains the concrete CLI named by its requirement (`create-service-linked-role`, the triage SLR command, `put-event-selectors` with the replace warning, `create-flow-logs --resource-type VPC`, `create-resolver-query-log-config` and `associate-resolver-query-log-config`).

**Validates: Requirements 1.7, 2.11, 3.11, 4.12, 5.13**

### Property 15: The suite is green and grows

`uv run pytest -q` reports zero failures and more than 10080 passed, with per-arm unit tests for all five checks and no AWS call.

**Validates: Requirements 6.5, 6.6**

### Property 16: Permissions grant exactly the three new actions

The generator's action set includes `ec2:DescribeVpcs`, `ec2:DescribeFlowLogs` and `route53resolver:ListResolverQueryLogConfigAssociations` and writes nothing to stderr; the template grants those three and no other new action and passes `validate-template`; simulation shows each `allowed`.

**Validates: Requirements 7.1, 7.2, 7.3**

### Property 17: Published inventory and steering agree with the code

`docs/checks.txt` is byte-identical to a fresh `sraverify --list-checks`, and every count in the steering documents matches the measured catalog, client-method and test counts.

**Validates: Requirements 7.4, 7.5**

### Property 18: Live validation sees both verdicts and leaves the org as found

Each check is observed producing PASS and FAIL (or is marked 🔄 with reason), every scan meets the `testing_checks.md` gates, the restoration script reports every snapshotted resource identical, and the CodeBuild consolidated CSV has zero ERROR rows from the five checks.

**Validates: Requirements 8.1, 8.2, 8.3, 8.4, 8.5, 8.6**

### Property 19: Delivery is clean and reviewable

The ASH scan is clean before the commit message is proposed, and the branch is pushed and submitted with `glab mr create` with a description covering changes, testing and any 🔄 arm.

**Validates: Requirements 8.7, 8.8**

### Property 20: Full-coverage services issue no availability lookup

Neither `sra_securityincidentresponse_07.py`, `sra_route53resolver_01.py`, `services/route53resolver/base.py` nor the SIR base references `service_available_in_region`, and `_CANDIDATE_SERVICE_IDS` in `test_availability_property.py` gains neither `events` nor `route53resolver`. Every scanned Region therefore receives a call and a row.

**Validates: Requirements 2.9, 5.11**

## Implementation order

1. EC2 client + accessors + adapter rows; `uv run pytest -q` green.
2. `route53resolver` package (client, base, adapters, 18 → 19 literals); green.
3. SIR client `events` binding, `get_event_rules`, adapter rows, dedicated cache test, evidence + golden hash; green.
4. The five check modules and the unit test module; 182 → 187 literals; green.
5. IAM generator run and template edit; then measure the edited `SRAVerifyLeastPrivilege` document minified (`json.dumps(document, separators=(",", ":"))`, as done for the 5,338 baseline) and assert it is under 6,144 characters (IAM quotas page); then `validate-template` and `simulate-custom-policy`.
6. `docs/checks.txt`, steering and README counts with measured test totals.
7. Live validation, report, ASH, commit, MR.

## Open questions for review

1. Decision 3 (split read/write selectors FAIL) follows Req 3.4/3.5 but can false-FAIL an unusual valid configuration; the FAIL text names the split so it is recognisable.
2. FAIL/ERROR `ResourceId` for SIR-06 hard-codes the `aws` partition, as Req 1.5 and SIR-05 do.

## Responses to the design review

### Revision 4 (round-3 review: 1 HIGH / 1 MEDIUM / 3 NIT)

| #   | Severity | Response                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| --- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1a  | HIGH     | **Addressed.** CLOUDTRAIL-15 step 10 now also reads `describe-trails --include-shadow-trails --region us-east-1` from codeprod into `.tmp/sratester/ct15-member-trails-after.json`, and the restoration script asserts the temporary ARN is absent (re-reading for up to 10 min before reporting it unrestored). The claim is reworded as "Expected, not observed"                                                                                                                                                                                                                                                                                        |
| 1b  | HIGH     | **Addressed.** The 6,144-character limit is cited to the IAM quotas page; implementation step 5 measures the edited `SRAVerifyLeastPrivilege` document minified, as for the 5,338 baseline, and asserts it is under 6,144 before `validate-template`                                                                                                                                                                                                                                                                                                                                                                                                      |
| 2   | MEDIUM   | **Addressed.** Target-set docstring and message now say 101 / 19 clients, matching the count table. Added l.1173 ("All 19") and l.1673 ("The 18 ``services/*/client.py``"). Chose to **update** every standalone `92` (nine sites in `test_client_contract_property.py` and `test_aws_client.py`, new `test_aws_client.py` row) rather than declare them drift. The first gate is now case-insensitive and covers the `17 ``services` form; a `\b92\b` gate is added; both are re-calibrated, and the expected post-edit output of the first is l.551 plus `test_service_migration_property.py` l.8 and l.27. The "proves the sweep" wording is withdrawn |
| 3   | NIT      | **Addressed.** `client_method="list_event_rules"` added to the `get_event_rules` row, with the reason; the `_OPERATION_OF_ACCESSOR` comment in `test_check_classification_property.py` (l.437–439) is updated in a new Edited files row so it stays true                                                                                                                                                                                                                                                                                                                                                                                                  |
| 4   | NIT      | **Addressed.** Advanced reason 2 branches on the sorted distinct `readOnly` values: one value gives the read-only or write text, more than one gives the advanced split text. Unit cases added for `true`, `false` and the split                                                                                                                                                                                                                                                                                                                                                                                                                          |
| 5   | NIT      | **Addressed.** ROUTE53RESOLVER-01 step 6: the RAM-shared configuration case is not exercised, and the report lists it as 🔄 with that reason                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| —   | Brief    | **Added.** Creating a temporary organization trail is billable organization-wide and now requires user sign-off requested at the time. The CLOUDTRAIL-15 plan runs read-only arms first (baseline PASS with the existing non-organization trail producing no row; home Region not scanned → ERROR; wrong account type, observed and recorded). It explains why a single-account, non-organization trail cannot reach the FAIL arm, and pauses with `send_message` severity `warning` before any organization-trail mutation. Without approval the coverage-gap FAIL arm is 🔄. `requirements.md` Req 8.2 and Out of Scope 11 are amended to match          |

### Revision 3 (round-2 review: 1 HIGH / 1 MEDIUM / 5 NIT)

| #   | Severity | Response                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| --- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1a  | HIGH     | **Addressed.** CLOUDTRAIL-15 step 3 now reads `get-trail-status` after `create-trail`, saves it to `.tmp/sratester/ct15-trail-status.json` and asserts `IsLogging: false` (with a `stop-logging` fallback). The billing-sign-off argument and the "bills nothing" claim are deleted; `accounts.md`'s standing sign-off is cited instead                                                                                                                                                                                                                                                                                                          |
| 1b  | HIGH     | **Addressed.** "The role is inert outside the DA" deleted; a `FAILED` deletion records the `Reason`, marks restoration unverified and leaves the role for manual follow-up                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| 1c  | HIGH     | **Addressed.** Cites the VPC User Guide "Amazon S3 bucket permissions for flow logs" page, asserts `Unsuccessful: []`, saves `get-bucket-policy`, and falls back to the documented `delivery.logs.amazonaws.com` policy with one retry                                                                                                                                                                                                                                                                                                                                                                                                           |
| 1d  | HIGH     | **Addressed.** Cites the Route 53 destination page, saves `get-bucket-policy`, polls until `ACTIVE`, `FAILED` or `ACTION_NEEDED` (all from botocore's status enum), applies the fallback to both failure states, and retries once with a CloudWatch Logs destination. The design does not claim the service attaches the S3 policy itself                                                                                                                                                                                                                                                                                                        |
| 1e  | HIGH     | **Addressed by citation**, the review's first option: the `ListRules` API reference sentence "If you omit this, the default event bus is used", also confirmed verbatim in the local botocore 1.43.105 `events` model. No guard is added, so Req 2.3 ("`ManagedBy`") is unchanged                                                                                                                                                                                                                                                                                                                                                                |
| —   | —        | The three doc URLs could not be fetched from the authoring session (outbound HTTP timed out). The live plan now requires the implementer to confirm each page's text before Phase 2 and record it in the report                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| 2   | MEDIUM   | **Addressed.** Both `test_eighteen_services_are_discovered` tests renamed to `test_nineteen_services_are_discovered` with "expected 19 service packages"; `test_generate_iam_policy.py` l.257; README l.234 and l.617; every listed comment site. One stated rule for comments (update anything stating the current tree size, plus a stale `158` in the same sentence); two named exemptions (`test_service_migration_property.py`'s historical 17, `test_check_classification_property.py` l.551's declared-pair count); pre-existing standalone `158` drift declared out of scope with its listing command; two calibrated closing grep gates |
| 3   | NIT      | **Addressed.** Empty header removed; the path-root sentence replaced with the review's wording                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| 4   | NIT      | **Addressed.** "Error-branch shape rule" added to the shared conventions, with the reason the VPC checks are single-arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| 5   | NIT      | **Addressed.** CLOUDTRAIL-15 evaluates `usable` trails (both fields non-empty `str`); when none is usable it yields the no-org-trail FAIL. Row-multiplicity table, Property 6 and two unit cases updated                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| 6   | NIT      | **Addressed.** The disabled-rule arm is attempted once in codeprod us-east-1 with a snapshot; 🔄 only on an observed refusal, else Phase 3/4 with `enable-rule`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| 7   | NIT      | **Addressed.** README reference corrected to l.1067                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

### Revision 2

Addressing `.agents/tasks/sir-log-readiness-checks/design-review.json` (CHANGES_REQUESTED, 0 HIGH / 6 MEDIUM / 7 NIT).

| #   | Severity | Response                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| --- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | MEDIUM   | **Addressed.** Decision 5 kept. `requirements.md` 2.9 and 5.11 amended to "SHALL NOT call the Availability_Lookup" with the 34/2/2 coverage numbers and the `_REJECTED_SERVICE_IDS` rule. Mapped to the new Property 20, with a source-reading unit test. "Unmapped criteria" and the old Open question 1 removed                                                                                                                                                                            |
| 2   | MEDIUM   | **Addressed.** One precedence statement (`selectors = Advanced if non-empty else basic`) in CLOUDTRAIL-15, cited to the `PutEventSelectors` API reference. Property 5 and the hypothesis case now quantify over the evaluated list only. New unit example: covering basic + non-covering advanced → advanced reason 1                                                                                                                                                                        |
| 3   | MEDIUM   | **Addressed.** Live plan rewritten as concrete per-check sequences: SIR-06 runs `create-service-linked-role` in Phase 4 and restores with `delete-service-linked-role` + deletion-status poll; CLOUDTRAIL-15 uses a temporary bucket with the org-trail policy and a never-started org trail (unbilled, so no billing sign-off), with explicit selector and create-trail fallbacks; EC2-02 and ROUTE53RESOLVER-01 use temporary S3 destinations. Each has a snapshot, restore and 🔄 fallback |
| 4   | MEDIUM   | **Addressed.** Every listed site is in the Edited files table with its replacement text. The SIR caching-site test is **renamed** (its name would otherwise state a falsehood); `test_eighteen_services_declare_a_table_attribute` becomes count-free; `docs/check-report.md` stays as a dated report, stated explicitly                                                                                                                                                                     |
| 5   | MEDIUM   | **Addressed.** Regeneration and the IAM generator run from the worktree's own `sraverify/.venv`, with a `cmp` and a calibrated `grep -cE` assertion of 187 rows plus the five new IDs                                                                                                                                                                                                                                                                                                        |
| 6   | MEDIUM   | **Addressed.** Normative snippets for SIR-07, EC2-02 and ROUTE53RESOLVER-01: `rule_name` with `<unnamed>`, `owned_vpcs` filtering to a non-empty `str` `VpcId`, `isinstance(ResourceId, str)` guards, non-dict elements skipped. A unit case for each malformed shape                                                                                                                                                                                                                        |
| 7   | NIT      | **Addressed.** Six `AccessorAdapter` rows                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| 8   | NIT      | **Addressed.** Renamed to `test_every_service_declares_a_table_attribute`, no count added                                                                                                                                                                                                                                                                                                                                                                                                    |
| 9   | NIT      | **Addressed.** CLOUDTRAIL-15 `DescribeTrails` arm uses the CT-14 wording; SIR-07 keeps the two-arm shape (house convention) with `EventBridge reports no default event bus in this Region`                                                                                                                                                                                                                                                                                                   |
| 10  | NIT      | **Addressed.** One value → `Only <v> …`; both → `Read and write management events are split across selectors (ReadOnly, WriteOnly); no single selector records both`                                                                                                                                                                                                                                                                                                                         |
| 11  | NIT      | **Addressed.** Unit tests build `ScanContext(session=MagicMock(), regions=[...])` with `get_account_info` patched, as `test_inspector_batching.py` does                                                                                                                                                                                                                                                                                                                                      |
| 12  | NIT      | **Addressed.** EC2-02 and ROUTE53RESOLVER-01 state the PASS-arm shapes are model-backed, not observed; Phase 4 saves the raw responses to named files under `.tmp/sratester/`                                                                                                                                                                                                                                                                                                                |
| 13  | NIT      | **No change**, as the review recommends: accepted under Req 1.5 and the SIR-05 precedent; still recorded as Open question 2                                                                                                                                                                                                                                                                                                                                                                  |
