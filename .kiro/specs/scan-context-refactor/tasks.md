# Implementation Plan: scan-context-refactor

## Overview

This plan refactors the sraverify library to introduce a `ScanContext` object that owns all per-scan state for a single `run_checks` invocation. The work is staged so the public `SRAVerify` API and the ~140 individual check files do not change. We land the `ScanContext` core, migrate the `SecurityCheck` base class with a deprecated 2-arg shim, plumb the orchestrator and CLI/MCP, then migrate the 18 service client wrappers and 17 service base classes one at a time so each is independently reviewable. Property tests for the nine consolidated correctness properties (P1–P9) are set up before the service migrations start so each migration is validated against P8 immediately. The deprecated shim is removed in a final follow-up task once all internal callers go through `initialize(ctx)`.

Throughout the migration: `SRAVerify.__init__` and `SRAVerify.run_checks` signatures must not change, and the finding format (key set produced by `create_finding`) must not change.

## Tasks

- [x] 1. Set up testing infrastructure for property-based tests
  - [x] 1.1 Add Hypothesis to dev dependencies and create test layout
    - Add `hypothesis` to `sra-verify/sraverify/requirements.txt` (or a dev/test extras section in `setup.py`)
    - Create the directory tree under `sra-verify/sraverify/sraverify/tests/` matching the design's Test layout: `unit/core/`, `unit/services/`, `unit/cli/`, `unit/mcp/`, `property/`
    - Add empty `__init__.py` files in each test package directory
    - Create a top-level `conftest.py` that silences boto3/botocore loggers during tests
    - _Requirements: 8.1, 8.2 (preserves test-able API surface)_

- [x] 2. Implement `ScanContext` core module
  - [x] 2.1 Create `sraverify/core/scan_context.py` with the `ScanContext` class
    - Define `ScanContext.__init__(session, regions=None, audit_accounts=None, log_archive_accounts=None, client_config=None, connect_timeout=None, read_timeout=None, max_attempts=None, max_pool_connections=None)`
    - Build the default `botocore.config.Config` factory: `connect_timeout=10`, `read_timeout=30`, `retries={"max_attempts": 3, "mode": "standard"}`, `max_pool_connections=50`
    - Implement override precedence: when `client_config` is supplied, use it as-is and log a debug message if individual override params were also supplied; otherwise apply each non-`None` individual override on top of the default `Config`
    - Default `audit_accounts` and `log_archive_accounts` to `[]` when `None` is passed
    - Initialize private state per the data model table: `_session`, `_explicit_regions`, `_resolved_regions=None`, `_audit_accounts`, `_log_archive_accounts`, `_client_config`, `_clients={}`, `_cache={}`, `_account_info=None`, `_management_account_id=None`, `_lock=threading.Lock()`
    - Expose typed read-only properties: `session`, `regions`, `audit_accounts`, `log_archive_accounts`, `client_config`
    - _Requirements: 1.6, 1.7, 1.8, 1.9, 1.10, 2.1, 2.2, 2.3, 2.4, 2.5_
  - [x] 2.2 Implement namespaced cache primitives
    - Add private `_get(namespace, key, default=None)`, `_set(namespace, key, value)`, `_has(namespace, key)` methods
    - Each method acquires `self._lock` for the duration of the dict access (microsecond critical section)
    - `_set` lazily creates the inner namespace dict on first write
    - Underscore-prefix all three methods so the API contract reads "service base classes only"
    - _Requirements: 1.5, 1.10, 6.1_
  - [x] 2.3 Implement `get_client` with double-checked locking and per-scan cache
    - Cache key is `(service_name, region or "__global__")`
    - On miss: release lock, construct `self._session.client(service_name, region_name=region, config=self._client_config)`, re-acquire lock, double-check cache, return cached instance if another thread populated it, else store and return ours
    - Document the thread-safety contract in the docstring: same key returns same object; underlying `session.client` may be called more than once under contention, but only one result is retained
    - _Requirements: 2.9, 2.10, 2.11, 2.12, 2.13_
  - [x] 2.4 Implement lazy typed accessors
    - `get_account_info()` — issues `sts.get_caller_identity` then `account.get_account_information`, caches `{"account_id": ..., "account_name": ...}`; preserves today's behavior of falling back to a blank `account_name` when the Account API fails; uses double-checked locking; STS failure is fatal (re-raise)
    - `get_management_account_id()` — issues `organizations.describe_organization`, caches the management account ID; uses double-checked locking; failures are propagated
    - `get_enabled_regions()` — if `_explicit_regions` is non-empty, return it; otherwise issue `ec2.describe_regions(AllRegions=False)` once, cache, and return; uses double-checked locking; failures are propagated
    - All three obtain underlying boto3 clients via `self.get_client(...)` so the `Client_Config` is applied
    - None of the three caches a failure — a transient failure followed by retry will retry the AWS call
    - _Requirements: 1.2, 1.3, 1.4_

  - [ ]* 2.5 Write property test for namespaced cache primitives
    - **Property 1: Namespaced cache primitives are correct**
    - **Validates: Requirements 1.5, 1.10, 6.1**
    - Hypothesis strategy: `lists(tuples(text(), text(), one_of(integers(), text(), lists(integers()))))` for `(namespace, key, value)` write sequences
    - Assert last-writer-wins on `_get`, `_has` matches presence, namespace isolation, fresh-ctx defaults
    - Place at `tests/property/test_scan_context_properties.py`
  - [ ]* 2.6 Write property test for lazy typed accessors
    - **Property 2: Lazy typed accessors call AWS at most once per scan**
    - **Validates: Requirements 1.2, 1.3, 1.4**
    - Parameterize over `(get_account_info, get_management_account_id, get_enabled_regions)`; for random `N` in `[1, 50]`, assert all calls return the same object and the underlying mocked boto3 method was called exactly once
  - [ ]* 2.7 Write property test for Client_Config override precedence
    - **Property 4: Client_Config override precedence**
    - **Validates: Requirements 2.4, 2.5**
    - Generate `(client_config_or_none, overrides_dict)` pairs; assert `ctx.client_config` is the supplied `Config` when given, else default merged with overrides
  - [ ]* 2.8 Write property test for client cache contract
    - **Property 5: Client cache contract**
    - **Validates: Requirements 2.1, 2.10, 2.11, 2.13**
    - Patch `session.client` to return a fresh mock per call; random sequence of `(service, region)` calls including `None` regions and concurrent calls via `ThreadPoolExecutor(max_workers=10)`; assert key→object identity, exactly one underlying call per unique key, every call received `config=ctx.client_config`, and `weakref` to clients is dead after `del ctx; gc.collect()`
    - Cap iterations at 50 because each iteration spawns threads
  - [ ]* 2.9 Write unit tests for `ScanContext` structural contracts
    - Public API allowlist test: introspect non-underscore attributes of `ScanContext`, assert exactly the documented set (Requirement 1.1)
    - Constructor identity tests: session, regions, audit_accounts, log_archive_accounts are stored verbatim (Requirements 1.6, 1.7, 2.3 sentinel identity)
    - Default `Config` values test: one assertion per documented default field (Requirement 2.2)
    - Concurrency stress test: 50 threads issuing mixed `_set`/`_get`/`_has` against shared and disjoint keys; assert no exceptions and consistent final state (Requirement 1.11)
    - Bounded-timeout reach test: patch `botocore.config.Config.__init__`; construct `ScanContext` with defaults; call `get_client('s3', 'us-east-1')`; assert recorded `Config` matches the documented defaults
    - Place at `tests/unit/core/test_scan_context_unit.py`

- [x] 3. Migrate `SecurityCheck` base class to use `ScanContext`
  - [x] 3.1 Update `sraverify/core/check.py` to accept `ScanContext`
    - Remove the `_account_info_cache` class variable
    - Replace mutable per-scan instance state (`session`, `regions`, `account_info`) with delegation to `self._ctx`
    - Add `self._ctx: Optional[ScanContext] = None` in `__init__`; keep `self._clients: Dict[str, Any] = {}` for service-level client wrappers
    - Modify `initialize` to accept either a `ScanContext` (new path) or `(session, regions=None)` (deprecated shim that emits `DeprecationWarning` and wraps the inputs into a temporary `ScanContext`)
    - Expose `session`, `regions`, `account_info`, `account_id`, `account_name` as read-only properties that delegate to `self._ctx`
    - Add `audit_accounts` and `log_archive_accounts` as read-only properties delegating to `self._ctx`; assignment to either MUST raise `AttributeError`
    - Update `get_management_accountId` to delegate to `self._ctx.get_management_account_id()` (keep the `session` parameter for backward compat but ignore it)
    - Keep `create_finding` and `execute` interfaces unchanged so finding format is preserved
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 8.3_

  - [ ]* 3.2 Write property test for read-only account-list delegation
    - **Property 3: Account-list defaults and read-only delegation**
    - **Validates: Requirements 1.8, 1.9, 4.7**
    - Generate `audit_accounts`/`log_archive_accounts` from `one_of(none(), just([]), lists(account_id_strategy))`; assert delegation and that assignment raises `AttributeError`
  - [ ]* 3.3 Write unit tests for `SecurityCheck` migration shape
    - Assert `SecurityCheck` no longer has `_account_info_cache` class attribute (Requirement 4.4)
    - Assert `initialize(ctx)` sets `self._ctx` and triggers `_setup_clients`
    - Assert `initialize(session, regions)` shim emits `DeprecationWarning` exactly once per call (capture via `pytest.warns`)
    - Assert `session`, `regions`, `account_info`, `account_id`, `account_name`, `audit_accounts`, `log_archive_accounts` properties delegate to `self._ctx` (Requirements 4.1, 4.2, 4.3, 4.5, 4.6)
    - Assert `create_finding` produces the documented key set with no extras (snapshot)
    - Place at `tests/unit/core/test_check_unit.py`

- [x] 4. Migrate `SRAVerify` orchestrator and CLI plumbing
  - [x] 4.1 Update `sraverify/main.py::SRAVerify` to construct and pass `ScanContext`
    - Add timeout-override init params: `connect_timeout`, `read_timeout`, `max_attempts`, `max_pool_connections` (all default `None`); store as private attrs
    - Keep the existing `__init__` signature (`profile`, `role_arn`, `regions`, `session`, `debug`) intact; the new params append after them
    - In `run_checks`, after the filtering logic, construct `ctx = ScanContext(session=self.session, regions=self.regions, audit_accounts=audit_accounts or [], log_archive_accounts=log_archive_accounts or [], connect_timeout=self._connect_timeout, read_timeout=self._read_timeout, max_attempts=self._max_attempts, max_pool_connections=self._max_pool_connections)`
    - Replace `check.initialize(self.session, regions=self.regions)` with `check.initialize(ctx)`
    - Remove the `check._audit_accounts = audit_accounts` and `check._log_archive_accounts = log_archive_accounts` mutation pattern; account lists now flow through `ctx`
    - Wrap the per-check loop in a `try/finally` that does `del ctx` so the `ScanContext` (and its boto3 clients) become collectible when `run_checks` returns
    - Preserve all other behavior (progress tracking, error finding synthesis, return value shape)
    - _Requirements: 2.6, 3.1, 3.2, 3.3, 3.4, 8.1, 8.2, 8.3_
  - [x] 4.2 Add CLI flags to `parse_args` and forward through `main`
    - Add `--connect-timeout` (`type=float`, default `None`), `--read-timeout` (`type=float`, default `None`), `--max-attempts` (`type=int`, default `None`), `--max-pool-connections` (`type=int`, default `None`) with helpful descriptions
    - Forward all four to `SRAVerify(...)` in `main()`
    - Keep all existing flags and behavior unchanged
    - _Requirements: 2.7, 8.4_
  - [ ]* 4.3 Write property test for per-scan isolation
    - **Property 6: Per-scan isolation across run_checks**
    - **Validates: Requirements 3.1, 3.3, 7.5**
    - Mock the boto3 layer to return a different detector ID per `run_checks` call; for random `N` in `[2, 5]`, assert each call constructs a distinct `ScanContext`, the previous ctx's `weakref` is dead after the next call returns, and findings reflect the current call's mocked state
    - Cap iterations at 50
  - [ ]* 4.4 Write property test for shared `ScanContext` across checks in a run
    - **Property 7: All checks in a single run share the same ScanContext**
    - **Validates: Requirements 3.2**
    - Register `M` fake check classes whose `initialize` records the received `ctx`; for random `M` in `[1, 20]`, assert all `M` checks received the same instance and `_ctx is ctx` for every one
  - [ ]* 4.5 Write unit tests for CLI plumbing
    - Argparse round-trip: feed `--connect-timeout 5 --read-timeout 15 --max-attempts 2 --max-pool-connections 25`; assert parsed namespace values
    - `inspect.signature` checks on `SRAVerify.__init__` and `SRAVerify.run_checks` to confirm preserved public signatures (Requirements 8.1, 8.2)
    - Snapshot test of CSV header to confirm output format is unchanged (Requirement 8.4)
    - Place at `tests/unit/cli/test_cli_args.py`

- [x] 5. Checkpoint - Core, orchestrator, and CLI in place
  - Ensure all tests pass, ask the user if questions arise.

- [x] 6. Migrate the 18 service client wrappers to accept `ScanContext`
  - Each wrapper's `__init__` signature changes from `(region, session=None)` to `(region, ctx)`. Each `self.session.client(svc, region_name=region)` call becomes `ctx.get_client(svc, region=region)`. The `WAFClient` wraps 9 distinct boto3 clients (CloudFront, ELBv2, WAFv2, API Gateway, AppSync, Cognito, App Runner, EC2, Amplify) — every one of them is converted in task 6.18.
  - These migrations are prerequisites for task 8 (service base class migrations).
  - [x] 6.1 Migrate `services/accessanalyzer/client.py`
    - Change constructor signature; replace `self.session.client(...)` with `ctx.get_client(...)`
    - _Requirements: 2.12_
  - [x] 6.2 Migrate `services/account/client.py`
    - _Requirements: 2.12_
  - [x] 6.3 Migrate `services/auditmanager/client.py`
    - _Requirements: 2.12_
  - [x] 6.4 Migrate `services/cloudtrail/client.py`
    - _Requirements: 2.12_
  - [x] 6.5 Migrate `services/config/client.py`
    - _Requirements: 2.12_
  - [x] 6.6 Migrate `services/ec2/client.py`
    - _Requirements: 2.12_
  - [x] 6.7 Migrate `services/firewallmanager/client.py`
    - _Requirements: 2.12_
  - [x] 6.8 Migrate `services/guardduty/client.py`
    - _Requirements: 2.12_
  - [x] 6.9 Migrate `services/iam/client.py`
    - Note: IAM is a global service; the wrapper is constructed without a region (calls `ctx.get_client('iam', region=None)`)
    - _Requirements: 2.12_
  - [x] 6.10 Migrate `services/inspector/client.py`
    - _Requirements: 2.12_
  - [x] 6.11 Migrate `services/macie/client.py`
    - _Requirements: 2.12_
  - [x] 6.12 Migrate `services/organizations/client.py`
    - Note: Organizations is a global service
    - _Requirements: 2.12_
  - [x] 6.13 Migrate `services/s3/client.py`
    - _Requirements: 2.12_
  - [x] 6.14 Migrate `services/securityhub/client.py`
    - _Requirements: 2.12_
  - [x] 6.15 Migrate `services/securityincidentresponse/client.py`
    - _Requirements: 2.12_
  - [x] 6.16 Migrate `services/securitylake/client.py`
    - _Requirements: 2.12_
  - [x] 6.17 Migrate `services/shield/client.py`
    - _Requirements: 2.12_
  - [x] 6.18 Migrate `services/waf/client.py` (9 underlying boto3 clients)
    - Convert each of the 9 internal `self.session.client(svc, region_name=...)` calls to `ctx.get_client(svc, region=...)`: CloudFront, ELBv2, WAFv2, API Gateway, AppSync, Cognito, App Runner, EC2, Amplify
    - Verify `WAFClient` itself is still constructed once per region per scan, but the 9 underlying boto3 clients now de-duplicate across `WAFClient` instances via the per-scan client cache
    - _Requirements: 2.12_
- [x] 7. Set up parameterized service-migration property test (table-driven)
  - [x] 7.1 Build the migrated-services table and the property-test harness
    - In `tests/property/test_service_migration_property.py`, define the `MIGRATED_SERVICES` list of `(class, namespace, [removed_attr_names])` tuples for all 17 service base classes per Requirements 5.1–5.17
    - Implement the parameterized property test that, for each row, asserts (a) no `cls.<attr>` exists for any removed attribute name, (b) `cls()` instance has no `<attr>` instance attribute (covers WAF), and (c) calling a typed method that should write to cache (with a mocked underlying client) results in exactly one `ctx._set(<expected_namespace>, ...)` call
    - The harness is created up front so each service migration in task 8 immediately runs against P8 as its acceptance check
    - **Property 8: Migrated service base classes have no cache attrs and route through ctx**
    - **Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 5.9, 5.10, 5.11, 5.12, 5.13, 5.14, 5.15, 5.16, 5.17, 5.18**
  - [ ]* 7.2 Write property test for finding format invariant
    - **Property 9: Finding format invariant**
    - **Validates: Requirements 8.3**
    - Generate random check metadata and finding inputs; for every concrete migrated service base class, call `create_finding` and assert `set(result.keys()) == EXPECTED_KEYS` exactly (no extras, no missing)
    - Place at `tests/property/test_run_checks_properties.py` alongside P6 and P7

- [x] 8. Migrate the 17 service base classes (one per task, parallel-safe)
  - Each task follows the same five-step pattern from the design: drop class-level cache dicts, pick the lowercased-service-name namespace, replace `ClassName._foo_cache[key] = value` with `self._ctx._set(NS, key, value)`, replace cache reads with `self._ctx._has` / `self._ctx._get`, and update `_setup_clients` to construct service client wrappers with `ctx=self._ctx`. Each task's reviewer checks Property 8 (`tests/property/test_service_migration_property.py`) for the corresponding row passes.
  - These 17 tasks are independent of each other once tasks 1–4 land; they can be reviewed and merged in any order, but each requires its corresponding service client wrapper migration (task 6) to be merged first.
  - [x] 8.1 Migrate `services/guardduty/base.py` (4 caches → "guardduty" namespace)
    - Drop class-level `_detector_details_cache`, `_detector_ids_cache`, `_org_config_cache`, `_admin_accounts_cache`
    - Set `NAMESPACE = "guardduty"`
    - Update `_setup_clients` to construct `GuardDutyClient(region, ctx=self._ctx)` for each region in `self.regions`
    - Rewrite `get_detector_id`, `get_detector_details`, `get_organization_configuration`, `list_organization_admin_accounts`, and `get_enabled_regions` to use `self._ctx._has` / `_get` / `_set`
    - Drop today's `f"{self.session.region_name}:{region}"` cache key prefix per the design's "Cache key conventions" section; the per-scan ctx already scopes the key
    - _Requirements: 5.1, 5.18_
  - [x] 8.2 Migrate `services/cloudtrail/base.py` (3 caches → "cloudtrail" namespace)
    - Drop `_describe_trails_cache`, `_trail_status_cache`, `_delegated_admin_account_id_cache`
    - Update `_setup_clients` to use `CloudTrailClient(region, ctx=self._ctx)`
    - _Requirements: 5.2, 5.18_
  - [x] 8.3 Migrate `services/accessanalyzer/base.py` (2 caches → "accessanalyzer" namespace)
    - Drop `_delegated_admin_cache`, `_analyzer_cache`
    - Update `_setup_clients` to use `AccessAnalyzerClient(region, ctx=self._ctx)`
    - _Requirements: 5.3, 5.18_
  - [x] 8.4 Migrate `services/config/base.py` (5 caches → "config" namespace)
    - Drop `_config_recorder_status_cache`, `_config_delivery_channel_status_cache`, `_config_organization_aggregator`, `_config_delivery_channel_cache`, `_config_delegated_admin_cache`
    - Update `_setup_clients` to use `ConfigClient(region, ctx=self._ctx)`
    - _Requirements: 5.4, 5.18_
  - [x] 8.5 Migrate `services/securityhub/base.py` (7 caches → "securityhub" namespace)
    - Drop `_enabled_standards_cache`, `_admin_account_cache`, `_organization_configuration_cache`, `_product_integrations_cache`, `_delegated_admin_cache`, `_organization_accounts_cache`, `_securityhub_members_cache`
    - Update `_setup_clients` to use `SecurityHubClient(region, ctx=self._ctx)`
    - _Requirements: 5.5, 5.18_
  - [x] 8.6 Migrate `services/s3/base.py` (1 cache → "s3" namespace)
    - Drop `_public_access_cache`
    - Update `_setup_clients` to use `S3Client(region, ctx=self._ctx)`
    - _Requirements: 5.6, 5.18_
  - [x] 8.7 Migrate `services/inspector/base.py` (5 caches → "inspector" namespace)
    - Drop `_inspector_account_status`, `_inspector_batch_account_status`, `_inspector_delegated_admin`, `_inspector_org_config`, `_organization_members`
    - Update `_setup_clients` to use `InspectorClient(region, ctx=self._ctx)`
    - _Requirements: 5.7, 5.18_
  - [x] 8.8 Migrate `services/ec2/base.py` (1 cache → "ec2" namespace)
    - Drop `_ebs_encryption_default_cache`
    - Update `_setup_clients` to use `EC2Client(region, ctx=self._ctx)`
    - _Requirements: 5.8, 5.18_
  - [x] 8.9 Migrate `services/macie/base.py` (6 caches → "macie" namespace)
    - Drop `_findings_publication_cache`, `_export_configuration_cache`, `_macie_delegated_admin_cache`, `_macie_members_cache`, `_org_members_cache`, `_auto_enable_cache`
    - Update `_setup_clients` to use `MacieClient(region, ctx=self._ctx)`
    - _Requirements: 5.9, 5.18_
  - [x] 8.10 Migrate `services/shield/base.py` (1 cache → "shield" namespace)
    - Drop `_subscription_cache`
    - Update `_setup_clients` to use `ShieldClient(region, ctx=self._ctx)`
    - _Requirements: 5.10, 5.18_
  - [x] 8.11 Migrate `services/account/base.py` (1 cache → "account" namespace)
    - Drop `_contact_cache`
    - Update `_setup_clients` to use `AccountClient(region, ctx=self._ctx)`
    - _Requirements: 5.11, 5.18_
  - [x] 8.12 Migrate `services/auditmanager/base.py` (1 cache → "auditmanager" namespace)
    - Drop `_account_status_cache`
    - Update `_setup_clients` to use `AuditManagerClient(region, ctx=self._ctx)`
    - _Requirements: 5.12, 5.18_
  - [x] 8.13 Migrate `services/firewallmanager/base.py` (2 caches → "firewallmanager" namespace)
    - Drop `_admin_account_cache`, `_policies_cache`
    - Update `_setup_clients` to use `FirewallManagerClient(region, ctx=self._ctx)`
    - _Requirements: 5.13, 5.18_
  - [x] 8.14 Migrate `services/securitylake/base.py` (7 caches → "securitylake" namespace)
    - Drop `_subscribers_cache`, `_security_lake_status_cache`, `_organization_configuration_cache`, `_delegated_admin_cache`, `_organization_accounts_cache`, `_log_sources_cache`, `_sqs_encryption_cache`
    - Update `_setup_clients` to use `SecurityLakeClient(region, ctx=self._ctx)`
    - _Requirements: 5.14, 5.18_
  - [x] 8.15 Migrate `services/organizations/base.py` (5 caches → "organizations" namespace)
    - Drop `_organization_cache`, `_roots_cache`, `_ous_cache`, `_policies_cache`, `_accounts_cache`
    - Update `_setup_clients` to use `OrganizationsClient(ctx=self._ctx)` (Organizations is a global service; pin to a single client)
    - _Requirements: 5.15, 5.18_
  - [x] 8.16 Migrate `services/iam/base.py` (1 cache → "iam" namespace)
    - Drop `_users_cache` class variable
    - Update `_setup_clients` to use `IAM_Client(ctx=self._ctx)` (IAM is global; pin to `us-east-1`)
    - Rewrite `list_users` to use `self._ctx._has("iam", f"users:{self.account_id}")` / `_get` / `_set`; preserve "cache both success and error responses" behavior
    - _Requirements: 5.16, 5.18_
  - [x] 8.17 Migrate `services/waf/base.py` (9 instance-level caches → "waf" namespace)
    - Remove the 9 instance-level cache dict assignments from `WAFCheck.__init__`: `_distributions_cache`, `_load_balancers_cache`, `_rest_apis_cache`, `_graphql_apis_cache`, `_user_pools_cache`, `_apprunner_services_cache`, `_verified_access_instances_cache`, `_amplify_apps_cache`, `_web_acls_cache`
    - Set `NAMESPACE = "waf"`
    - Update `_setup_clients` to construct `WAFClient(region, ctx=self._ctx)`; preserve the "WAF for CloudFront is global, use us-east-1" behavior
    - Rewrite each of the 9 `get_*` methods (`get_distributions`, `get_load_balancers`, `get_rest_apis`, `get_graphql_apis`, `get_user_pools`, `get_apprunner_services`, `get_verified_access_instances`, `get_amplify_apps`, `get_web_acls`) to use `self._ctx._has` / `_get` / `_set` under the `"waf"` namespace; `get_stages` is unchanged because it has no cache
    - For `get_web_acls`, preserve the `f"{region}_{scope}"` cache key shape (now under the namespace primitives)
    - _Requirements: 5.17, 5.18_

- [x] 9. Cross-service cache sharing — worked example
  - [x] 9.1 Implement cross-service read for SecurityHub from the Organizations namespace
    - Add a `get_organization()` (or similarly named) typed method on `SecurityHubCheck` that first checks `self._ctx._has("organizations", f"organization:{self.account_id}")`, returns the cached value on hit, and otherwise issues `organizations.describe_organization` and writes back into the `"organizations"` namespace under the same key shape that `OrganizationsCheck` uses, so a later `OrganizationsCheck` call picks it up
    - Verify there is no individual check class call site to `_get` / `_set` / `_has` — only the service base class touches the primitives (Requirement 6.3)
    - _Requirements: 6.1, 6.2, 6.3_
  - [ ]* 9.2 Write unit test for the cross-service worked example
    - Pre-populate the Organizations namespace on a fresh `ctx`; call `SecurityHubCheck.get_organization`; assert no Organizations boto3 call was made and the pre-populated value was returned
    - Inverse direction: call `SecurityHubCheck.get_organization` first against a fresh ctx (mocked to return a known response); then assert `OrganizationsCheck` reads the SecurityHub-populated value without re-fetching
    - Add a ripgrep-based test over `services/*/checks/` asserting no `_get`, `_set`, or `_has` primitive call appears in any individual check file (Requirement 6.3)
    - Place at `tests/unit/services/test_securityhub_base.py` and `tests/unit/services/test_service_migration_grep.py`

- [x] 10. Checkpoint - All service migrations complete
  - Ensure all tests pass (including the parameterized P8 across all 17 services), ask the user if questions arise.
- [x] 11. Update MCP server integration
  - [x] 11.1 Remove `_clear_sra_caches` and forward timeout overrides
    - In `sra-verify-mcp/awslabs/sraverify_mcp_server/server.py`, delete the `_clear_sra_caches` helper function entirely
    - Delete the `_clear_sra_caches()` call inside the `run_check` tool body
    - Add `connect_timeout`, `read_timeout`, `max_attempts`, `max_pool_connections` as optional kwargs (`int | float | None`) to `_get_sra_instance` and forward them to `SRAVerify(...)`
    - Add the same four optional kwargs (`float | None` / `int | None`) to the `run_check` MCP tool signature; forward them through `_get_sra_instance` to `SRAVerify`
    - When the four kwargs are absent, the library's default `Client_Config` values are used automatically (no explicit branching needed)
    - Leave the four read-only tools (`list_checks_by_account_type`, `list_services`, `list_checks_by_service`, `describe_check`) unchanged — they only read static metadata from `ALL_CHECKS` and never construct a session
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_
  - [ ]* 11.2 Write unit tests for MCP server changes
    - Module attribute absence: assert `not hasattr(server_module, "_clear_sra_caches")` (Requirement 7.1)
    - Mock-based forwarding: patch `SRAVerify`; call the `run_check` tool with each of the four timeout args set; assert `SRAVerify` was constructed with those values (Requirement 7.3)
    - Default fall-through: call `run_check` with no timeout args; assert `SRAVerify` was constructed with `None` for all four (Requirement 7.4)
    - Read-only tools without session: call each of the four read-only tools without AWS credentials in the environment; assert each returns successfully (Requirement 7.2)
    - Place at `tests/unit/mcp/test_mcp_run_check.py`
  - [ ]* 11.3 Write integration-style test validating per-scan isolation through MCP
    - Use `moto` (or equivalent) to stand up fake AWS; invoke the `run_check` tool twice for the same `check_id`, mutating the fake AWS state between the two calls
    - Assert the second invocation's findings reflect the second AWS state, confirming the `_clear_sra_caches` workaround can safely be removed
    - _Requirements: 7.5_

- [x] 12. Final checkpoint - End-to-end verification
  - Ensure all tests pass (P1–P9 properties + all unit tests + the MCP integration test), ask the user if questions arise.

- [x] 13. Remove the deprecated `SecurityCheck.initialize(session, regions)` shim
  - This is the final cleanup step and runs only after all internal callers have been confirmed to go through `initialize(ctx)`.
  - [x] 13.1 Delete the deprecated 2-argument shim from `sraverify/core/check.py`
    - Remove the `isinstance(ctx_or_session, ScanContext)` branch and the `else` branch that wraps a session into a temporary `ScanContext`
    - Change the parameter to `ctx: ScanContext` only; remove the `regions=None` parameter
    - Run a workspace-wide grep for `initialize(session` and `initialize(self.session` to confirm no internal caller still uses the old signature; if any are found, fix them in the same change
    - Update any docstrings that referenced the deprecated shim
    - _Requirements: 4.1_
  - [ ]* 13.2 Remove or update tests that exercised the deprecation warning
    - Delete the `pytest.warns(DeprecationWarning)` test added in 3.3 (the shim no longer exists)
    - Add a test asserting that `initialize(some_session_object)` raises `TypeError` (or equivalent) so callers get a clear failure rather than silent breakage

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP, but the property tests in tasks 7.1, 2.5–2.8, 4.3–4.4, and 9.2 are highly recommended because they validate the universal correctness invariants (P1, P2, P4, P5, P6, P7, P8) that the refactor stands on.
- Each task references specific requirements for traceability; the property test sub-tasks additionally annotate the property number from the design's "Correctness Properties" section.
- The 17 service base class migrations in task 8 are independent of each other once tasks 1–4 land. They can be parallelized, but each requires its corresponding service client wrapper migration in task 6 to be merged first.
- Service client wrapper migrations (task 6) MUST precede the corresponding service base class migrations (task 8). The dependency graph encodes this with task 6 in a wave before task 8.
- The parameterized P8 property test harness (task 7.1) is set up before any service migration so that each migration in task 8 immediately runs against P8 as part of its review.
- Backward compatibility is maintained throughout: `SRAVerify.__init__` and `SRAVerify.run_checks` signatures are preserved (Requirements 8.1, 8.2), and the finding format is unchanged (Requirement 8.3, Property 9). The CLI continues to accept all existing flags and produces the same output format (Requirement 8.4).
- Task 13 (removing the deprecation shim) is a follow-up cleanup that runs only after every internal caller has been confirmed to use the new `initialize(ctx)` path. It is intentionally last so that earlier tasks can be reviewed and merged independently without breaking the migration shim.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["2.1"] },
    { "id": 2, "tasks": ["2.2", "2.3", "2.4"] },
    { "id": 3, "tasks": ["2.5", "2.6", "2.7", "2.8", "2.9", "3.1", "6.1", "6.2", "6.3", "6.4", "6.5", "6.6", "6.7", "6.8", "6.9", "6.10", "6.11", "6.12", "6.13", "6.14", "6.15", "6.16", "6.17", "6.18"] },
    { "id": 4, "tasks": ["3.2", "3.3", "4.1", "7.1", "7.2"] },
    { "id": 5, "tasks": ["4.2", "4.3", "4.4", "8.1", "8.2", "8.3", "8.4", "8.5", "8.6", "8.7", "8.8", "8.9", "8.10", "8.11", "8.12", "8.13", "8.14", "8.15", "8.16", "8.17", "11.1"] },
    { "id": 6, "tasks": ["4.5", "9.1", "11.2"] },
    { "id": 7, "tasks": ["9.2", "11.3"] },
    { "id": 8, "tasks": ["13.1"] },
    { "id": 9, "tasks": ["13.2"] }
  ]
}
```
