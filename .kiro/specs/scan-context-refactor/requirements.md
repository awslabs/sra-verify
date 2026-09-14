# Requirements Document

## Introduction

The sraverify library currently uses class-level dictionary caches on every service base class (GuardDutyCheck, CloudTrailCheck, SecurityHubCheck, etc.) to cache AWS API responses such as detector IDs, trail details, and organization configurations. These class-level caches persist for the entire Python process lifetime, causing stale data when the library is used in a long-lived process like the sra-verify-mcp server. The library also constructs every boto3 client without a `botocore.config.Config`, so calls to AWS services that are not enabled or are unreachable can stall for up to five minutes per call before failing.

This refactor introduces a `ScanContext` object that owns all per-scan state for a single scan run: the boto3 session, region list, account-ID lists, cached AWS API responses, and the boto3 clients themselves. Each call to `run_checks` creates a fresh `ScanContext`, and all checks within that scan share it. This eliminates stale cache issues, lets checks share boto3 clients (one per service+region per scan instead of one per check), and applies bounded boto3 timeouts so calls to disabled or unreachable regions fail fast instead of stalling. The shape is also designed to be safe for the future Phase 3.1 concurrency work without requiring a second refactor.

## Glossary

- **ScanContext**: A new object that holds all per-scan state — boto3 session, regions, audit/log-archive account lists, cached AWS API data, the boto3 Client_Config, and a per-scan boto3 Client_Cache. Created fresh for each `run_checks` invocation.
- **SecurityCheck**: The base class (`core/check.py`) for all security checks. Currently holds a class-level `_account_info_cache` dict.
- **Service_Base_Class**: A service-specific subclass of SecurityCheck (e.g., GuardDutyCheck, SecurityHubCheck) that provides shared AWS API caching methods for its service's individual checks.
- **SRAVerify**: The orchestrator class (`main.py`) that creates sessions, discovers checks, and runs them.
- **MCP_Server**: The MCP server process (`sra-verify-mcp/`) that uses the sraverify library in a long-lived process, calling `run_checks` repeatedly.
- **Namespace**: A string key (typically the service name) used to partition cached data within a ScanContext so different services' caches do not collide.
- **Class_Level_Cache**: A Python class variable (dict) shared across all instances of a class, persisting for the process lifetime. The pattern being replaced.
- **Instance_Level_Cache**: A Python instance variable (dict) set in `__init__`, scoped to a single object instance. Used by WAFCheck.
- **Client_Config**: A `botocore.config.Config` object owned by ScanContext and applied to every boto3 client constructed for the scan. Sets bounded connect/read timeouts, retry attempts, and connection pool size.
- **Client_Cache**: A per-scan dictionary inside ScanContext keyed by `(service_name, region)` that returns one boto3 client per key, reused across all checks for the lifetime of the scan.

## Requirements

### Requirement 1: ScanContext Object

**User Story:** As a library maintainer, I want a ScanContext object that encapsulates all per-scan state with a typed public API, so that cached data does not leak between scan runs and check authors do not interact with stringly-typed cache keys.

#### Acceptance Criteria

1. THE ScanContext public API SHALL expose only typed accessors for cached data; generic stringly-typed cache access (e.g., `get(namespace, key)`) SHALL NOT be part of the public API.
2. THE ScanContext SHALL provide a `get_account_info()` method that returns a dict with `account_id` and `account_name` keys, calling STS once per scan and caching the result for reuse by all subsequent calls within the scan.
3. THE ScanContext SHALL provide a `get_management_account_id()` method that returns the AWS Organizations management account ID, calling Organizations once per scan and caching the result for reuse by all subsequent calls within the scan.
4. THE ScanContext SHALL provide a `get_enabled_regions()` method that returns the list of enabled AWS regions for the account, lazily resolving the list via EC2 the first time it is called when no explicit region list was supplied at construction time.
5. THE ScanContext SHALL provide internal namespaced storage primitives (e.g., `_get(namespace, key)`, `_set(namespace, key, value)`, `_has(namespace, key)`) intended for use by service base classes only; these SHALL be marked as private (underscore-prefixed) and SHALL NOT be called from individual check classes.
6. THE ScanContext SHALL hold a reference to the boto3 Session for the scan.
7. THE ScanContext SHALL hold the list of AWS regions for the scan.
8. THE ScanContext SHALL hold the list of audit account IDs for the scan, defaulting to an empty list when none are provided.
9. THE ScanContext SHALL hold the list of log-archive account IDs for the scan, defaulting to an empty list when none are provided.
10. WHEN a ScanContext is created, THE ScanContext SHALL start with an empty cache containing no entries.
11. THE ScanContext SHALL be safe to share across multiple threads; concurrent reads and writes to the internal namespaced cache, the Client_Cache, and the cached account info SHALL be serialized so that the future Phase 3.1 concurrent-execution work does not require a second refactor.

### Requirement 2: Bounded Boto3 Client Lifecycle

**User Story:** As an operator running multi-account sweeps, I want every boto3 client in the library to use bounded timeouts and to be reused across checks in the same scan, so that calls to disabled or unreachable regions fail fast and the worker pool is not exhausted.

#### Acceptance Criteria

1. THE ScanContext SHALL hold a `botocore.config.Config` object (the Client_Config) that is applied to every boto3 client constructed for the scan.
2. THE default Client_Config SHALL set `connect_timeout=10`, `read_timeout=30`, `retries={"max_attempts": 3, "mode": "standard"}`, and `max_pool_connections=50`.
3. THE ScanContext SHALL accept an optional `client_config` parameter at construction time so callers (CLI, MCP, tests) can override the default.
4. THE ScanContext SHALL accept individual override parameters at construction time (`connect_timeout`, `read_timeout`, `max_attempts`, `max_pool_connections`) that selectively override fields of the default Client_Config without requiring callers to construct a full `botocore.config.Config` themselves.
5. WHEN both a `client_config` parameter and individual override parameters are supplied, THE ScanContext SHALL prefer the explicit `client_config` and ignore the individual parameters.
6. THE SRAVerify class SHALL accept and forward the same individual override parameters to the ScanContext it creates inside `run_checks`.
7. THE CLI SHALL expose `--connect-timeout`, `--read-timeout`, `--max-attempts`, and `--max-pool-connections` flags that are forwarded to SRAVerify and ultimately to the ScanContext.
8. THE MCP_Server `run_check` tool SHALL expose `connect_timeout`, `read_timeout`, `max_attempts`, and `max_pool_connections` as optional tool arguments that are forwarded to SRAVerify and ultimately to the ScanContext.
9. THE ScanContext SHALL provide a `get_client(service_name, region=None)` method that returns a boto3 client for the given service and region, constructed from the ScanContext's session and Client_Config.
10. WHEN `get_client` is called more than once with the same `(service_name, region)` pair within the same scan, THE ScanContext SHALL return the same boto3 client instance.
11. THE `get_client` method SHALL be thread-safe so that concurrent callers receive a single client per `(service_name, region)` pair without race conditions.
12. WHEN a service-level client wrapper (`services/<svc>/client.py`) constructs its underlying boto3 client, THE wrapper SHALL obtain the boto3 client from `ScanContext.get_client(...)` rather than calling `session.client(...)` directly.
13. THE underlying boto3 clients held by Client_Cache SHALL NOT be reachable after the scan completes, so that they are eligible for garbage collection along with the ScanContext.

### Requirement 3: ScanContext Lifecycle in SRAVerify

**User Story:** As a library consumer, I want each `run_checks` call to use a fresh ScanContext, so that no stale data from a previous scan affects the current scan.

#### Acceptance Criteria

1. WHEN `run_checks` is called, THE SRAVerify class SHALL create a new ScanContext instance with the current session, regions, audit_accounts, and log_archive_accounts.
2. THE SRAVerify class SHALL pass the ScanContext to each SecurityCheck instance during initialization.
3. WHEN `run_checks` completes, THE SRAVerify class SHALL release its reference to the ScanContext so that cached data and boto3 clients are eligible for garbage collection.
4. THE SRAVerify class SHALL NOT mutate per-scan state on SecurityCheck instances directly (e.g., `check._audit_accounts = ...`); audit and log-archive account lists SHALL flow exclusively through the ScanContext.

### Requirement 4: SecurityCheck Base Class Migration

**User Story:** As a library maintainer, I want the SecurityCheck base class to use ScanContext instead of class-level caches and instance-level session/region attributes, so that all per-scan state lives in one place.

#### Acceptance Criteria

1. THE SecurityCheck base class SHALL accept a ScanContext during initialization.
2. THE SecurityCheck base class SHALL store the ScanContext as an instance attribute accessible to subclasses.
3. THE SecurityCheck base class SHALL look up account information by calling `ScanContext.get_account_info()` instead of using the class-level `_account_info_cache` dict.
4. THE SecurityCheck base class SHALL remove the class-level `_account_info_cache` class variable.
5. THE SecurityCheck base class SHALL read the session from the ScanContext instead of storing a separate session instance attribute.
6. THE SecurityCheck base class SHALL read the regions list from the ScanContext instead of storing a separate regions instance attribute.
7. THE SecurityCheck base class SHALL expose audit and log-archive account lists as read-only properties that delegate to the ScanContext, replacing the current `check._audit_accounts` and `check._log_archive_accounts` direct-mutation pattern.

### Requirement 5: Service Base Class Migration

**User Story:** As a library maintainer, I want all service base classes with class-level or instance-level caches to use ScanContext, so that AWS API response caching is scoped to a single scan.

#### Acceptance Criteria

1. THE GuardDutyCheck class SHALL replace its 4 class-level cache dicts (`_detector_details_cache`, `_detector_ids_cache`, `_org_config_cache`, `_admin_accounts_cache`) with ScanContext cache calls using the "guardduty" namespace.
2. THE CloudTrailCheck class SHALL replace its 3 class-level cache dicts (`_describe_trails_cache`, `_trail_status_cache`, `_delegated_admin_account_id_cache`) with ScanContext cache calls using the "cloudtrail" namespace.
3. THE AccessAnalyzerCheck class SHALL replace its 2 class-level cache dicts (`_delegated_admin_cache`, `_analyzer_cache`) with ScanContext cache calls using the "accessanalyzer" namespace.
4. THE ConfigCheck class SHALL replace its 5 class-level cache dicts (`_config_recorder_status_cache`, `_config_delivery_channel_status_cache`, `_config_organization_aggregator`, `_config_delivery_channel_cache`, `_config_delegated_admin_cache`) with ScanContext cache calls using the "config" namespace.
5. THE SecurityHubCheck class SHALL replace its 7 class-level cache dicts (`_enabled_standards_cache`, `_admin_account_cache`, `_organization_configuration_cache`, `_product_integrations_cache`, `_delegated_admin_cache`, `_organization_accounts_cache`, `_securityhub_members_cache`) with ScanContext cache calls using the "securityhub" namespace.
6. THE S3Check class SHALL replace its 1 class-level cache dict (`_public_access_cache`) with ScanContext cache calls using the "s3" namespace.
7. THE InspectorCheck class SHALL replace its 5 class-level cache dicts (`_inspector_account_status`, `_inspector_batch_account_status`, `_inspector_delegated_admin`, `_inspector_org_config`, `_organization_members`) with ScanContext cache calls using the "inspector" namespace.
8. THE EC2Check class SHALL replace its 1 class-level cache dict (`_ebs_encryption_default_cache`) with ScanContext cache calls using the "ec2" namespace.
9. THE MacieCheck class SHALL replace its 6 class-level cache dicts (`_findings_publication_cache`, `_export_configuration_cache`, `_macie_delegated_admin_cache`, `_macie_members_cache`, `_org_members_cache`, `_auto_enable_cache`) with ScanContext cache calls using the "macie" namespace.
10. THE ShieldCheck class SHALL replace its 1 class-level cache dict (`_subscription_cache`) with ScanContext cache calls using the "shield" namespace.
11. THE AccountCheck class SHALL replace its 1 class-level cache dict (`_contact_cache`) with ScanContext cache calls using the "account" namespace.
12. THE AuditManagerCheck class SHALL replace its 1 class-level cache dict (`_account_status_cache`) with ScanContext cache calls using the "auditmanager" namespace.
13. THE FirewallManagerCheck class SHALL replace its 2 class-level cache attributes (`_admin_account_cache`, `_policies_cache`) with ScanContext cache calls using the "firewallmanager" namespace.
14. THE SecurityLakeCheck class SHALL replace its 7 class-level cache dicts (`_subscribers_cache`, `_security_lake_status_cache`, `_organization_configuration_cache`, `_delegated_admin_cache`, `_organization_accounts_cache`, `_log_sources_cache`, `_sqs_encryption_cache`) with ScanContext cache calls using the "securitylake" namespace.
15. THE OrganizationsCheck class SHALL replace its 5 class-level cache dicts (`_organization_cache`, `_roots_cache`, `_ous_cache`, `_policies_cache`, `_accounts_cache`) with ScanContext cache calls using the "organizations" namespace.
16. THE IAMCheck class SHALL replace its 1 class-level cache dict (`_users_cache`, keyed by `account_id`) with ScanContext cache calls using the "iam" namespace.
17. THE WAFCheck class SHALL replace its 9 instance-level cache dicts (`_distributions_cache`, `_load_balancers_cache`, `_rest_apis_cache`, `_graphql_apis_cache`, `_user_pools_cache`, `_apprunner_services_cache`, `_verified_access_instances_cache`, `_amplify_apps_cache`, `_web_acls_cache`, set in `__init__`) with ScanContext cache calls using the "waf" namespace, and remove the instance-level cache dict assignments from its `__init__` method.
18. WHEN a service base class is migrated, THE service base class SHALL remove all class-level or instance-level cache dict variables.

### Requirement 6: Cross-Service Cache Sharing

**User Story:** As a library maintainer, I want a service base class to be able to read cached data that another service base class wrote, so that redundant AWS API calls are avoided when services share data.

#### Acceptance Criteria

1. THE ScanContext SHALL allow any service base class to read from any namespace via the internal namespaced primitives, regardless of which service wrote the data.
2. WHEN a service base class needs data that another service base class has already cached (e.g., Organizations describe-organization data needed by SecurityHub), THE service base class SHALL read from the other service's namespace through the internal primitives rather than re-fetching from AWS.
3. Individual check classes (subclasses of a service base class) SHALL NOT call the internal namespaced primitives directly; cross-service data access SHALL go through typed methods on the relevant service base class.

### Requirement 7: MCP Server Integration

**User Story:** As an MCP server maintainer, I want the MCP server to remove the cache-clearing workaround it currently uses between runs and to expose timeout overrides to operators, so that the server relies on the library's own per-scan isolation and slow-network environments can tune up.

#### Acceptance Criteria

1. THE MCP_Server SHALL remove the `_clear_sra_caches` helper function and the call to it inside the `run_check` tool, since per-scan isolation is now provided by ScanContext.
2. THE MCP_Server read-only tools (list_checks_by_account_type, list_services, list_checks_by_service, describe_check) SHALL continue to work without requiring an AWS session, since they only read static check metadata from the ALL_CHECKS registry.
3. THE MCP_Server `run_check` tool SHALL accept optional `connect_timeout`, `read_timeout`, `max_attempts`, and `max_pool_connections` arguments and forward them to SRAVerify when constructing the per-call instance.
4. WHEN the `run_check` tool is invoked without timeout arguments, THE MCP_Server SHALL fall back to the library's default Client_Config values.
5. WHEN the MCP_Server invokes the `run_check` tool, THE call SHALL produce findings that reflect the current AWS state at the time of the call, regardless of what previous `run_check` invocations cached.

### Requirement 8: Backward Compatibility

**User Story:** As a library consumer, I want the public API and CLI behavior of SRAVerify to remain unchanged, so that existing integrations continue to work without modification.

#### Acceptance Criteria

1. THE SRAVerify class SHALL maintain the same `__init__` signature (profile, role_arn, session, regions, debug parameters).
2. THE SRAVerify class SHALL maintain the same `run_checks` signature (account_type, service, check_id, audit_accounts, log_archive_accounts, show_progress parameters).
3. THE SRAVerify class SHALL return findings in the same format as before the refactor.
4. THE CLI entry point SHALL produce the same output format and accept the same command-line arguments as before the refactor.
