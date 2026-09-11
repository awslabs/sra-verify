# Implementation Plan: IAM User Detection (SRA-IAM-01)

## Overview

Convert the feature design into a series of prompts for a code-generation LLM that will implement each step with incremental progress. Each prompt builds on the previous prompts and ends with wiring things together. There should be no hanging or orphaned code that isn't integrated into a previous step. Focus ONLY on tasks that involve writing, modifying, or testing code.

This plan implements the new `SRA-IAM-01` check and its supporting `services/iam/` module by following the dependency order called out in the design document's "Implementation Considerations" section: client → base → check → registration → tests. Property-based tests (Hypothesis) validate the correctness properties P1–P9 defined in the design; unit tests cover specific examples and edge cases. All code is Python 3.8+, mirrors the structural patterns used by `services/organizations/` and `services/accessanalyzer/`, and uses the existing `SecurityCheck` framework for findings creation.

## Tasks

- [x] 1. Scaffold the `services/iam/` package layout
  - Create directory `sraverify/sraverify/services/iam/` and its `checks/` subdirectory
  - Create empty `services/iam/checks/__init__.py` package marker (mirrors `services/accessanalyzer/checks/__init__.py`)
  - Create placeholder `services/iam/__init__.py` (to be populated in task 5 once `SRA_IAM_01` exists)
  - No implementation logic yet; this task only establishes importable package paths
  - _Requirements: 6.1_

- [x] 2. Implement the `IAM_Client` wrapper
  - [x] 2.1 Create `IAM_Client` in `services/iam/client.py`
    - Construct `boto3` iam client pinned to `region_name="us-east-1"` in `__init__`, accepting an optional `boto3.Session`
    - Implement `list_users()` using `self.client.get_paginator("list_users")` and iterate pages, accumulating the `Users` list into `{"Users": [...]}`
    - Catch `botocore.exceptions.ClientError` and return `{"Error": {"Code": <code>, "Message": <message>}}` (log at `warning` level, do not re-raise)
    - Catch `EndpointConnectionError`, `ReadTimeoutError`, `ConnectTimeoutError` and return `{"Error": {"Code": e.__class__.__name__, "Message": str(e)}}`
    - Catch any other `Exception` and return `{"Error": {"Code": "UnknownError", "Message": str(e)}}`
    - Mirror the shape of `services/organizations/client.py` for logging/session handling
    - _Requirements: 1.6, 1.7, 4.1_

  - [ ]* 2.2 Write unit tests for `IAM_Client` in `sraverify/tests/services/iam/test_client.py`
    - `test_single_page_success`: returns `{"Users": [...]}` for a single-page response (_Req 1.6_)
    - `test_multi_page_pagination`: paginator iterates all pages; result contains union (_Req 1.7_)
    - `test_empty_page`: returns `{"Users": []}` when paginator yields no users (_Req 3.1_)
    - `test_client_error_access_denied`: ClientError mapped to `{"Error": {"Code": "AccessDenied", ...}}` without raising (_Req 4.1_)
    - `test_client_error_throttling`: Throttling ClientError mapped structurally (_Req 4.1_)
    - `test_unexpected_exception`: generic `Exception` mapped to `{"Error": {"Code": "UnknownError", ...}}` (_Req 4.1_)
    - `test_region_pinned_us_east_1`: asserts `session.client("iam", region_name="us-east-1")` was called (_Req 1.6, 3.5_)
    - Use `unittest.mock.MagicMock` for `boto3.Session`; build `ClientError` instances from `botocore.exceptions`
    - Ensure `sraverify/tests/services/__init__.py` and `sraverify/tests/services/iam/__init__.py` exist so pytest discovers the package
    - _Requirements: 1.6, 1.7, 3.1, 4.1, 3.5_

- [x] 3. Implement the `IAMCheck` service base class
  - [x] 3.1 Create `IAMCheck` in `services/iam/base.py`
    - Extend `SecurityCheck` from `sraverify.core.check`
    - In `__init__`, call `super().__init__(account_type="application", service="IAM", resource_type="AWS::IAM::User")` and initialize `self._iam_client: Optional[IAM_Client] = None`
    - Declare `_users_cache: Dict[str, Dict[str, Any]] = {}` class attribute (shared across instances) and `GLOBAL_REGION: str = "us-east-1"` class constant
    - Implement `_setup_clients(self)` that constructs a single `IAM_Client(self.session)` and stores it on `self._iam_client` (do not populate a per-region `_clients` dict — mirrors `OrganizationsCheck`)
    - Implement `get_iam_client(self) -> IAM_Client` that returns `self._iam_client`
    - Implement `list_users(self) -> Dict[str, Any]` that checks `self._users_cache.get(self.account_id)` first; on miss calls `self._iam_client.list_users()`, stores the result in `_users_cache[self.account_id]`, and returns it (caches both success and error responses)
    - Implement `_validate_metadata(self)` that raises `ValueError(f"{attr_name} is missing or empty on {self.__class__.__name__}")` when any of `check_name`, `description`, or `check_logic` is `None` or an empty string
    - _Requirements: 1.2, 1.4, 1.5, 1.6, 7.4_

  - [ ]* 3.2 Write unit tests for `IAMCheck` in `sraverify/tests/services/iam/test_base.py`
    - `test_setup_clients_creates_single_client`: single `IAM_Client` constructed; `_clients` dict unused (_Req 1.6_)
    - `test_list_users_caches_success`: second call does not re-invoke `IAM_Client.list_users` (_Property P9_)
    - `test_list_users_caches_error`: error responses are cached too (_Property P9_)
    - `test_validate_metadata_raises_on_missing_name`: `ValueError` when `check_name = None` (_Req 7.4_)
    - `test_validate_metadata_raises_on_empty_description`: `ValueError` when `description = ""` (_Req 7.4_)
    - `test_validate_metadata_passes`: no exception when all three attributes are non-empty (_Req 7.4_)
    - Reset `IAMCheck._users_cache` between tests with a pytest fixture
    - _Requirements: 1.6, 7.4_

- [x] 4. Implement `SRA_IAM_01` check class
  - [x] 4.1 Create `SRA_IAM_01` in `services/iam/checks/sra_iam_01.py`
    - Extend `IAMCheck`
    - In `__init__`, call `super().__init__()` then set:
      - `self.check_id = "SRA-IAM-01"`
      - `self.check_name` to a single-sentence, period-terminated string (≤200 chars) containing `"IAM user"` — e.g. `"Account contains no IAM users."`
      - `self.description` (≤2000 chars) containing all of: `"IAM user"`, `"long-lived credential"`, `"IAM Identity Center"`, `"IAM role"`
      - `self.severity = "HIGH"`
      - `self.check_logic` (≤1000 chars) containing `"ListUsers"` and stating one FAIL finding per user returned
    - Implement `execute(self) -> List[Dict[str, Any]]`:
      - Call `self._validate_metadata()` first
      - Set `region = self.GLOBAL_REGION` (`"us-east-1"`)
      - Call `response = self.list_users()`
      - If `"Error" in response`: append a single ERROR finding via `self.create_finding(status="ERROR", region=region, resource_id=self.account_id, actual_value=(message[:1000] if message else "Unknown error"), remediation="Verify the execution role has the iam:ListUsers permission attached.")` and `return self.findings`
      - Otherwise build a deduplicated list of users by ARN (preserving first occurrence) using a `Set[str]` to track seen ARNs
      - If the deduplicated list is empty: append a single PASS finding with `resource_id=self.account_id`, `actual_value="0 IAM users found in the account."`, `remediation="No remediation needed."`
      - Otherwise, for each distinct user, append one FAIL finding with `resource_id=user["Arn"]`, `actual_value=f"IAM user '{user.get('UserName', '')}' exists in the account."`, and a remediation string mentioning `"IAM Identity Center"`, `"IAM role"`, and `"delete"`
      - Return `self.findings`
    - _Requirements: 1.1, 1.3, 1.8, 1.9, 1.10, 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 7.1, 7.2, 7.3_

  - [ ]* 4.2 Write example-based unit tests in `sraverify/tests/services/iam/checks/test_sra_iam_01.py`
    - Create `sraverify/tests/services/iam/checks/__init__.py`
    - `test_metadata_attributes`: asserts `check_id == "SRA-IAM-01"`, `severity == "HIGH"`, `service == "IAM"`, `resource_type == "AWS::IAM::User"`, `account_type == "application"` (_Req 1.1–1.5_)
    - `test_metadata_content`: asserts **Property P8** string/length predicates on `check_name`, `description`, `check_logic` (_Req 7.1–7.3_)
    - `test_pass_on_zero_users`: mock `list_users` → `{"Users": []}`; expect 1 PASS finding with ResourceId=account_id, Region="us-east-1", ActualValue containing "0" and "IAM user", 1≤len≤256 (_Req 3.1–3.5_)
    - `test_fail_per_user`: mock with 3 distinct users; expect 3 FAIL findings with matching ARNs, ActualValue contains each UserName, Remediation contains "IAM Identity Center", "IAM role", "delete" (_Req 2.1–2.5_)
    - `test_dedup_duplicate_arns`: same ARN returned twice → only 1 FAIL finding (_Property P4_, _Req 2.1_)
    - `test_error_maps_to_error_finding`: `{"Error": {"Code": "AccessDenied", "Message": "denied"}}` → 1 ERROR finding; ActualValue == "denied"; Remediation contains "iam:ListUsers" (_Req 4.1–4.5_)
    - `test_error_empty_message_becomes_unknown`: `{"Error": {"Message": ""}}` → ActualValue == "Unknown error" (_Req 4.3_)
    - `test_error_message_truncated_1000`: `{"Error": {"Message": "x" * 5000}}` → `len(ActualValue) == 1000` (_Req 4.2_)
    - `test_no_pass_or_fail_when_error`: error response → all findings have Status=="ERROR" (_Req 4.6, Property P1_)
    - `test_region_always_us_east_1`: every branch → all findings have Region=="us-east-1" (_Property P5, Req 3.5_)
    - Reset `IAMCheck._users_cache` between tests; stub `account_id`/`account_name` on the check instance with a deterministic value
    - _Requirements: 1.1–1.5, 2.1–2.5, 3.1–3.5, 4.1–4.6, 7.1–7.3_

- [x] 5. Wire `SRA_IAM_01` into the IAM service package
  - Populate `services/iam/__init__.py` with `from sraverify.services.iam.checks.sra_iam_01 import SRA_IAM_01` and `CHECKS = {"SRA-IAM-01": SRA_IAM_01}`
  - Verify `CHECKS` contains exactly one entry mapping the string ID to the class (not an instance)
  - _Requirements: 6.1, 6.2_

- [x] 6. Register the IAM service in the CLI `main.py`
  - In `sraverify/sraverify/main.py`, add `from sraverify.services.iam import CHECKS as iam_checks` alongside the other service imports
  - Add `**iam_checks` to the `ALL_CHECKS` dictionary comprehension, preserving all existing entries and their order
  - Confirm no existing CHECKS entry is removed or replaced
  - _Requirements: 6.3, 6.4, 6.5, 6.6, 6.7, 6.8_

- [x] 7. Add `SRA-IAM-01` entry to `docs/checks.txt`
  - Append a line in the existing format: `  SRA-IAM-01: Account contains no IAM users (IAM) [application]`
  - Preserve the alphabetical/service grouping already used in the file
  - _Requirements: 6.5_

- [ ]* 8. Checkpoint - Ensure all unit tests pass
  - Run `pytest sraverify/tests/services/iam/` and confirm all example-based unit tests from tasks 2.2, 3.2, and 4.2 pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ]* 9. Add Hypothesis as a test-only dependency
  - Add `hypothesis` to a test-only requirements file (e.g. `sraverify/requirements-dev.txt`) without adding it to the runtime `requirements.txt`
  - If `requirements-dev.txt` does not exist, create it and include `pytest` and `hypothesis`
  - Document the install command in a short comment at the top of the file
  - _Requirements: supports PBT testing strategy_

- [ ]* 10. Author property-based tests for `SRA_IAM_01`
  - [ ]* 10.1 Create Hypothesis strategies and shared helpers in `sraverify/tests/services/iam/checks/test_sra_iam_01_properties.py`
    - Define `arn_strategy` (regex-generated IAM user ARNs of form `arn:aws:iam::<12 digits>:user/<name>`)
    - Define `user_strategy` as a dict with `Arn` and `UserName` keys
    - Define `response_success = st.builds(lambda users: {"Users": users}, st.lists(user_strategy, max_size=50))`
    - Define `response_error = st.builds(lambda code, msg: {"Error": {"Code": code, "Message": msg}}, st.sampled_from([...]), st.text(max_size=5000))`
    - Define `response = st.one_of(response_success, response_error)`
    - Create a `make_check(response_dict)` factory that returns an `SRA_IAM_01` with a mocked `IAM_Client` whose `list_users()` returns the response dict and stubbed `account_id`/`account_name`
    - Reset `IAMCheck._users_cache` in a pytest autouse fixture to isolate property examples
    - _Requirements: supports all PBT test cases_

  - [ ]* 10.2 Write property test for mutual exclusion
    - **Property P1: Mutually exclusive outcomes**
    - **Validates: Requirements 1.10, 3.6, 4.6**
    - `@given(response)` — assert every finding in `F` shares a single `Status` value (all PASS, all FAIL, or all ERROR)

  - [ ]* 10.3 Write property test for finding-count invariant
    - **Property P2: Finding-count invariant**
    - **Validates: Requirements 1.8, 1.9, 2.1, 3.1, 4.1**
    - `@given(response)` — assert: error response → `|F|=1` and Status=ERROR; success with 0 distinct users → `|F|=1` and Status=PASS; success with N distinct users → `|F|=N` and all Status=FAIL

  - [ ]* 10.4 Write property test for FAIL-finding ARN bijection
    - **Property P3: FAIL-finding ARN bijection**
    - **Validates: Requirements 2.1, 2.3**
    - `@given(response_success)` — assert `{f.ResourceId for f in F} == U(R)` when users exist and no error; no spurious ARNs; exactly one finding per ARN

  - [ ]* 10.5 Write property test for deduplication under duplicate ARNs
    - **Property P4: Deduplication under duplicate input ARNs**
    - **Validates: Requirements 1.9, 2.1**
    - `@given(st.lists(user_strategy, min_size=1, max_size=20))` — inject duplicates into the response; assert `|F_FAIL| == len(set(arns))`

  - [ ]* 10.6 Write property test for region constancy
    - **Property P5: Region constancy**
    - **Validates: Requirements 3.5, 4.5**
    - `@given(response)` — assert every finding has `Region == "us-east-1"` regardless of input

  - [ ]* 10.7 Write property test for ActualValue truncation bound
    - **Property P6: ActualValue truncation bound**
    - **Validates: Requirements 4.2, 4.3**
    - `@given(response_error)` — assert empty `Message` → `ActualValue == "Unknown error"`; non-empty → `ActualValue == Message[:1000]` and `len(ActualValue) ≤ 1000`

  - [ ]* 10.8 Write property test for caching idempotence
    - **Property P9: Caching idempotence**
    - **Validates: execution efficiency; indirectly protects Requirements 1.6, 2.1**
    - `@given(response)` — call `execute()` twice on the same check instance; assert `IAM_Client.list_users` was called at most once and both finding lists are equal in content

- [ ]* 11. Checkpoint - Ensure all property tests pass
  - Run `pytest sraverify/tests/services/iam/checks/test_sra_iam_01_properties.py` and confirm each property (P1, P2, P3, P4, P5, P6, P9) passes
  - Ensure all tests pass, ask the user if questions arise.

- [ ]* 12. Verify end-to-end registration via automated tests
  - [ ]* 12.1 Add a registration test in `sraverify/tests/services/iam/test_registration.py`
    - Assert `from sraverify.services.iam import CHECKS` contains exactly `{"SRA-IAM-01": SRA_IAM_01}` (class, not instance) (_Req 6.2_)
    - Assert `from sraverify.main import ALL_CHECKS; ALL_CHECKS["SRA-IAM-01"] is SRA_IAM_01` (_Req 6.3_)
    - Assert `docs/checks.txt` contains the exact token `SRA-IAM-01` (_Req 6.5_)
    - _Requirements: 6.2, 6.3, 6.5_

- [-] 13. Final checkpoint - Ensure the full test suite passes
  - Run `python -m py_compile sraverify/sraverify/services/iam/*.py sraverify/sraverify/services/iam/checks/*.py sraverify/sraverify/main.py` to confirm there are no syntax errors in the new or modified modules
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP, though they materially increase confidence in the correctness properties.
- Each task references specific requirements and, where applicable, a property from the design document (P1–P9) for traceability.
- Checkpoints (tasks 8, 11, 13) provide incremental validation at natural seams: after unit tests, after property tests, and after full integration.
- Property tests validate universal correctness properties (P1–P9); unit tests validate specific examples and edge cases; the registration test at task 12.1 closes the loop on CLI-facing requirements 6.2–6.5 without requiring live AWS calls.
- Implementation order (client → base → check → package `__init__` → `main.py` → docs → tests) follows the design's "Implementation Considerations → Ordering of Changes" section.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1"] },
    { "id": 1, "tasks": ["2.1"] },
    { "id": 2, "tasks": ["2.2", "3.1"] },
    { "id": 3, "tasks": ["3.2", "4.1"] },
    { "id": 4, "tasks": ["4.2", "5"] },
    { "id": 5, "tasks": ["6", "7"] },
    { "id": 6, "tasks": ["9", "10.1", "12.1"] },
    { "id": 7, "tasks": ["10.2", "10.3", "10.4", "10.5", "10.6", "10.7", "10.8"] }
  ]
}
```
