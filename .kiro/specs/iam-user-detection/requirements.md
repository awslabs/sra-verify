# Requirements Document

## Introduction

This document defines the requirements for a new SRA Verify security check that detects the presence of IAM users in an AWS account. AWS Security Reference Architecture (SRA) best practices recommend using federated identity through AWS IAM Identity Center (formerly AWS SSO) and assuming IAM roles, rather than provisioning long-lived IAM users with static credentials. The presence of any IAM user in an account indicates a deviation from SRA guidance and introduces risks associated with long-lived credentials, credential rotation, and identity sprawl.

This check is the first IAM service check in SRA Verify and is assigned the identifier SRA-IAM-01. It executes on every standard member account (account type `application`) and produces one HIGH severity FAIL finding per IAM user discovered. When no IAM users exist, the check produces a single PASS finding for the account.

## Glossary

- **SRA Verify**: Security assessment tool that automates verification of AWS Security Reference Architecture implementations.
- **AWS Security Reference Architecture (SRA)**: AWS prescriptive guidance for a multi-account security architecture.
- **IAM User**: An IAM identity with long-lived credentials (passwords, access keys) created within an AWS account via the IAM `CreateUser` API.
- **IAM Identity Center**: The AWS federated identity service (formerly AWS SSO) recommended by SRA for workforce identity.
- **IAM Role**: An IAM identity with temporary credentials assumed by principals; preferred by SRA over IAM users.
- **Application Account**: An AWS account with the `account_type` value `application` in SRA Verify, representing a standard member workload account.
- **Global Region**: The AWS IAM service is a global service; API calls are made to the `us-east-1` endpoint and results apply account-wide.
- **Finding**: A result produced by a security check containing a status (PASS, FAIL, or ERROR), a resource identifier, and remediation guidance.
- **Check**: A single unit of validation in SRA Verify identified by a `check_id` of the form `SRA-{SERVICE}-##`.
- **IAM_User_Check**: The SRA Verify component identified by check ID `SRA-IAM-01` that detects IAM users in an account.
- **IAM_Client**: The SRA Verify wrapper around the boto3 `iam` client used by the IAM service checks.
- **API Failure**: Any outcome of a `ListUsers` invocation that is not a successful response, including service-returned errors, client-raised exceptions, access-denied responses, and timeouts.

## Requirements

### Requirement 1: Detect IAM users in an account

**User Story:** As a security administrator, I want SRA Verify to detect every IAM user in an account, so that I can identify deviations from the SRA recommendation to use federated identity and IAM roles instead of long-lived IAM users.

**Check Title:** Account contains no IAM users (SRA-IAM-01)

#### Acceptance Criteria

1. THE IAM_User_Check SHALL be registered with check ID "SRA-IAM-01".
2. THE IAM_User_Check SHALL be assigned account type "application".
3. THE IAM_User_Check SHALL be assigned severity "HIGH".
4. THE IAM_User_Check SHALL be assigned service name "IAM".
5. THE IAM_User_Check SHALL be assigned resource type "AWS::IAM::User".
6. WHEN the IAM_User_Check executes, THE IAM_User_Check SHALL enumerate all IAM users in the account by calling the IAM `ListUsers` API through the IAM_Client against the global IAM endpoint in region "us-east-1".
7. WHEN the IAM `ListUsers` response contains a non-empty pagination continuation token, THE IAM_User_Check SHALL continue calling `ListUsers` with that token until a response is returned with no continuation token, and SHALL evaluate the union of IAM users returned across all pages before producing findings.
8. WHEN the enumeration in Acceptance Criterion 6 completes with exactly 0 IAM users returned, THE IAM_User_Check SHALL produce exactly one PASS finding for the account under evaluation as specified by Requirement 3.
9. WHEN the enumeration in Acceptance Criterion 6 completes with one or more IAM users returned, THE IAM_User_Check SHALL produce one FAIL finding per distinct IAM user ARN as specified by Requirement 2.
10. IF the IAM `ListUsers` invocation results in an API Failure at any point during enumeration or pagination, THEN THE IAM_User_Check SHALL halt enumeration, produce exactly one ERROR finding as specified by Requirement 4, and produce no PASS or FAIL findings for the same check execution.

### Requirement 2: Produce one FAIL finding per IAM user

**User Story:** As a security administrator, I want one finding per IAM user, so that I can track and remediate each user individually in reporting and dashboards.

**Check Title:** One FAIL finding per IAM user (SRA-IAM-01)

#### Acceptance Criteria

1. WHEN the IAM_User_Check invokes the IAM `ListUsers` API and receives one or more IAM users, including all users retrieved across paginated responses, THE IAM_User_Check SHALL create exactly one finding per distinct IAM user ARN.
2. WHEN the IAM_User_Check creates a finding for an IAM user, THE IAM_User_Check SHALL set the finding Status field to the exact string value "FAIL".
3. WHEN the IAM_User_Check creates a finding for an IAM user, THE IAM_User_Check SHALL set the finding ResourceId field to the IAM user Amazon Resource Name (ARN) returned by the IAM `ListUsers` API for that user.
4. WHEN the IAM_User_Check creates a finding for an IAM user, THE IAM_User_Check SHALL set the finding ActualValue field to a non-empty string that contains the IAM user name returned by the IAM `ListUsers` API for that user.
5. WHEN the IAM_User_Check creates a finding for an IAM user, THE IAM_User_Check SHALL set the finding Remediation field to guidance that instructs the administrator to replace the IAM user with federated access through AWS IAM Identity Center or an IAM role, and to delete the IAM user after migration is complete.
6. IF the IAM_User_Check invokes the IAM `ListUsers` API and receives zero IAM users for the account, THEN THE IAM_User_Check SHALL create zero FAIL findings for that account.
7. IF the IAM `ListUsers` API call results in an API Failure, THEN THE IAM_User_Check SHALL create zero FAIL findings for that execution and SHALL defer to Requirement 4 for the ERROR finding.

### Requirement 3: Produce a PASS finding when no IAM users exist

**User Story:** As a security administrator, I want a PASS finding when no IAM users exist, so that I have a positive confirmation in reporting that the account complies with SRA guidance.

**Check Title:** PASS finding when no IAM users are present (SRA-IAM-01)

#### Acceptance Criteria

1. WHEN the IAM `ListUsers` API call succeeds, all response pages are retrieved, and the combined pages return exactly 0 IAM users, THE IAM_User_Check SHALL create exactly one finding.
2. WHEN the IAM_User_Check creates the finding described in Requirement 3 Acceptance Criterion 1, THE IAM_User_Check SHALL set the finding Status field to the exact string value "PASS".
3. WHEN the IAM_User_Check creates the finding described in Requirement 3 Acceptance Criterion 1, THE IAM_User_Check SHALL set the finding ResourceId field to the 12-digit AWS account identifier of the account under evaluation.
4. WHEN the IAM_User_Check creates the finding described in Requirement 3 Acceptance Criterion 1, THE IAM_User_Check SHALL set the finding ActualValue field to a non-empty string between 1 and 256 characters that explicitly states that 0 IAM users were found in the account.
5. WHEN the IAM_User_Check creates the finding described in Requirement 3 Acceptance Criterion 1, THE IAM_User_Check SHALL set the finding Region field to "us-east-1".
6. IF the IAM `ListUsers` API call results in an API Failure at any point during enumeration or pagination, THEN THE IAM_User_Check SHALL NOT create the PASS finding described in Requirement 3 Acceptance Criterion 1.

### Requirement 4: Handle API errors explicitly

**User Story:** As a security administrator, I want explicit ERROR findings when the IAM API call fails, so that I can distinguish permission or service failures from genuine PASS or FAIL results.

**Check Title:** ERROR finding when IAM API calls fail (SRA-IAM-01)

#### Acceptance Criteria

1. IF the IAM `ListUsers` API call results in an API Failure, including a service-returned error, a client-raised exception, an access-denied response, or a timeout, THEN THE IAM_User_Check SHALL create exactly one finding with the Status field set to the exact string value "ERROR" for the executing account and region.
2. IF the IAM `ListUsers` API call returns an error response with a non-empty error message, THEN THE IAM_User_Check SHALL set the finding ActualValue field to that error message truncated to at most 1000 characters.
3. IF the IAM `ListUsers` API call results in an API Failure with no error message available or with an empty error message, THEN THE IAM_User_Check SHALL set the finding ActualValue field to the exact string "Unknown error".
4. IF the IAM `ListUsers` API call results in an API Failure, THEN THE IAM_User_Check SHALL set the finding Remediation field to text instructing the administrator to verify the execution role has the `iam:ListUsers` IAM permission attached.
5. IF the IAM `ListUsers` API call results in an API Failure, THEN THE IAM_User_Check SHALL set the finding Region field to "us-east-1", the AccountId and AccountName fields from the SRA Verify base class, and the ResourceId field to the 12-digit AWS account identifier of the account under evaluation.
6. IF the IAM `ListUsers` API call results in an API Failure, THEN THE IAM_User_Check SHALL NOT create any finding with a Status value of "PASS" or "FAIL" during the same check execution.

### Requirement 5: Run on every application account

**User Story:** As a security administrator, I want this check to run on every standard member account, so that no account is exempt from IAM user detection.

**Check Title:** Check runs on all application accounts (SRA-IAM-01)

#### Acceptance Criteria

1. WHEN SRA Verify executes with account type filter "application", THE IAM_User_Check SHALL be included in the execution set and produce at least one finding with a Status of PASS, FAIL, or ERROR for the account under evaluation.
2. WHEN SRA Verify executes without an account type filter, THE IAM_User_Check SHALL be included in the execution set and produce at least one finding with a Status of PASS, FAIL, or ERROR for the account under evaluation.
3. IF SRA Verify executes with an account type filter set to a value other than "application" (such as "audit", "log-archive", or "management") and no explicit check selection targets SRA-IAM-01, THEN THE IAM_User_Check SHALL be excluded from the execution set and produce no findings.
4. THE IAM_User_Check SHALL produce findings that contain a non-empty AccountId field equal to the 12-digit AWS account identifier of the account under evaluation as populated by the SRA Verify base class.
5. THE IAM_User_Check SHALL produce findings that contain a non-empty AccountName field equal to the account name of the account under evaluation as populated by the SRA Verify base class.

### Requirement 6: Register the check with SRA Verify

**User Story:** As a developer, I want the new check registered in the SRA Verify framework, so that the check is discoverable by the CLI and executed by the orchestrator.

**Check Title:** IAM service and SRA-IAM-01 check registration

#### Acceptance Criteria

1. THE SRA Verify package SHALL contain an IAM service module at `sraverify/sraverify/services/iam/` that includes the files `__init__.py`, `base.py`, `client.py`, and a `checks/` subdirectory containing `sra_iam_01.py`.
2. THE IAM service `__init__.py` module SHALL expose a `CHECKS` dictionary that contains exactly one entry mapping the string "SRA-IAM-01" to the IAM_User_Check class reference (not an instance).
3. WHEN the SRA Verify `main.py` module composes its `ALL_CHECKS` registry, THE SRA Verify `main.py` module SHALL merge the IAM service `CHECKS` dictionary into `ALL_CHECKS` such that `ALL_CHECKS["SRA-IAM-01"]` resolves to the IAM_User_Check class and no previously registered check entries are removed or replaced.
4. WHEN the user runs `sraverify --list-services`, THE SRA Verify system SHALL include the exact token "IAM" in standard output and SHALL exit with exit code 0 within 10 seconds.
5. WHEN the user runs `sraverify --list-checks`, THE SRA Verify system SHALL include the exact token "SRA-IAM-01" in standard output and SHALL exit with exit code 0 within 10 seconds.
6. WHEN the user runs `sraverify --check SRA-IAM-01` with valid AWS credentials and a resolvable region list, THE SRA Verify system SHALL invoke the IAM_User_Check `execute` method exactly once per target account and produce findings as defined in Requirements 1 through 5.
7. IF the user runs `sraverify --check SRA-IAM-01` before the IAM service module is registered or if the check ID cannot be resolved, THEN THE SRA Verify system SHALL exit with a non-zero exit code and SHALL emit an error indicating the unknown check ID without invoking IAM_User_Check.
8. IF the IAM_User_Check `execute` method raises an unhandled exception during a `sraverify --check SRA-IAM-01` invocation, THEN THE SRA Verify system SHALL record an ERROR finding for the execution and SHALL continue executing any remaining target accounts without aborting the overall run.

### Requirement 7: Provide metadata consistent with SRA Verify conventions

**User Story:** As a security administrator, I want the check metadata to clearly describe what is being validated and why, so that findings in reports and dashboards are self-explanatory.

**Check Title:** Check metadata for SRA-IAM-01

#### Acceptance Criteria

1. THE IAM_User_Check SHALL define a check_name attribute as a non-empty string between 1 and 200 characters that contains the phrase "IAM user" and describes the validation performed in a single sentence terminated by a period.
2. THE IAM_User_Check SHALL define a description attribute as a non-empty string between 1 and 2000 characters that contains the phrases "IAM user", "long-lived credential", "IAM Identity Center", and "IAM role".
3. THE IAM_User_Check SHALL define a check_logic attribute as a non-empty string between 1 and 1000 characters that contains the phrase "ListUsers" and states that one FAIL finding is created for each IAM user returned by the API call.
4. IF the IAM_User_Check is instantiated and any of the check_name, description, or check_logic attributes is undefined, null, or an empty string, THEN THE IAM_User_Check SHALL raise an initialization error indicating which metadata attribute is missing and SHALL NOT execute the check.
