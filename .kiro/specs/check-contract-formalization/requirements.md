# Requirements Document

## Introduction

The scanner's check layer is held together by convention rather than by contract. A check is any class that subclasses a service base class, sets a handful of instance attributes in `__init__`, and is remembered in two hand-maintained dictionaries. Findings are raw `dict` objects assembled by a base-class helper, and the sixteen-column CSV schema those dicts feed is declared independently in a second module. Nothing in the code enforces that a check's ID matches its class name, that its file is registered, that its severity is one of four legal values, or that a produced finding carries all sixteen fields.

This feature replaces those conventions with enforced contracts. Metadata moves out of `__init__` into a frozen, validated `CheckMeta` declared in the check's own class body and assigned to the class attribute `meta`. Registration becomes automatic, and the same mechanism cross-checks four independent expressions of a check's identity and refuses to register a class whose file, class name, and metadata disagree. The check base class becomes an abstract base class with a single abstract method, `execute()`, which yields `Finding` objects — a frozen, slotted, fully typed dataclass that owns the CSV contract. Selection filters read class attributes instead of constructing objects.

Declaring metadata as typed Python makes a missing field, a misspelled keyword, and an illegal enum value a static type error rather than a run-time validation failure. Four of the metadata fields — `sra_sections`, `additional_urls`, `remediation.cli`, and `remediation.console` — are carried but consumed by nothing in this phase; they are declared now so that a machine-readable catalog can be generated from the registry when one is wanted, where it cannot drift from the code.

The measured defects this addresses, all counted against the current tree:

- Of 158 check files, 79 build a local `findings` list and 79 append to `self.findings`, so `get_findings()` returns an empty list for exactly half the catalog.
- Registration costs roughly 354 lines of mechanical boilerplate across `main.py` and 18 service `__init__.py` files, and requires two edits per new check; missing either means the check silently never runs.
- Because metadata lives on instances, the orchestrator constructs checks purely to read it: 474 instantiations for a default scan and 161 for a single `--check`.
- Of 468 literal remediation arguments, 178 are semantically empty across three different spellings.
- The base class declares `severity = "Unknown"` and `check_id = None`, neither of which is a legal value for its column, and one service base class sets an account type that is not a legal CLI value.

All 158 checks across all 18 services migrate in a single atomic change. The acceptance gate is a catalog-wide before/after CSV comparison that shows only five expected categories of cell change. The per-scan isolation model established by the preceding scan-context refactor is preserved in full.

## Glossary

### Domain terms

- **Check**: One security control evaluation, implemented as a class in `services/<svc>/checks/sra_<svc>_NN.py` and identified by a check ID of the form `SRA-<SERVICE>-NN`.
- **Finding**: One row of scanner output, describing the outcome of one check for one region and one resource. Carries a status of `PASS`, `FAIL`, or `ERROR`.
- **Catalog**: The complete set of checks known to the scanner — 158 checks across 18 AWS services.
- **Check metadata**: A frozen `CheckMeta` value declared in a check class's own body and assigned to the class attribute `meta`, holding that check's ID, title, description, check logic, severity, account type, service, resource type, remediation, SRA sections, and additional URLs. Constructed, and therefore validated, while the check module's class body executes at import time.
- **Registry**: The single authoritative mapping of check ID to check class, populated at import time and read-only thereafter.
- **Service base class**: The `<Service>Check` class in `services/<svc>/base.py`. Declares the cache `NAMESPACE` constant and the cached typed accessors that check bodies call. Not itself a check.
- **Per-scan context**: The `ScanContext` instance created once per `run_checks` call. Owns the boto3 session, the region list, the audit and log-archive account lists, the bounded client config, the client cache, and the namespaced response cache.
- **16-column contract**: The fixed CSV column set and column order — `AccountId`, `AccountName`, `Region`, `CheckId`, `Status`, `Severity`, `Title`, `Description`, `ResourceId`, `ResourceType`, `CheckedValue`, `ActualValue`, `Remediation`, `Service`, `CheckLogic`, `AccountType` — parsed by the two standalone HTML dashboards.

### System names used in acceptance criteria

- **Scanner**: The `sraverify` package as a whole.
- **Finding_Model**: The `Finding` frozen dataclass and its `FIELDS` and `to_row()` members.
- **Check_Metadata**: The `CheckMeta` frozen dataclass, its `Remediation` member type, and the `meta` class attribute that carries one `CheckMeta` per check class.
- **Metadata_Validator**: The validation performed when a `CheckMeta` instance is constructed.
- **Registration_Hook**: The subclass-creation hook on the check base class that reads metadata, cross-checks identity, and registers the class.
- **Check_Registry**: The registry module that stores and exposes the catalog.
- **Check_Discovery**: The import-time traversal that imports service packages and check modules.
- **Check_Base_Class**: The `SecurityCheck` abstract base class.
- **Finding_Helpers**: The `passed()`, `failed()`, and `error()` methods on the check base class.
- **CSV_Writer**: The `write_csv_output` function.
- **Check_Selector**: The filter resolution that turns CLI arguments into the set of checks to run.
- **CLI**: The `sraverify` console-script entry point.
- **Scan_Orchestrator**: The `SRAVerify.run_checks` loop.
- **Check_Catalog**: The 158 migrated check modules, considered as one deliverable.
- **Acceptance_Gate**: The catalog-wide before/after CSV comparison that admits or rejects the migration.
- **Package_Build**: The setuptools configuration in `setup.py`.

## Out of Scope

The following are deliberately excluded. Each exclusion carries the design's reasoning and its accepted cost.

1. **Per-operation AWS error classification.** The FAIL-versus-ERROR mapping is a function of the pair (operation, error code), not of service: `BadRequestException` is correctly an ERROR when reached through `ListOrganizationAdminAccounts` and correctly a FAIL when reached through `DescribeOrganizationConfiguration`. That judgment stays in the 34 check bodies that hold it today. Clients continue to return `{"Error": {"Code", "Message"}}` without raising, and `error()` remains a public helper because checks still author their own ERROR findings.

2. **A base-driven region loop.** No `evaluate(region)` hook and no `Scope` enum. Introducing one would restructure all 158 check bodies. Accepted consequences: the region loop stays duplicated across 96 region-iterating checks, 36 global checks, and 26 checks pinned to `us-east-1`; Shield keeps writing `Region=us-east-1` where the convention says `global`; and error isolation stays per-check rather than per-region.

3. **Typed per-service resource models.** No `Detector` model or equivalent. Accessor return types stay as they are.

4. **Test harness and CI.** A separate later phase. This document specifies the correctness properties that phase must target, but adds no harness. One orphaned test module that breaks bare test collection is deleted.

5. **`pyproject.toml` and broader packaging migration.** Out of scope except for the single mandatory `setup.py` change covered by Requirement 12.

6. **A generated machine-readable catalog.** Emitting the catalog as a machine-readable artifact — JSON for a documentation site, or an SRA-section coverage report — is deferred to a later phase. Generating it from the registry is the intended direction: `sra_sections` and `additional_urls` are declared in metadata now, so the data exists, and an artifact generated from the registry cannot drift from the code.

## Requirements

### Requirement 1: Formalized finding model

**User Story:** As a maintainer of the scanner, I want every finding to be a typed immutable object that owns the CSV column contract, so that a finding missing a column or carrying an illegal value fails inside the check that produced it rather than reaching the report.

#### Acceptance Criteria

1. THE Finding_Model SHALL define exactly sixteen fields: `check_id`, `status`, `region`, `severity`, `title`, `description`, `resource_id`, `resource_type`, `account_id`, `account_name`, `checked_value`, `actual_value`, `remediation`, `service`, `check_logic`, and `account_type`.
2. THE Finding_Model SHALL declare all sixteen fields with no default value, so that omitting any field at construction raises `TypeError`, SHALL type `resource_id` as the single field admitting a null value, and SHALL admit the empty string as a legal value of every string-typed field, so that a PASS Finding can carry an empty `remediation` and an unresolved account identity can carry an empty `account_id` and `account_name`.
3. THE Finding_Model SHALL type `status` as `Status`, `severity` as `Severity`, and `account_type` as `AccountType`, where the members of `Status` carry the values `PASS`, `FAIL`, and `ERROR`; the members of `Severity` carry the values `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW`; and the members of `AccountType` carry the values `application`, `audit`, `log-archive`, and `management`.
4. THE Finding_Model SHALL expose `FIELDS` as an immutable sequence that is the single declaration of the sixteen CSV column names in the order stated in the Glossary entry for the 16-column contract, where each `FIELDS` entry corresponds to exactly one field named in criterion 1, being the field whose name is that column name rendered in lower-case snake case.
5. WHEN `to_row()` is called on a Finding, THE Finding_Model SHALL return a mapping whose keys equal `FIELDS` in `FIELDS` order.
6. WHEN `to_row()` is called on a Finding, THE Finding_Model SHALL render `status`, `severity`, and `account_type` as the enum member's `value`, SHALL render a null `resource_id` as the empty string, and SHALL return the stored string unchanged for every remaining field, applying no coercion, so that a non-string value cannot render as its `repr`.
7. WHEN `to_row()` is called on a Finding, THE Finding_Model SHALL leave the receiving Finding unmodified.
8. IF a value supplied for `status`, `severity`, or `account_type` at construction is neither a member of the corresponding enum nor a string equal to the `value` of one of that enum's members, THEN THE Finding_Model SHALL raise `ValueError` naming the field and the rejected value, because a dataclass field annotation performs no run-time type check and an unvalidated string would otherwise reach the CSV.
9. IF a caller assigns to any field of a constructed Finding, THEN THE Finding_Model SHALL raise `FrozenInstanceError`.
10. THE Finding_Model SHALL declare slotted storage so that construction allocates no per-instance attribute dictionary.
11. THE Finding_Model SHALL hold, for every field, either a string, a member of `Status`, `Severity`, or `AccountType`, or a null value in `resource_id`, so that a Finding holds no reference to a check instance, to the per-scan context, or to any mutable object.
12. IF the `title` supplied at construction does not begin with the value of `check_id` followed by exactly one space, THEN THE Finding_Model SHALL raise `ValueError` naming both values.
13. THE Finding_Model SHALL export the constant `GLOBAL_REGION` with the value `global` for use by non-regional checks.
14. WHEN a Finding is constructed, THE Finding_Model SHALL convert the supplied `status`, `severity`, and `account_type` to the corresponding enum member, so that the constructed Finding carries an enum member for each of the three whether the caller supplied a member or that member's string value.
15. WHEN `to_row()` is called on a Finding, THE Finding_Model SHALL return each value with every embedded comma, double quote, and line break preserved unchanged, applying no quoting, no escaping, and no truncation, so that delimiter handling belongs solely to the CSV_Writer and no value is escaped twice.
16. IF a value supplied for any field other than `resource_id`, `status`, `severity`, and `account_type` is not a string, THEN THE Finding_Model SHALL raise `TypeError` naming the field, so that a null value cannot reach the CSV as the text `None`.

### Requirement 2: Check metadata as a validated class attribute

**User Story:** As a check author, I want a check's metadata to be a frozen typed value declared in its own class body, so that metadata is data rather than imperative instance state, a wrong field name or an illegal enum value is a static type error, and the scanner reads no file to learn what a check is.

#### Acceptance Criteria

1. THE Check_Catalog SHALL declare each check's metadata as a `CheckMeta` value assigned to the class attribute `meta` in that check's own class body.
2. THE Check_Metadata SHALL carry `check_id`, `title`, `description`, `check_logic`, `severity`, `account_type`, `service`, `resource_type`, and `remediation` as required fields, and `sra_sections` and `additional_urls` as optional fields defaulting to an empty tuple, where `remediation` carries `text` as a required value and `cli` and `console` as optional values defaulting to the empty string.
3. THE Check_Metadata SHALL declare `severity` as a member of `Severity` and `account_type` as a member of `AccountType` rather than as a string, so that a static type checker rejects an illegal value before the scanner runs and no string-to-enum conversion step exists.
4. THE Check_Metadata SHALL declare `sra_sections` and `additional_urls` as tuples of strings and `remediation` as an immutable value exposing `text`, `cli`, and `console`, so that a `CheckMeta` holds no list, no dict, and no set, hashing a `CheckMeta` succeeds, and assignment to any `CheckMeta` field or to any `remediation` member raises.
5. IF a `CheckMeta` is constructed with a keyword argument that is not a `CheckMeta` field name, or without a value for a required field, THEN THE Check_Metadata SHALL raise `TypeError` while the declaring class body executes, so that the strict-key rule needs no code of its own and a misspelled field name fails at import rather than being silently ignored.
6. THE Check_Metadata SHALL carry only values written literally in the check module that declares it, so that no value derived from an AWS API response and no value derived from the invocation can enter a `CheckMeta`, and two scans in one process necessarily observe identical metadata for a given check.
7. THE Scanner SHALL read no file at run time to obtain check metadata.

### Requirement 3: Metadata validation rules

**User Story:** As a reviewer of the catalog, I want every metadata value checked against an explicit rule when it is constructed, so that an illegal check ID, an empty title, or mangled description text becomes an import failure instead of a defective CSV cell.

#### Acceptance Criteria

1. IF `check_id` does not match `^SRA-[A-Z0-9]+-\d{2}$` over the whole value, compared case-sensitively against ASCII characters only so that a non-ASCII digit does not satisfy the numeric segment, THEN THE Metadata_Validator SHALL raise `MetadataError` naming the field, the offending value, and the defining module file.
2. IF `resource_type` does not match `^AWS::[A-Za-z0-9]+::[A-Za-z0-9]+$` over the whole value, compared case-sensitively against ASCII characters only, THEN THE Metadata_Validator SHALL raise `MetadataError` naming the field, the offending value, and the check ID together with the defining module file.
3. IF `title`, `description`, `check_logic`, or `service` is empty after stripping surrounding whitespace, THEN THE Metadata_Validator SHALL raise `MetadataError` naming the field and the check ID together with the defining module file.
4. IF `title`, `description`, `check_logic`, `service`, `remediation.text`, or any `sra_sections` element differs from the same value with each run of one or more Unicode whitespace characters collapsed to one space and with surrounding whitespace removed, THEN THE Metadata_Validator SHALL raise `MetadataError` naming the field, the offending value, and the check ID together with the defining module file, applying this rule to no other field so that `remediation.cli` and `remediation.console` remain exempt and may carry the line breaks and alignment a command example needs, and standing as the defense against the backslash-continuation defect that leaks a run of whitespace into a `Description` cell by operating on the rendered value rather than on the source.
5. IF the first whitespace-delimited token of `title`, with trailing punctuation removed and compared without regard to letter case, equals `ensure`, `ensures`, `check`, or `checks`, THEN THE Metadata_Validator SHALL raise `MetadataError` naming the field and the check ID together with the defining module file, so that a title states the control as a fact and reads correctly on both a PASS row and a FAIL row, while a title whose first token is `Checkpoint` or `Ensured` is accepted.
6. IF `title` exceeds 120 characters, `description` exceeds 1200 characters, `check_logic` exceeds 400 characters, `service` exceeds 60 characters, `remediation.text` exceeds 1000 characters, or `remediation.cli` or `remediation.console` exceeds 2000 characters, counting Unicode code points, THEN THE Metadata_Validator SHALL raise `MetadataError` naming the field, the measured length, the applicable maximum, and the check ID together with the defining module file.
7. IF `remediation.text` is empty after stripping surrounding whitespace, THEN THE Metadata_Validator SHALL raise `MetadataError` naming the field and the check ID together with the defining module file.
8. IF any `additional_urls` element does not begin with `https://`, carries no character after `https://`, contains a whitespace character, or exceeds 500 characters, THEN THE Metadata_Validator SHALL raise `MetadataError` naming the offending value and the check ID together with the defining module file.
9. IF any `sra_sections` element is empty after stripping surrounding whitespace or exceeds 200 characters, THEN THE Metadata_Validator SHALL raise `MetadataError` naming the offending value and the check ID together with the defining module file.
10. THE Metadata_Validator SHALL apply the rules of criteria 1 through 9 and criterion 13 in ascending criterion order, SHALL stop at the first rule that fails, and SHALL report only that rule, so that a `CheckMeta` declaration violating two rules always produces the same error.
11. THE Metadata_Validator SHALL run during `CheckMeta` construction, so that a `CheckMeta` instance that fails any rule is unreachable by any caller and a check module declaring a defective `CheckMeta` fails at import.
12. THE Metadata_Validator SHALL validate using only the Python standard library.
13. IF `sra_sections` or `additional_urls` holds more than 20 elements, THEN THE Metadata_Validator SHALL raise `MetadataError` naming the field, the element count, the maximum, and the check ID together with the defining module file.

### Requirement 4: Automatic registration and identity enforcement

**User Story:** As a check author, I want adding a check file to be the whole of registering it, so that the current failure mode where a check is written, appears correct, and silently never runs becomes impossible.

#### Acceptance Criteria

1. WHEN a subclass of the Check_Base_Class is created from a module whose file stem begins with `sra_`, THE Registration_Hook SHALL derive the expected check ID from the module file stem, read `meta` from the class body, verify the metadata `check_id` and the subclass name against the derived check ID, verify the containing service package, and then add the subclass to the Check_Registry under the metadata `check_id`, performing those steps in that order.
2. IF a subclass of the Check_Base_Class is created from a module whose file stem does not begin with `sra_`, THEN THE Registration_Hook SHALL leave the subclass unregistered, so that the service base classes in `base.py` and any intermediate subclass declared outside a `sra_*` module stay out of the catalog.
3. WHEN the Registration_Hook processes a check class, THE Registration_Hook SHALL derive the expected check ID from the module file stem by upper-casing the service segment and joining `SRA`, the service segment, and the two-digit number with hyphens, and that derivation SHALL be reversible so that lower-casing the derived check ID and replacing each hyphen with an underscore reproduces the module file stem exactly.
4. IF a check module's file stem does not match `^sra_[a-z][a-z0-9]*_(0[1-9]|[1-9][0-9])$` over the whole stem against ASCII characters only, requiring the service segment to begin with a lower-case letter and the number to lie in `01` through `99`, THEN THE Registration_Hook SHALL raise `CheckIdentityError` naming the module file, and that two-digit range SHALL cap one service at 99 checks.
5. IF the metadata `check_id` differs from the check ID derived from the module file stem, THEN THE Registration_Hook SHALL raise `CheckIdentityError` naming both values and the module file.
6. IF the check class name differs from the derived check ID with each hyphen replaced by an underscore, THEN THE Registration_Hook SHALL raise `CheckIdentityError` naming both values and the module file, applying this rule to every subclass of the Check_Base_Class created inside a `sra_*` module so that a second subclass or an intermediate subclass declared in that module fails at import rather than registering under a check ID it does not own.
7. IF a check ID already present in the Check_Registry is claimed by a different class, THEN THE Check_Registry SHALL raise `DuplicateCheckIdError` naming the check ID and both classes.
8. WHEN the same class is registered again under the same check ID, THE Check_Registry SHALL complete without raising, so that a module imported twice under the same name stays harmless.
9. THE Check_Registry SHALL expose the catalog as a read-only mapping ordered by ascending lexicographic check ID, so that inventory output and duplicate diagnostics are reproducible.
10. THE Registration_Hook SHALL complete registration and identity enforcement without issuing any AWS API call.
11. THE Check_Registry SHALL be the only source of the catalog, so that the scanner holds no hand-maintained check import list and no hand-maintained check dictionary.
12. THE Registration_Hook SHALL determine registration eligibility from the defining module's file name rather than from the presence of a `meta` class attribute, so that a check declaring no `meta` raises rather than being skipped, because eligibility keyed on `meta` would conflate a class that is not a check with a check whose author forgot to declare metadata, and those two must not share a code path.
13. IF the module named by a subclass's `__module__` is absent from the loaded-module table or carries no file location, THEN THE Registration_Hook SHALL leave the subclass unregistered and SHALL raise no error, so that a class created dynamically, created by `exec`, or created in an interactive session is not treated as a check, and WHERE that module is present in the loaded-module table and carries a file location, THE Registration_Hook SHALL proceed with the processing of criterion 1, so that absence from the loaded-module table and a missing file location are the only two conditions this criterion admits as grounds for leaving a subclass unregistered.
14. IF the service segment of the derived check ID, lower-cased, differs from the name of the service package containing the check module's `checks` package, THEN THE Registration_Hook SHALL raise `CheckIdentityError` naming both values and the module file, so that a check module filed under the wrong service package fails at import rather than registering cleanly and running against the wrong service base class.
15. IF any identity rule fails for a check class, or the class declares no `meta`, THEN THE Registration_Hook SHALL leave the Check_Registry unchanged, so that a failed import contributes no partial catalog entry.
16. IF a subclass of the Check_Base_Class created from a module whose file stem begins with `sra_` declares no `meta` class attribute, THEN THE Registration_Hook SHALL raise `CheckIdentityError` naming the class and the module file.

### Requirement 5: Check discovery

**User Story:** As a check author, I want the presence of a check module on disk to be its registration, so that the roughly 354 lines of double-entry registration boilerplate and the two mandatory edits per check disappear.

#### Acceptance Criteria

1. WHEN a service package is imported, THE Check_Discovery SHALL import every non-package module in that package's `checks` subpackage whose name begins with `sra_`, in ascending lexicographic name order, and SHALL import no subpackage of `checks` and no module whose name does not begin with `sra_`.
2. WHEN the `services` package is imported, THE Check_Discovery SHALL import every service subpackage in ascending lexicographic name order, and SHALL import no non-package module at the `services` level.
3. WHEN discovery completes for a package, THE Check_Discovery SHALL return the list of imported module names in import order to the caller, and SHALL return an empty list when no module matches.
4. WHEN discovery of the `services` package completes, THE Check_Registry SHALL hold exactly one entry for each check module file present under `services/*/checks/sra_*.py`, and each Check_Registry entry SHALL correspond to exactly one such file, so that the Check_Registry entry count equals the check module file count.
5. WHEN a check module is added to a service's `checks` package, THE Check_Discovery SHALL register the check without any edit to an import list or a dictionary.
6. THE Check_Discovery SHALL resolve service packages and check modules by name at run time, so that no `core` module declares a static import of a service package.
7. IF a discovered check module fails to import, or a service package carries no `checks` subpackage, THEN THE Check_Discovery SHALL propagate the exception unchanged, so that the process exits before any AWS API call is issued, before any output file is written, and without exposing a partially populated catalog.
8. THE Check_Discovery SHALL complete discovery and import without issuing any AWS API call, so that importing the `services` package requires no credentials.
9. WHEN the `services` package or a service package is imported a second time in one process, THE Check_Discovery SHALL import no module a second time and SHALL add no Check_Registry entry.

### Requirement 6: Check execution contract

**User Story:** As a maintainer of the scanner, I want `execute()` to be the only source of findings and the only method a check must implement, so that the 79-of-158 accumulator divergence cannot re-form and a misspelled `execute` fails immediately rather than when that check happens to run.

#### Acceptance Criteria

1. THE Check_Base_Class SHALL be an abstract base class declaring `execute()` as its single abstract method, taking no parameter other than the instance and returning `Iterable[Finding]`, a return type that a generator function satisfies.
2. IF a registered check class leaves `execute()` unimplemented, THEN THE Check_Base_Class SHALL raise `TypeError` naming the class and the unimplemented method at construction, before `initialize(ctx)` runs.
3. THE Check_Base_Class SHALL omit `create_finding`, the `findings` instance attribute, and `get_findings`, so that the Findings yielded or returned by `execute()` are the only source of findings.
4. WHEN a check's `execute()` returns normally having yielded no Finding, THE Scan_Orchestrator SHALL record zero Findings for that check, so that the check contributes no row, and SHALL synthesize no Finding for that check, so that a bare `return` inside `execute()` is a legal early exit, and WHERE `execute()` instead terminates exceptionally, by an exception escaping `execute()` or by the check being terminated before `execute()` returns, THE Scan_Orchestrator SHALL retain the synthetic ERROR Finding that Requirement 10 requires.
5. THE Check_Base_Class SHALL accept no constructor parameter other than the instance, and construction SHALL set the per-scan context reference to a null value and the client mapping to empty.
6. THE Check_Base_Class SHALL expose `check_id`, `service`, `severity`, and `account_type` as read-only properties returning the corresponding `meta` field.
7. IF a check assigns to `check_id`, `service`, `severity`, or `account_type`, THEN THE Check_Base_Class SHALL raise `AttributeError` naming the property, so that each of the 90 post-constructor account-type assignments in the current tree fails at the point of assignment rather than shadowing metadata.
8. THE Check_Base_Class SHALL retain `initialize(ctx)` as the single initialization path, together with the `_setup_clients()` subclass hook, `get_client()`, and `get_management_accountId()`.
9. THE Check_Base_Class SHALL retain `session`, `regions`, `account_info`, `account_id`, `account_name`, `audit_accounts`, and `log_archive_accounts` as read-only properties delegating to the per-scan context, and IF one of those properties is read before `initialize(ctx)` has attached a per-scan context, THEN THE Check_Base_Class SHALL raise `RuntimeError` naming the property and the check ID.
10. WHEN `get_client(region)` is called for a region that has a client wrapper registered, THE Check_Base_Class SHALL return that wrapper, and IF no wrapper is registered for the requested region, THEN THE Check_Base_Class SHALL return a null value, that absence being the only condition under which `get_client(region)` returns a null value, preserving the existing behavior that check bodies handle.
11. IF a check reads or assigns `findings`, `create_finding`, or `get_findings` on an instance, or supplies any argument to the constructor, THEN THE Check_Base_Class SHALL raise an error naming the offending attribute or argument, raising `AttributeError` for the attribute and `TypeError` for the argument, so that an assignment such as `self.findings = []` cannot silently re-create the accumulator and discard every appended finding.
12. IF a check class is created with another registered check class among its bases, or with a class attribute named `check_id`, `service`, `severity`, or `account_type`, THEN THE Registration_Hook SHALL raise `CheckIdentityError` naming the offender and the module file, so that identity and account type come only from the check's own metadata.
13. THE Check_Catalog SHALL contain no check that constructs, initializes, or calls `execute()` on another check, so that every Finding is attributable to exactly one check ID.

### Requirement 7: Finding construction helpers

**User Story:** As a check author, I want three status-specific helpers whose signatures encode the remediation rules, so that a PASS cannot carry placeholder remediation text and an ERROR cannot silently inherit control remediation that does not apply.

#### Acceptance Criteria

1. THE Finding_Helpers SHALL provide `passed()`, `failed()`, and `error()`, each declaring every parameter as keyword-only and each returning exactly one Finding carrying the corresponding `Status` member.
2. THE `passed()` helper SHALL declare no `remediation` parameter and SHALL set `remediation` to the empty string on every Finding it produces, so that the 178 semantically empty remediation values among the 468 literal remediation arguments become unrepresentable.
3. THE Finding_Helpers SHALL declare `region`, `resource_id`, and `actual_value` as required keyword-only parameters of `passed()`, `failed()`, and `error()`, with `resource_id` accepting a null value, and SHALL declare `checked_value` as an optional keyword-only parameter of all three.
4. WHEN a caller of `failed()` supplies no `remediation`, THE Finding_Helpers SHALL use `meta.remediation.text`.
5. WHEN a caller of `failed()` supplies a `remediation`, THE Finding_Helpers SHALL use the supplied value so that dynamic remediation text remains available, and IF that supplied value is empty after stripping surrounding whitespace, THEN THE Finding_Helpers SHALL use `meta.remediation.text` instead, so that no FAIL row carries an empty `Remediation` cell.
6. THE `error()` helper SHALL declare `remediation` as a required keyword-only parameter, so that an ERROR row describes fixing the scan environment rather than fixing the control, and IF the supplied value is empty after stripping surrounding whitespace, THEN THE Finding_Helpers SHALL raise `ValueError` naming the check ID, that emptiness test standing as the whole of the validation applied to the value, so that the helper accepts any value that is not empty after stripping surrounding whitespace and judges no wording.
7. WHEN a caller supplies no `checked_value`, THE Finding_Helpers SHALL default `checked_value` to the service name followed by one space and the word `Configuration`.
8. WHEN a helper builds a Finding, THE Finding_Helpers SHALL populate `check_id`, `severity`, `title`, `description`, `resource_type`, `service`, `check_logic`, and `account_type` from `meta`, and SHALL populate `account_id` and `account_name` by value from the per-scan context.
9. WHEN a helper builds a Finding, THE Finding_Helpers SHALL leave the check instance unmodified.
10. THE Finding_Helpers SHALL remain public methods of the Check_Base_Class, including `error()`, so that checks continue to author their own ERROR findings.
11. IF a caller supplies any helper argument positionally, omits a required parameter, or supplies a `remediation` argument to `passed()`, THEN THE Finding_Helpers SHALL raise `TypeError` naming the helper and the parameter and SHALL return no Finding, so that a positional swap of `actual_value` and `remediation` across three near-identical signatures cannot produce a well-formed but wrong row.
12. IF a helper is called on a check to which `initialize(ctx)` has not attached a per-scan context, THEN THE Finding_Helpers SHALL raise `RuntimeError` naming the check ID and SHALL return no Finding.

### Requirement 8: CSV output

**User Story:** As a consumer of the findings CSV, I want the writer to render typed findings against a single column declaration without side effects, so that the published sixteen-column contract has exactly one definition and writing a report cannot alter the findings being reported.

#### Acceptance Criteria

1. THE CSV_Writer SHALL accept a list of Finding objects and an output file path.
2. WHEN the CSV_Writer writes a file, THE CSV_Writer SHALL replace any existing content at the output path, SHALL emit a header line equal to the comma-joined `Finding.FIELDS`, and SHALL follow that header with one data row per Finding in list order, each row produced by that Finding's `to_row()`, with cells separated by commas and written without enclosing quotes except as criterion 7 requires.
3. WHEN the findings list is empty, THE CSV_Writer SHALL create the output file containing the header line and no data rows, so that a consumer can distinguish a scan that found nothing from a scan that did not run.
4. WHEN the CSV_Writer writes a file, THE CSV_Writer SHALL leave the findings list holding the same Finding objects in the same order with no element added and no element removed, and SHALL leave every field value of every Finding in that list unchanged.
5. THE CSV_Writer SHALL derive column names solely from `Finding.FIELDS`, so that the output module declares no second list of column names.
6. THE CSV_Writer SHALL render each row solely from `to_row()`, so that the output module performs no missing-field backfill and no legacy `CheckType`-to-`AccountType` migration.
7. WHEN the CSV_Writer writes a cell whose value contains a comma, a double quote, a carriage return, or a line feed, THE CSV_Writer SHALL enclose that cell in double quotes and SHALL write each embedded double quote as two consecutive double quotes, so that a consumer recovers the original value from a `Description`, `Remediation`, or `ActualValue` cell.
8. THE CSV_Writer SHALL terminate the header line and every data row with a carriage return followed by a line feed, and SHALL encode the file as UTF-8 with no byte-order mark, so that the emitted bytes do not vary with the host platform or the host locale.
9. IF the output path cannot be opened for writing, including a parent directory that does not exist and a path naming a directory, THEN THE CSV_Writer SHALL raise an error identifying the path and the reason, SHALL create no directory, and SHALL leave the findings unmodified, treating a path naming a directory as one such failure even where that directory is writable and synthesizing no file name within it, so that supplying a complete file path is the caller's responsibility.

### Requirement 9: Check selection and usage errors

**User Story:** As an operator running a scan, I want filters resolved from class attributes and a non-zero exit when a filter matches nothing, so that no check is constructed merely to read its metadata and a mistyped check ID cannot produce a header-only CSV that looks like a clean scan.

#### Acceptance Criteria

1. WHEN resolving the account-type, service, and check-ID filters, THE Check_Selector SHALL read `meta` from the registered classes, SHALL construct zero check instances, and SHALL issue zero AWS API calls.
2. WHEN the account-type filter is a value other than `all`, THE Check_Selector SHALL retain only checks whose `meta.account_type` equals that value.
3. WHEN the service filter is supplied, THE Check_Selector SHALL retain only checks whose `meta.service` equals the supplied value after stripping surrounding whitespace from the supplied value and mapping each ASCII letter `A` through `Z` in both values to lower case, comparing the two values in full with no prefix match, no substring match, and no dependence on the host locale.
4. IF the check-ID filter names an ID absent from the Check_Registry, the supplied ID being matched exactly and case-sensitively, THEN THE Check_Selector SHALL raise `UnknownCheckError` carrying at most three registry keys whose similarity to the supplied ID is at least 0.6 on a scale of 0 to 1, ordered from most similar to least similar with ties broken by ascending check ID, and carrying an empty list when no registry key reaches that threshold.
5. IF the filter combination matches zero checks, THEN THE Check_Selector SHALL raise `NoChecksSelectedError` carrying, for each of the account-type filter, the service filter, and the check-ID filter, either the supplied value or an indication that the filter was not supplied.
6. WHEN selection succeeds, THE Check_Selector SHALL return a non-empty mapping of check ID to check class equal to the intersection of the checks retained by every supplied filter, with the check-ID filter narrowing that intersection rather than replacing it, so that a check ID contradicting a supplied account type or a supplied service yields zero matches and reaches criterion 5.
7. WHEN the CLI catches `UnknownCheckError` or `NoChecksSelectedError`, THE CLI SHALL log the message through the shared logger together with the supplied filter values and, for `UnknownCheckError`, the carried suggestions, SHALL create no file at the resolved output path, and SHALL exit with status 2.
8. WHEN the CLI lists checks or lists services, THE CLI SHALL read `meta` from the registered classes, construct no check instance, and preserve the existing output format so that `docs/checks.txt` stays structurally unchanged.
9. WHEN the CLI reports the check count in the startup banner, THE CLI SHALL derive the count from the selected mapping and construct no check instance.
10. THE CLI SHALL derive the account-type argument choices from the `AccountType` members plus the literal `all`, so that the CLI surface holds no separate list of account-type strings.
11. WHEN a scan runs, THE Scan_Orchestrator SHALL construct exactly one instance of each selected check, so that a default scan performs 158 constructions in place of 474 and a single-check run performs 1 in place of 161.
12. WHERE the operator supplies no output file path, THE CLI SHALL resolve the output path from the default base name with an underscore followed by the scan-start date and time formatted as `YYYYMMDD_HHMMSS` inserted before the file extension, so that consecutive default scans do not overwrite one report.
13. WHEN the scan completes and the output file has been written, THE CLI SHALL exit with status 0 regardless of how many FAIL Findings and ERROR Findings were produced, so that a non-zero exit status indicates only a usage error or a write failure.
14. IF the CSV_Writer reports that it could not write the output file, THEN THE CLI SHALL log an error naming the path and the reason, SHALL report no scan summary on standard output, and SHALL exit with status 1, distinct from the status 2 reserved for a filter matching no check.

### Requirement 10: Orchestration resilience and per-scan isolation

**User Story:** As an operator scanning many accounts, I want one broken check to cost one row rather than the scan, every ERROR row to be attributable, and no boto3 client to outlive its scan, so that a fan-out across an organization cannot silently under-report and a long-running server does not accumulate scan state.

#### Acceptance Criteria

1. WHEN the Scan_Orchestrator runs a selected check, THE Scan_Orchestrator SHALL perform construction, `initialize(ctx)`, and consumption of `execute()` inside one guarded block for that check that catches `Exception` and does not catch `BaseException`, so that `KeyboardInterrupt` and `SystemExit` propagate rather than manufacturing one synthetic ERROR row for each remaining check.
2. IF construction, initialization, or execution of one check raises an `Exception`, THEN THE Scan_Orchestrator SHALL log the error with a traceback, append exactly one synthetic ERROR Finding for that check, advance the progress indicator for that check, retain every Finding already collected from previous checks, and continue with the next selected check.
3. THE synthetic ERROR Finding SHALL carry all sixteen fields, taking `status` as ERROR, taking `check_id`, `title`, `description`, `resource_type`, `service`, `check_logic`, `severity`, and `account_type` from the check class's `meta` so that `severity` is one of the four legal `Severity` members, taking `region` as `GLOBAL_REGION`, taking `account_id` and `account_name` from the account identity resolved once for the scan, taking `resource_id` as a null value, deriving `checked_value` from `meta.service`, setting `actual_value` to a string identifying the exception type and the exception message, and setting `remediation` to `meta.remediation.text`.
4. WHEN the Scan_Orchestrator builds a synthetic ERROR Finding, THE Scan_Orchestrator SHALL read metadata from the check class rather than from an instance, so that a construction failure still produces an attributable row.
5. IF the account identity cannot be resolved at the start of a scan, THEN THE Scan_Orchestrator SHALL log the failure, use empty strings for `account_id` and `account_name` in synthetic ERROR Findings, and continue the scan.
6. WHEN the Scan_Orchestrator consumes a check's `execute()` result, THE Scan_Orchestrator SHALL materialize the whole iterable into a list inside the guarded block for that check, so that no generator, iterator, or other lazy object derived from a check instance outlives that guarded block.
7. WHEN `run_checks` returns normally, THE Scan_Orchestrator SHALL return a concrete `list` whose every element is a Finding and which is no generator, no iterator, no view, and no other lazy object.
8. IF a check raises after yielding one or more Findings, THEN THE Scan_Orchestrator SHALL discard the Findings yielded before the failure and record only the synthetic ERROR Finding, preserving the existing one-row-per-broken-check behavior.
9. THE Scan_Orchestrator SHALL construct one per-scan context per `run_checks` call and SHALL drop its only reference to that context in a `finally` block, both on the path where `run_checks` returns normally and on the path where an exception propagates out of the check loop.
10. WHEN the Scan_Orchestrator resolves the account identity for synthetic ERROR rows, THE Scan_Orchestrator SHALL use the per-scan context's cached account lookup, so that the scan issues no additional AWS API call.
11. WHILE the caller holds no strong reference to the per-scan context, WHEN `run_checks` returns, THE Scan_Orchestrator SHALL leave a weak reference to that context dead after one forced garbage collection, so that neither the returned list nor anything reachable from it keeps the context alive.
12. IF construction of the synthetic ERROR Finding itself raises, THEN THE Scan_Orchestrator SHALL log that secondary failure with a traceback, SHALL append no Finding for that check, and SHALL leave the scan running so that the remaining selected checks are reached, leaving the Findings already collected and the per-scan context lifecycle unaffected.

### Requirement 11: Catalog-wide migration without behavioral change

**User Story:** As a reviewer of this change, I want all 158 checks migrated in one atomic change with every control decision preserved, so that a before and after CSV comparison is sufficient evidence that no check changed what it reports.

#### Acceptance Criteria

1. THE Check_Catalog SHALL migrate every check module and every service package present in the catalog in a single change, carrying no transitional adapter and no compatibility shim.
2. WHEN a check body is migrated, THE Check_Catalog SHALL produce, against the same account state, the same number of rows, the same set of `Region` and `ResourceId` pairs, the same `Status` for each such pair, and the same set of AWS API operations issued as that check produced before the migration.
3. THE Check_Catalog SHALL preserve the per-operation error-code classification held by the 34 checks that classify AWS error codes themselves, including the divergent classification of `BadRequestException` between `sra_guardduty_14` and `sra_guardduty_15`, `sra_guardduty_16`, and `sra_guardduty_20` through `sra_guardduty_25`.
4. WHEN a migrated check reports an outcome that previously supplied a null actual value, THE Check_Catalog SHALL supply an `ActualValue` that is not empty after stripping surrounding whitespace and that carries each run of whitespace collapsed to one space.
5. WHEN a migrated check reports a PASS, THE Check_Catalog SHALL emit an empty `Remediation` cell, collapsing the three current spellings of an absent remediation into one canonical empty value.
6. WHEN a check module is migrated, THE Check_Catalog SHALL move that check's metadata assignments out of its `__init__` into a `CheckMeta` literal declared in the same module's class body, SHALL remove the emptied constructor from that check module, and SHALL remove every metadata-only constructor body from every service base class in the catalog, so that declaring metadata is one per-file edit made alongside the switch to yielding Findings.
7. THE Check_Catalog SHALL reduce each service package's `__init__.py` to a discovery call.
8. WHEN the base-class rewrite begins, THE Acceptance_Gate SHALL already hold a baseline CSV captured from the pre-change tree against the same account, the same region list, the same account-type selection, and the same audit and log-archive account arguments used for the post-change capture, because the tree does not run between the base-class rewrite and the completion of the check-body migration.
9. WHEN the catalog-wide before and after CSV comparison runs, THE Acceptance_Gate SHALL admit cell differences only in `ActualValue`, in `Remediation` on PASS rows, in whitespace-normalized `Description`, in `Title` for retitled checks, and in `AccountType` for the reclassified Config checks, and SHALL require every other cell of every matched row to be byte-identical.
10. THE Check_Catalog SHALL declare a legal `AccountType` member in the `meta` of each Config check that currently inherits an account type outside the legal set, so that those checks become selectable by the account-type filter.
11. THE `sra_accessanalyzer_03` check SHALL read audit accounts through the `audit_accounts` property.
12. WHEN the migration completes and the migrated catalog imports successfully, THE Check_Catalog SHALL regenerate `docs/checks.txt` from the CLI check listing, and WHERE a later gate rejects that migrated result, THE Check_Catalog SHALL regenerate `docs/checks.txt` from the same listing against the catalog as it then stands, so that the file states the current catalog rather than a superseded one.
13. WHEN the migration completes, THE Check_Catalog SHALL contain no test module importing the removed `sraverify.checks` path, so that bare test collection from the pip project root succeeds.
14. WHEN a Config check that iterates regions while emitting global rows is migrated, THE Check_Catalog SHALL record that check as a candidate for reclassification without restructuring it in this change.
15. WHEN the catalog-wide before and after CSV comparison runs, THE Acceptance_Gate SHALL key each row on `AccountId`, `CheckId`, `Region`, and `ResourceId`, SHALL order both captures by that key before comparing, and SHALL compare rows sharing one key as an unordered group, those four columns lying outside the admitted difference set so that the key is independent of the differences being judged.
16. IF the two captures differ in the set of row keys present, or in the number of rows carrying any one key, THEN THE Acceptance_Gate SHALL reject the migration and SHALL report the added keys and the removed keys, applying this rule independently of criterion 9 so that a cell difference the admitted set of that criterion would otherwise admit does not excuse an unequal key set.
17. IF a row key carries `ERROR` in exactly one of the two captures, THEN THE Acceptance_Gate SHALL re-run the affected check against both trees before admitting or rejecting the migration, and SHALL reject the migration if the difference persists, so that transient throttling is distinguishable from a regression.

### Requirement 12: Python version floor

**User Story:** As an operator installing the scanner, I want the declared Python floor to match the interpreter the scanner is built against, so that an environment that cannot run the code refuses to install it rather than failing at import.

#### Acceptance Criteria

1. THE Package_Build SHALL declare `python_requires` as exactly `>=3.11`, matching the CodeBuild image and supporting the string-valued enums, slotted dataclasses, and runtime-evaluated optional annotations this feature uses, SHALL leave the MCP server's declared floor of `>=3.10` unchanged, and SHALL record as a known and accepted consequence that no compliant version of this distribution resolves on Python 3.10, so the MCP server's declared 3.10 support becomes unsatisfiable against this distribution.

### Requirement 13: Preservation constraints

**User Story:** As a maintainer of the downstream dashboards and the deployment templates, I want the per-scan isolation model, the dependency set, the CSV schema, and every service client left untouched, so that this change is confined to the check contract.

#### Acceptance Criteria

1. THE Scanner SHALL retain `core/scan_context.py` byte-identical to its pre-change revision, preserving the session, the region list and lazy enabled-region resolution, the audit and log-archive account lists, the bounded client config and its four CLI knobs, the client cache and its locking, the namespaced cache primitives, the account-info and management-account lookups, and the fresh-per-scan lifecycle.
2. THE Scanner SHALL add no field to the per-scan context.
3. THE Scanner SHALL add zero new runtime dependencies, SHALL keep `install_requires` at exactly the existing `boto3` and `colorama`, and SHALL restrict every added or modified module to the Python standard library and those two packages, excluding test-only tooling declared under `extras_require`.
4. THE Scanner SHALL emit the sixteen CSV columns named in the Glossary in that exact order, so that both standalone HTML dashboards continue to parse the output.
5. THE Scanner SHALL retain the check ID format `SRA-<SERVICE>-NN` with a two-digit zero-padded number.
6. Every service base class SHALL retain its `NAMESPACE` constant and its cached typed accessors built on the per-scan context cache primitives, with removal of a metadata-only constructor as the only permitted edit.
7. Every service client module SHALL remain byte-identical to its pre-change revision, continuing to catch client errors, log through the shared logger, and return either a named-key success mapping or an error mapping carrying a code and a message.
8. THE Scanner SHALL issue the same set of AWS API calls as before this change, so that the generated IAM policy artifacts and `1-sraverify-member-roles.yaml` remain unchanged.
9. THE Scanner SHALL remain read-only, calling only describe, get, and list operations.
10. THE Scanner SHALL retain the shared stderr-only logger as the single logging path, so that stdout stays clean for the MCP server.
11. THE Scanner SHALL leave the `setup.py` and package version disagreement, the boto3 pin disagreement, and the checked-in build artifacts unchanged.
