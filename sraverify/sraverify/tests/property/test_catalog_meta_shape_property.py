"""
Catalog-wide pass over metadata shape and enum legality (task 17.4).

This module implements **Property 5: Metadata shape and enum legality** from
the ``check-contract-formalization`` design:

    ∀ registered ``cls``: ``isinstance(cls.meta.severity, Severity)`` and
    ``isinstance(cls.meta.account_type, AccountType)`` -- enum *members*, not
    strings that merely compare equal to one. Every required field is present
    and non-null, and ``sra_sections`` and ``additional_urls`` are tuples.

Why the property is not vacuous
-------------------------------

Because the declaration writes the enum member directly, what this catches is a
bare string where a member belongs -- ``severity="HIGH"`` instead of
``severity=Severity.HIGH``. A type checker flags that; the annotation does not
enforce it at run time, and because ``Severity`` is a ``str`` subclass the
string compares **equal** to the member and nothing downstream would notice.
``isinstance`` is what separates the two. So ``isinstance(x, Severity)`` /
``type(x) is Severity`` is the load-bearing assertion here, and an
``== "HIGH"`` assertion would prove nothing at all.

``test_a_bare_string_is_equal_to_the_member_but_is_not_the_member`` states that
gap directly, so the reason the catalog-wide assertions are written with
``isinstance`` rather than ``==`` is itself under test.

On Requirement 3.11
-------------------

3.11's rule -- validation runs during construction, so no partially-validated
``CheckMeta`` escapes to a caller -- is already demonstrated by this module
importing at all: ``import sraverify.services`` constructs all 158 real
``CheckMeta`` values while the declaring class bodies execute, and a defective
one would have raised ``MetadataError`` at import rather than yielding an
instance. There is nothing left to re-derive here; Property 19
(``test_metadata_validation_property.py``) covers the totality argument on
synthetic input.

What this module adds on top of that is
``test_reconstructing_meta_from_its_own_field_values_revalidates``: it feeds
each real meta's own field values back through ``CheckMeta(...)``, so every
value on disk is confirmed to satisfy every rule *now*, rather than having been
grandfathered in by a validator that was weaker when the check was written.

Scope
-----

This is a read over the real registry and quantifies over a fixed finite set,
so it enumerates the catalog directly rather than sampling it. Parametrization
is over ``sorted(all_checks().items())`` with the check ID as the test ID, so a
failure names the offending check. It needs no credentials and issues no AWS
call.

The catalog is captured once, at import time, into ``CATALOG``. Four sibling
property modules empty the shared ``core/registry._REGISTRY`` inside fixtures
for the duration of a test and restore it afterwards; the assertions below read
the class objects captured here rather than the live registry, so the outcome
does not depend on which module ran first. This module installs no fixture of
its own and never clears the registry.

Feature: check-contract-formalization, Property 5: Metadata shape and enum
legality.

**Validates: Requirements 2.2, 2.3, 3.11**
"""
from __future__ import annotations

import dataclasses
from typing import Any, Dict, List, Tuple, Type

import pytest

# Imported for the registration side effect: importing the package imports
# every service package, which imports every check module, which executes every
# class body, which constructs and validates every CheckMeta.
import sraverify.services  # noqa: F401
from sraverify.core.check import SecurityCheck
from sraverify.core.enums import AccountType, Severity
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.core.registry import all_checks

#: The nine fields Requirement 2.2 makes required, in declaration order.
REQUIRED_FIELDS: Tuple[str, ...] = (
    "check_id",
    "title",
    "description",
    "check_logic",
    "severity",
    "account_type",
    "service",
    "resource_type",
    "remediation",
)

#: The two fields Requirement 2.2 makes optional, defaulting to ``()``.
OPTIONAL_SEQUENCE_FIELDS: Tuple[str, ...] = ("sra_sections", "additional_urls")

#: Required text fields, which must also be non-empty once stripped.
REQUIRED_TEXT_FIELDS: Tuple[str, ...] = (
    "check_id",
    "title",
    "description",
    "check_logic",
    "service",
    "resource_type",
)

#: The catalog, captured once at import. A sibling module emptying the live
#: registry mid-session cannot reach these class objects.
CATALOG: Tuple[Tuple[str, Type[SecurityCheck]], ...] = tuple(
    sorted(all_checks().items())
)


def _catalog_params() -> List[Any]:
    """One ``pytest.param`` per registered check, identified by its check ID."""
    return [pytest.param(cls, id=check_id) for check_id, cls in CATALOG]


def _meta_kwargs(meta: CheckMeta) -> Dict[str, Any]:
    """The field values of *meta* as constructor keyword arguments.

    Reads each field with ``getattr`` rather than using
    ``dataclasses.asdict``, which recurses into the nested ``Remediation`` and
    would hand back a ``dict`` where a ``Remediation`` belongs. The point of
    the round trip is to re-run validation over the *same* values, so the
    nested value must survive unconverted.
    """
    return {field.name: getattr(meta, field.name) for field in dataclasses.fields(meta)}


def test_the_catalog_is_not_empty() -> None:
    """A zero-length parametrization would make every assertion below vacuous."""
    assert CATALOG, "the registry is empty; import sraverify.services registered nothing"


def test_a_bare_string_is_equal_to_the_member_but_is_not_the_member() -> None:
    """The gap that makes ``isinstance`` the load-bearing assertion.

    ``Severity`` and ``AccountType`` are ``str`` subclasses, so the bare string
    a mistaken declaration would carry compares equal to the member it was
    meant to be and nothing downstream notices. An ``== "HIGH"`` assertion
    would therefore pass on the defect this property exists to catch.
    """
    assert "HIGH" == Severity.HIGH
    assert not isinstance("HIGH", Severity)
    assert type("HIGH") is not Severity

    assert "application" == AccountType.APPLICATION
    assert not isinstance("application", AccountType)
    assert type("application") is not AccountType

    # And the members themselves do satisfy the assertion, so it is not simply
    # rejecting everything.
    assert isinstance(Severity.HIGH, Severity)
    assert isinstance(AccountType.APPLICATION, AccountType)


def test_checkmeta_declares_exactly_the_fields_requirement_2_2_names() -> None:
    """The field set, and which fields carry a default (Requirement 2.2)."""
    fields = {field.name: field for field in dataclasses.fields(CheckMeta)}

    assert tuple(fields) == REQUIRED_FIELDS + OPTIONAL_SEQUENCE_FIELDS

    for name in REQUIRED_FIELDS:
        assert fields[name].default is dataclasses.MISSING, (
            f"{name} is a required field and must carry no default"
        )
        assert fields[name].default_factory is dataclasses.MISSING

    for name in OPTIONAL_SEQUENCE_FIELDS:
        assert fields[name].default == (), f"{name} must default to an empty tuple"


def test_remediation_declares_text_required_and_cli_and_console_defaulting() -> None:
    """``remediation`` exposes ``text``, ``cli``, ``console`` (Requirement 2.2)."""
    fields = {field.name: field for field in dataclasses.fields(Remediation)}

    assert tuple(fields) == ("text", "cli", "console")
    assert fields["text"].default is dataclasses.MISSING
    assert fields["cli"].default == ""
    assert fields["console"].default == ""


@pytest.mark.parametrize("cls", _catalog_params())
def test_severity_is_a_severity_member(cls: Type[SecurityCheck]) -> None:
    """``meta.severity`` is a ``Severity`` member, not a string (Req 2.3)."""
    severity = cls.meta.severity

    assert isinstance(severity, Severity), (
        f"severity={severity!r} is a {type(severity).__name__}, not a Severity "
        f"member; write severity=Severity.{str(severity).upper()} rather than a "
        f"bare string"
    )
    assert type(severity) is Severity
    assert severity in tuple(Severity)


@pytest.mark.parametrize("cls", _catalog_params())
def test_account_type_is_an_account_type_member(cls: Type[SecurityCheck]) -> None:
    """``meta.account_type`` is an ``AccountType`` member (Req 2.3)."""
    account_type = cls.meta.account_type

    assert isinstance(account_type, AccountType), (
        f"account_type={account_type!r} is a {type(account_type).__name__}, not "
        f"an AccountType member; write account_type=AccountType.<MEMBER> rather "
        f"than a bare string"
    )
    assert type(account_type) is AccountType
    assert account_type in tuple(AccountType)


@pytest.mark.parametrize("cls", _catalog_params())
def test_every_required_field_is_present_and_non_null(
    cls: Type[SecurityCheck],
) -> None:
    """All nine required fields carry a value (Requirement 2.2)."""
    meta = cls.meta
    assert isinstance(meta, CheckMeta)

    for name in REQUIRED_FIELDS:
        assert hasattr(meta, name), f"required field {name} is absent"
        assert getattr(meta, name) is not None, f"required field {name} is None"

    for name in REQUIRED_TEXT_FIELDS:
        value = getattr(meta, name)
        assert isinstance(value, str), f"{name} is a {type(value).__name__}, not a str"
        assert value.strip(), f"{name} is empty"


@pytest.mark.parametrize("cls", _catalog_params())
def test_sequence_fields_are_tuples_of_strings(cls: Type[SecurityCheck]) -> None:
    """``sra_sections`` and ``additional_urls`` are tuples (Requirement 2.2).

    ``type(...) is tuple`` rather than ``isinstance``, since a ``list`` is the
    error being excluded and a ``NamedTuple`` would also be the wrong shape
    here.
    """
    for name in OPTIONAL_SEQUENCE_FIELDS:
        values = getattr(cls.meta, name)
        assert type(values) is tuple, (
            f"{name} is a {type(values).__name__}, not a tuple"
        )
        for index, element in enumerate(values):
            assert type(element) is str, (
                f"{name}[{index}]={element!r} is a {type(element).__name__}, "
                f"not a str"
            )


@pytest.mark.parametrize("cls", _catalog_params())
def test_remediation_is_a_remediation_with_string_examples(
    cls: Type[SecurityCheck],
) -> None:
    """``meta.remediation`` shape and value types (Requirement 2.2).

    ``cli`` and ``console`` default to the empty string, never to ``None``, so
    a check declaring neither still carries two strings.
    """
    remediation = cls.meta.remediation

    assert isinstance(remediation, Remediation), (
        f"remediation is a {type(remediation).__name__}, not a Remediation"
    )
    assert type(remediation.text) is str
    assert remediation.text.strip(), "remediation.text is empty"

    for name in ("cli", "console"):
        value = getattr(remediation, name)
        assert value is not None, f"remediation.{name} is None; it defaults to ''"
        assert type(value) is str, (
            f"remediation.{name} is a {type(value).__name__}, not a str"
        )


@pytest.mark.parametrize("cls", _catalog_params())
def test_reconstructing_meta_from_its_own_field_values_revalidates(
    cls: Type[SecurityCheck],
) -> None:
    """Every value on disk satisfies every rule now, not merely when written.

    Requirement 3.11 puts validation inside construction, so feeding a real
    meta's own field values back through ``CheckMeta(...)`` re-runs all
    thirteen rules over them. A value that would fail a rule tightened after
    the check was written fails here rather than being grandfathered in.
    """
    meta = cls.meta

    rebuilt = CheckMeta(**_meta_kwargs(meta))

    assert rebuilt == meta
    assert hash(rebuilt) == hash(meta)
