"""
Unit tests for ``core/aws_errors.py`` -- the error result shape and its predicates.

This module owns the *shape*: what an error result is, what ``is_error`` accepts, and
how the discriminator reads it. The thing that *builds* an error result from a caught
exception is ``AWSClient.aws_error``, tested in ``test_aws_client.py`` beside the
class that owns it.

Coverage map:

* Property 17 -- ``TRANSPORT_ERROR_CODES`` is derived, not written out.
* :func:`is_error` -- strict in both directions, every missing/blank/wrong-type
  case for each of the three fields.
* :func:`error_result` -- rejects exactly what ``is_error`` would reject.
* :func:`no_client_result` -- names the service and Region, and claims no
  operation.
* :func:`is_not_configured` -- total and conservative.
* :class:`NotConfigured` -- evidence is required and non-blank.

Validates: Requirements 1.1, 2.7, 3.7, 4.6, 4.6a.
"""
from __future__ import annotations

from typing import Any

import pytest

from sraverify.core.aws_errors import (
    NO_CLIENT_CODE,
    TRANSPORT_ERROR_CODES,
    _TRANSPORT_EXCEPTIONS,
    UNKNOWN_OPERATION,
    NotConfigured,
    error_result,
    is_error,
    is_not_configured,
    no_client_result,
)


# --------------------------------------------------------------------------- #
# Property 17 -- the transport constant is single-sourced
# --------------------------------------------------------------------------- #


def test_transport_error_codes_is_derived_from_the_exception_tuple() -> None:
    """Property 17: the two constants cannot drift, because one derives the other."""
    assert TRANSPORT_ERROR_CODES == frozenset(
        exc.__name__ for exc in _TRANSPORT_EXCEPTIONS
    )


def test_transport_error_codes_names_the_three_transport_subclasses() -> None:
    """The set's membership is pinned, so a silent addition or removal fails."""
    assert TRANSPORT_ERROR_CODES == {
        "EndpointConnectionError",
        "ConnectTimeoutError",
        "ReadTimeoutError",
    }


def test_no_client_code_is_stable() -> None:
    """``NoClient`` is compared as a literal by checks."""
    assert NO_CLIENT_CODE == "NoClient"


# --------------------------------------------------------------------------- #
# is_error -- strict in both directions
# --------------------------------------------------------------------------- #


def test_is_error_accepts_a_well_formed_error_result() -> None:
    """The positive case, built by the constructor."""
    assert is_error(
        error_result(code="C", message="M", operation="Op")
    )


@pytest.mark.parametrize(
    "value",
    [
        None, [], {}, "", "Error", 0, 1, True, False, (), set(),
        {"Subscribers": []},
        {"error": {"Code": "C", "Message": "M", "Operation": "Op"}},
        {"Error": None},
        {"Error": "AccessDenied"},
        {"Error": []},
        {"Error": 42},
    ],
    ids=[
        "None", "list", "empty-dict", "empty-str", "str", "zero", "int",
        "True", "False", "tuple", "set",
        "success-dict", "lowercase-error-key", "Error-None", "Error-str",
        "Error-list", "Error-int",
    ],
)
def test_is_error_rejects_anything_that_is_not_an_error_result(value: Any) -> None:
    """A success dict, a non-mapping, and a wrong-shaped ``Error`` are all False.

    ``{"Subscribers": []}`` is the case that matters for the success path: a
    real response must never be mistaken for a failure. The lowercase
    ``"error"`` key case matters because several AWS services use lowercase
    response members and a case-insensitive test would misfire.
    """
    assert is_error(value) is False


@pytest.mark.parametrize("field", ["Code", "Message", "Operation"])
@pytest.mark.parametrize(
    "mutation,label",
    [
        ("missing", "missing"),
        ("", "empty"),
        ("   ", "whitespace"),
        ("\t\n", "whitespace-control"),
        (None, "None"),
        (42, "int"),
        (["C"], "list"),
        ({"a": 1}, "dict"),
        (True, "bool"),
    ],
    ids=[
        "missing", "empty", "whitespace", "whitespace-control", "None", "int",
        "list", "dict", "bool",
    ],
)
def test_is_error_rejects_a_half_built_error_result(
    field: str, mutation: Any, label: str
) -> None:
    """Every missing, blank, and wrong-type case for each of the three fields.

    A half-built error result must fail in *both* directions: it must not pass as a
    error result and be half-read downstream, and it must not fail the test and be
    written to the cache as if it were a successful response. Requirement 1.1
    asks for every one of these cases explicitly.
    """
    err: dict[str, Any] = {"Code": "C", "Message": "M", "Operation": "Op"}
    if mutation == "missing":
        del err[field]
    else:
        err[field] = mutation

    assert is_error({"Error": err}) is False, (
        f"{field}={label} must not be accepted as an error result"
    )


def test_is_error_ignores_extra_keys() -> None:
    """An error result with additional members is still an error result.

    botocore attaches ``HTTPStatusCode`` and friends to real error dicts; the
    predicate tests the three fields it needs and does not require exclusivity.
    """
    assert is_error(
        {
            "Error": {
                "Code": "C",
                "Message": "M",
                "Operation": "Op",
                "HTTPStatusCode": 403,
            },
            "ResponseMetadata": {"RequestId": "x"},
        }
    )


# --------------------------------------------------------------------------- #
# error_result() -- rejects exactly what is_error rejects
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("field", ["code", "message", "operation"])
@pytest.mark.parametrize(
    "bad",
    ["", "   ", "\t\n", None, 42, ["C"], {"a": 1}, True],
    ids=["empty", "whitespace", "whitespace-control", "None", "int", "list", "dict", "bool"],
)
def test_error_result_rejects_every_input_is_error_would_reject(
    field: str, bad: Any
) -> None:
    """The constructor and the predicate agree, so a malformed error result cannot exist.

    If the constructor accepted something the predicate rejects, a client could
    build a value that is neither a success nor a failure and every downstream
    guard would mis-handle it.
    """
    kwargs: dict[str, Any] = {"code": "C", "message": "M", "operation": "Op"}
    kwargs[field] = bad

    with pytest.raises(ValueError) as excinfo:
        error_result(**kwargs)

    assert field in str(excinfo.value)


def test_error_result_is_keyword_only() -> None:
    """Three strings positionally would transpose silently."""
    with pytest.raises(TypeError):
        error_result("C", "M", "Op")  # type: ignore[misc]


def test_no_client_result_names_the_service_and_region() -> None:
    """The message has to be actionable on its own in the CSV cell."""
    result = no_client_result(service="Security Lake", region="eu-west-3")

    assert is_error(result)
    assert result["Error"]["Code"] == NO_CLIENT_CODE
    assert result["Error"]["Operation"] == UNKNOWN_OPERATION
    assert "Security Lake" in result["Error"]["Message"]
    assert "eu-west-3" in result["Error"]["Message"]


def test_no_client_result_is_keyword_only() -> None:
    """Same reasoning as ``error_result``."""
    with pytest.raises(TypeError):
        no_client_result("Security Lake", "eu-west-3")  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# NotConfigured -- evidence is structural
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "evidence",
    ["", "   ", "\t", "\n", None, 42, [], {}],
    ids=["empty", "whitespace", "tab", "newline", "None", "int", "list", "dict"],
)
def test_not_configured_requires_non_blank_evidence(evidence: Any) -> None:
    """A table entry without evidence is an assertion, not a fact.

    Enforced at construction rather than by review, because an entry converts
    an ERROR into a FAIL and a wrong one fabricates a finding out of a
    permission failure.
    """
    with pytest.raises(ValueError):
        NotConfigured(evidence=evidence)


def test_not_configured_accepts_evidence_and_defaults_message_to_none() -> None:
    """The common case: a code whose meaning does not depend on the message."""
    fact = NotConfigured(evidence="https://docs.aws.amazon.com/...")

    assert fact.evidence == "https://docs.aws.amazon.com/..."
    assert fact.message is None


def test_not_configured_is_frozen() -> None:
    """A table is declared once and never mutated."""
    fact = NotConfigured(evidence="e")

    with pytest.raises(Exception):
        fact.evidence = "other"  # type: ignore[misc]


def test_not_configured_is_hashable_and_shareable() -> None:
    """One fact object can be reused across operations in the same table.

    The Security Lake table declares one ``ResourceNotFoundException`` fact and
    binds it to five operations; that only works if the object is shareable.
    """
    fact = NotConfigured(evidence="e")
    table = {"OpA": {"C": fact}, "OpB": {"C": fact}}

    assert hash(fact) == hash(fact)
    assert table["OpA"]["C"] is table["OpB"]["C"]


# --------------------------------------------------------------------------- #
# is_not_configured -- total and conservative
# --------------------------------------------------------------------------- #

_PLAIN = NotConfigured(evidence="API reference: the resource does not exist")
_NEEDLED = NotConfigured(
    message="macie is not enabled",
    evidence="observed log line, account 111122223333 us-west-1",
)

_TABLE = {
    "GetThing": {"ResourceNotFoundException": _PLAIN},
    "GetOverloaded": {"AccessDeniedException": _NEEDLED},
}


def test_declared_pair_without_a_needle_is_not_configured() -> None:
    """operation + code declared, no message condition -> True."""
    assert is_not_configured(
        _TABLE,
        {"Operation": "GetThing", "Code": "ResourceNotFoundException", "Message": "x"},
    )


@pytest.mark.parametrize(
    "message",
    [
        "Macie is not enabled",
        "macie is not enabled",
        "MACIE IS NOT ENABLED",
        "The request failed because Macie is not enabled for this account.",
    ],
    ids=["title-case", "lower", "upper", "embedded"],
)
def test_declared_needle_matches_case_insensitively_anywhere(message: str) -> None:
    """The needle is a case-insensitive substring, not a prefix or an equality.

    AWS wraps the phrase in different prose per operation, and the casing is
    not guaranteed, so anything stricter would silently stop classifying.
    """
    assert is_not_configured(
        _TABLE,
        {
            "Operation": "GetOverloaded",
            "Code": "AccessDeniedException",
            "Message": message,
        },
    )


def test_declared_needle_absent_from_the_message_is_not_configured_false() -> None:
    """The overloaded code's *other* meaning: a real permission failure.

    This is the single most consequential ``False`` in the module. ``macie2``
    returns ``AccessDeniedException`` both when Macie is disabled and when the
    role lacks the permission; reading the second as "not configured" would
    publish a fabricated finding.
    """
    assert (
        is_not_configured(
            _TABLE,
            {
                "Operation": "GetOverloaded",
                "Code": "AccessDeniedException",
                "Message": (
                    "User: arn:aws:sts::111122223333:assumed-role/SRAMemberRole/"
                    "sraverify-session is not authorized to perform: "
                    "macie2:DescribeOrganizationConfiguration"
                ),
            },
        )
        is False
    )


def test_undeclared_operation_is_not_configured_false() -> None:
    """A declared code arriving from an undeclared operation is not semantic.

    This is the operation dimension earning its place: the same code can mean
    two different things through two operations.
    """
    assert (
        is_not_configured(
            _TABLE,
            {
                "Operation": "SomeOtherOperation",
                "Code": "ResourceNotFoundException",
                "Message": "x",
            },
        )
        is False
    )


def test_undeclared_code_under_a_declared_operation_is_false() -> None:
    """A code AWS introduces later produces an honest ERROR, not a fake FAIL."""
    assert (
        is_not_configured(
            _TABLE,
            {"Operation": "GetThing", "Code": "SomeFutureException", "Message": "x"},
        )
        is False
    )


@pytest.mark.parametrize(
    "error",
    [
        {},
        {"Operation": "GetThing"},
        {"Code": "ResourceNotFoundException"},
        {"Operation": "", "Code": "", "Message": ""},
        {"Operation": None, "Code": None, "Message": None},
    ],
    ids=["empty", "operation-only", "code-only", "blank", "None-valued"],
)
def test_a_malformed_error_dict_is_false_and_does_not_raise(error: Any) -> None:
    """Total over its input: the predicate never raises, whatever it is handed.

    A predicate that raised here would abort the check and cost every row it
    had already yielded, for a value that ``is_error`` should have rejected
    upstream anyway.
    """
    assert is_not_configured(_TABLE, error) is False


def test_an_empty_table_classifies_nothing() -> None:
    """The ``SecurityCheck`` default: no declared semantics, so everything ERRORs."""
    assert (
        is_not_configured(
            {},
            {"Operation": "GetThing", "Code": "ResourceNotFoundException", "Message": "x"},
        )
        is False
    )


def test_transport_codes_are_never_classified_as_not_configured() -> None:
    """Requirement 4.3: a transport failure is always an undetermined state.

    A Region with no endpoint and a Region behind a broken network raise the
    same exception, so a transport code can never establish absence.
    """
    for code in TRANSPORT_ERROR_CODES | {NO_CLIENT_CODE}:
        assert (
            is_not_configured(
                _TABLE, {"Operation": "GetThing", "Code": code, "Message": "x"}
            )
            is False
        ), f"{code} must never classify as not-configured"
