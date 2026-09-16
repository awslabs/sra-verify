"""
The client error contract: one error result shape, and the predicates that read it.

Every ``<Service>Client`` method catches its own exceptions with a plain
``try``/``except`` and returns one of two things -- a named-key success dict, or
the error result this module defines. Every ``<Service>Check`` base class declares
a ``NOT_CONFIGURED_ERRORS`` table that :func:`is_not_configured` reads. Nothing in
this module issues an AWS call.

The shape is the whole point. A check handed a bare ``{}``, ``[]``, ``None`` or
``bool`` on failure cannot tell a disabled service from a denied permission from
an unreachable endpoint, so it lands on whichever branch its author wrote for "no
data" -- and where that branch is ``failed()``, an undetermined state is published
as an established negative.

Three rules make that unrepresentable:

* Every non-raising client path returns a ``Mapping``. ``"Error" in result`` is
  the only test that separates success from failure, at every tier.
* A client catches exactly ``ClientError`` and ``BotoCoreError``. Anything else
  is a programming defect and propagates to the orchestrator's guard.
* The FAIL-versus-ERROR judgement is made by the check, against a per-service
  table, never by the client. A client that classified a code would be making
  the decision at the wrong tier and without the operation context that decides
  it -- ``BadRequestException`` means "not configured" through
  ``guardduty:DescribeOrganizationConfiguration`` and "wrong account" through
  ``guardduty:ListOrganizationAdminAccounts``.

Where the error result is built
-------------------------------

Not here. This module defines the shape and the predicates that read it; the
error result is *built* by ``AWSClient.aws_error`` in ``core/aws_client.py``, the
base class every client inherits. Clients import that module; checks and base
classes import this one. The dependency runs one way.

``tests/property/test_client_contract_property.py`` drives every client method
through a simulated ``ClientError``, ``EndpointConnectionError``,
``NoCredentialsError`` and ``RuntimeError`` and asserts the return shape, so a
handler that erases the error or forgets ``BotoCoreError`` fails a test rather
than a scan.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, TypedDict

from botocore.exceptions import (
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)


class ErrorDetail(TypedDict):
    """The ``Error`` sub-dict of an error result. Every value is a non-blank ``str``."""

    Code: str
    """AWS error code, or the exception type name where AWS gave none."""

    Message: str
    """``e.response["Error"]["Message"]``, or ``str(e)`` as a fallback."""

    Operation: str
    """botocore operation name, e.g. ``"ListSubscribers"``."""


class ErrorResult(TypedDict):
    """What a client method returns in place of a response when the call failed."""

    Error: ErrorDetail


#: The three ``BotoCoreError`` subclasses whose meaning is specifically "the
#: network did not carry the call". Clients catch all of ``BotoCoreError``; this
#: tuple names only the members a check may want to word remediation for
#: ("confirm the endpoint is reachable").
#:
#: Private: nothing outside this module consumes the exception classes. Its only
#: job is to derive :data:`TRANSPORT_ERROR_CODES`, which is what the rest of the
#: tree imports.
_TRANSPORT_EXCEPTIONS: Final = (
    EndpointConnectionError,
    ConnectTimeoutError,
    ReadTimeoutError,
)

#: The ``Code`` values those three produce. **Derived** from
#: :data:`_TRANSPORT_EXCEPTIONS` rather than written out, so the tuple a client
#: raises through and the set a check tests against cannot drift. ``sra_waf_06``
#: is the one consumer.
TRANSPORT_ERROR_CODES: Final[frozenset[str]] = frozenset(
    exc.__name__ for exc in _TRANSPORT_EXCEPTIONS
)

#: ``Code`` for the no-client condition: a base accessor found no client
#: wrapper registered for the Region. Neither a success nor an AWS failure --
#: an undetermined state. Never cached, always an ERROR.
NO_CLIENT_CODE: Final = "NoClient"

#: The ``Operation`` an error result carries when no AWS operation name exists.
#:
#: Two conditions produce one. A ``BotoCoreError`` -- a timeout, missing
#: credentials, an unreachable endpoint -- means the request never completed, and
#: botocore attaches no operation because none was processed. And the no-client
#: condition means no request was made at all. In both, the request itself is
#: what failed, which is what this value says: an ERROR row reads
#: ``Request failed: EndpointConnectionError: Could not connect to ...``.
#:
#: Nothing downstream needs more. Neither condition's code is ever semantic, so
#: the discriminator does not consult the operation, and the message names the
#: endpoint or the Region.
UNKNOWN_OPERATION: Final = "Request"

#: The three keys :func:`is_error` requires, in the order the error result declares
#: them. Named once so the validator, the constructor, and the tests agree.
_ERROR_KEYS: Final = ("Code", "Message", "Operation")


def _require_text(name: str, value: Any) -> str:
    """Return ``value`` if it is a non-blank ``str``, else raise ``ValueError``.

    Args:
        name: The field name, for the error message.
        value: The candidate value.

    Returns:
        ``value`` unchanged.

    Raises:
        ValueError: If ``value`` is not a ``str``, or is blank after stripping.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"error_result: {name} must be a non-blank str, got {value!r}"
        )
    return value


def error_result(*, code: str, message: str, operation: str) -> ErrorResult:
    """Build an error result. Every field is a non-blank ``str``; that is the whole contract.

    Keyword-only, because ``code``, ``message``, and ``operation`` are three
    strings and a positional call that transposed two of them would be
    well-formed and silently wrong.

    Args:
        code: AWS error code, or the exception type name where none exists.
        message: The AWS error message.
        operation: The botocore operation name.

    Returns:
        An error result that :func:`is_error` recognizes.

    Raises:
        ValueError: If any field is not a non-blank ``str``. Every input
            :func:`is_error` would reject is rejected here, so a malformed
            error result cannot be constructed in the first place.
    """
    return {
        "Error": {
            "Code": _require_text("code", code),
            "Message": _require_text("message", message),
            "Operation": _require_text("operation", operation),
        }
    }


def no_client_result(*, service: str, region: str) -> ErrorResult:
    """Build the error result for a base accessor that found no client for a Region.

    No request was made, so ``Operation`` is :data:`UNKNOWN_OPERATION` rather
    than a per-accessor literal -- the same reasoning that removed the operation
    literal from every client ``except`` clause. The message already says which
    service and which Region.

    Args:
        service: Display name for the message, e.g. ``"Security Lake"``.
        region: The Region with no registered wrapper.

    Returns:
        An error result whose ``Code`` is :data:`NO_CLIENT_CODE`.
    """
    return error_result(
        code=NO_CLIENT_CODE,
        message=f"No {service} client is registered for Region {region}",
        operation=UNKNOWN_OPERATION,
    )


def is_error(value: Any) -> bool:
    """
    Return ``True`` iff ``value`` is a well-formed error result.

    That is: a ``Mapping`` whose ``Error`` member is itself a ``Mapping`` whose
    ``Code``, ``Message``, and ``Operation`` are each a ``str`` that is
    non-blank after stripping.

    Strict on purpose, in both directions.

    * A success dict from an operation that happens to have a top-level
      ``Error`` member of some other shape must not be mistaken for an error result.
    * A half-built value -- a blank ``Code``, a missing ``Operation`` -- must not
      pass as an error result and be half-read downstream, and must not fail the
      test and be cached as a success either. The only value that satisfies
      this is one :func:`error_result` could have built, which is why that
      constructor rejects exactly the inputs this predicate rejects.

    Args:
        value: Anything.

    Returns:
        ``True`` for a well-formed error_result, ``False`` for everything else.
    """
    if not isinstance(value, Mapping):
        return False
    err = value.get("Error")
    if not isinstance(err, Mapping):
        return False
    return all(
        isinstance(err.get(key), str) and err[key].strip() for key in _ERROR_KEYS
    )


@dataclass(frozen=True, slots=True)
class NotConfigured:
    """
    One declared "this code, from this operation, means not configured" fact.

    ``evidence`` is required and non-blank: the AWS API reference URL that
    documents the code's meaning for the operation, or a build-log line from a
    controlled account observed to produce it. A table entry converts an ERROR
    into a FAIL -- it turns "we could not tell" into "we established the control
    is absent" -- so an entry without evidence is an assertion, not a fact, and
    a wrong one fabricates a finding out of a permission failure. Validated at
    construction rather than checked by convention, because a comment can be
    omitted and a required field cannot.

    ``message``, when given, is a case-insensitive substring the error message
    must contain. This is the discriminator for an **overloaded** code -- one
    AWS returns for both a semantic condition and an access failure, so the
    code alone cannot classify it. ``macie2`` returns
    ``AccessDeniedException`` both when Macie is disabled in a Region and when
    the caller lacks the API permission; only the message separates them.
    """

    evidence: str
    """Why this entry is a fact: an API reference URL, or an observed log line."""

    message: str | None = None
    """Case-insensitive substring the message must contain, for an overloaded code."""

    def __post_init__(self) -> None:
        """Reject a blank or non-``str`` ``evidence``.

        Raises:
            ValueError: If ``evidence`` is not a non-blank ``str``.
        """
        if not isinstance(self.evidence, str) or not self.evidence.strip():
            raise ValueError("NotConfigured.evidence must be a non-blank str")


#: operation -> code -> the fact. Declared as a literal on each service base
#: class and never mutated. Keyed by operation first because the judgement is a
#: function of the pair: the same code can mean "not configured" through one
#: operation and "wrong account" through another.
NotConfiguredTable = Mapping[str, Mapping[str, NotConfigured]]


def is_not_configured(table: NotConfiguredTable, error: Mapping[str, str]) -> bool:
    """
    Decide whether ``error`` means the control is absent for the operation that
    produced it.

    Lookup is operation -> code -> optional message substring. **Anything not
    declared is** ``False``: an unknown code, a known code arriving from an
    operation it is not declared for, or a declared substring that does not
    appear in the message. ``False`` means the check should yield ERROR;
    ``True`` means FAIL.

    Conservative in that one direction on purpose. A code AWS introduces later,
    or a code that reaches an operation nobody considered, produces an honest
    ERROR rather than a fabricated FAIL.

    Args:
        table: The service's ``NOT_CONFIGURED_ERRORS``.
        error: An error result's ``Error`` sub-dict, which carries ``Operation``.

    Returns:
        ``True`` if the pair is declared and any message needle matches.
    """
    by_code = table.get(error.get("Operation", ""))
    if not by_code:
        return False
    fact = by_code.get(error.get("Code", ""))
    if fact is None:
        return False
    if fact.message is None:
        return True
    return fact.message.lower() in error.get("Message", "").lower()
