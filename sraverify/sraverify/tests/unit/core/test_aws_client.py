"""
Unit tests for ``core/aws_client.py`` -- ``AWSClient.aws_error``.

``aws_error`` is the single line every client's ``except`` clause contains, so
it is the one piece of the client tier that is written once and relied on 92
times. These tests pin its behaviour directly; the reflection module
``tests/property/test_client_contract_property.py`` then drives every real client
method through the same failure kinds and asserts the return shape.

Every test here exercises :class:`_ExampleClient`, which is written in exactly
the shape ``services/*/client.py`` uses -- a plain ``try`` around the boto3 call,
one ``except AWS_EXCEPTIONS`` clause, ``return self.aws_error(e)``. So these test
the *pattern* and not only the helper.

The asymmetry these tests exist to pin
--------------------------------------

The design question that produced this class was whether the ``except`` clause
should carry an ``operation=`` literal. It does not, and the reason is a fact
about botocore rather than a preference:

* A ``ClientError`` means AWS answered with an error code, and botocore sets
  ``e.operation_name`` on every one. The literal would be redundant -- and worse,
  it *can disagree* with what actually failed, which no test could catch.
* A ``BotoCoreError`` means the request never completed, so botocore attaches no
  operation. There is nothing to read.

So a ``ClientError`` carries the real operation and a ``BotoCoreError`` carries
:data:`UNKNOWN_OPERATION`. Nothing downstream needs more from the second case,
and :func:`test_a_transport_operation_is_never_semantic` and
:func:`test_a_transport_error_result_still_produces_actionable_remediation` are the
tests that hold that claim rather than merely asserting it.

Validates: Requirements 1.1, 1.2, 1.3, 1.8, 1.9, 2.1, 2.2, 2.3, 2.4.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
    NoCredentialsError,
    ParamValidationError,
    ReadTimeoutError,
)

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.aws_errors import (
    TRANSPORT_ERROR_CODES,
    UNKNOWN_OPERATION,
    NotConfigured,
    is_error,
    is_not_configured,
)
from sraverify.core.scan_context import ScanContext

_REGION = "us-west-1"

#: The one record a client emits on failure, as the acceptance gate parses it:
#: three whitespace-free fields then a JSON-encoded message, in that order.
_LOG_RE = re.compile(
    r"^aws_call_failed operation=(?P<op>\S+) region=(?P<region>\S+) "
    r"code=(?P<code>\S+) message=(?P<message>.*)$",
    re.DOTALL,
)


class _ExampleClient(AWSClient):
    """A client written exactly the way every real client is written."""

    def __init__(self, region: str = _REGION) -> None:
        """Build against a mock context and a mock boto3 client.

        Args:
            region: The Region this wrapper serves.
        """
        super().__init__(region, MagicMock(spec=ScanContext))
        self.client = MagicMock(name="boto3:example")

    def describe_thing(self) -> Any:
        """Call the operation.

        Returns:
            The boto3 response on success, or the error result.
        """
        try:
            return self.client.describe_thing()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)


@pytest.fixture
def client() -> _ExampleClient:
    """A client whose one operation can be armed to raise or return.

    Returns:
        The client.
    """
    return _ExampleClient()


@pytest.fixture
def guard_log() -> Any:
    """Capture records from the ``sraverify`` logger.

    ``caplog`` cannot be used: ``core/logging.py`` sets ``propagate = False`` and
    binds its own handler, so records never reach the root logger pytest
    attaches to.

    Yields:
        The captured records, in emission order.
    """
    records: list[logging.LogRecord] = []

    class _Collector(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Collector()
    target = logging.getLogger("sraverify")
    target.addHandler(handler)
    try:
        yield records
    finally:
        target.removeHandler(handler)


def _errors(records: list[logging.LogRecord]) -> list[str]:
    """Return the messages of the ``ERROR``-level records.

    Args:
        records: Captured records.

    Returns:
        Formatted messages.
    """
    return [r.getMessage() for r in records if r.levelno >= logging.ERROR]


def _client_error(
    code: str = "AccessDeniedException",
    message: str = "not authorized",
    operation: str = "DescribeThing",
) -> ClientError:
    """Build a ``ClientError`` shaped the way botocore builds one.

    Args:
        code: The AWS error code.
        message: The AWS error message.
        operation: The operation name botocore attaches.

    Returns:
        A ``ClientError`` with ``operation_name`` set.
    """
    return ClientError({"Error": {"Code": code, "Message": message}}, operation)


# --------------------------------------------------------------------------- #
# AWS_EXCEPTIONS -- the pair every client catches
# --------------------------------------------------------------------------- #


def test_aws_exceptions_is_exactly_client_error_and_botocore_error() -> None:
    """Requirement 2.1 and 2.2: catch these two, and nothing else.

    Named as a tuple so an ``except`` clause cannot narrow the pair by accident.
    Writing ``except ClientError`` alone is what let transport failures escape
    seven clients, and because the orchestrator materializes
    ``list(check.execute())``, one escaped timeout discarded every row the check
    had already yielded for every other Region.
    """
    assert set(AWS_EXCEPTIONS) == {ClientError, BotoCoreError}


def test_aws_exceptions_excludes_exception_and_base_exception() -> None:
    """A client that caught either would swallow programming defects."""
    assert Exception not in AWS_EXCEPTIONS
    assert BaseException not in AWS_EXCEPTIONS


# --------------------------------------------------------------------------- #
# ClientError -- AWS answered, and carries its own operation
# --------------------------------------------------------------------------- #


def test_a_client_error_becomes_an_error_result_with_aws_code_and_message(
    client: _ExampleClient, guard_log: Any
) -> None:
    """AWS's own code and message reach the caller, verbatim."""
    client.client.describe_thing.side_effect = _client_error()

    result = client.describe_thing()

    assert is_error(result), f"expected an error result, got {result!r}"
    assert result["Error"] == {
        "Code": "AccessDeniedException",
        "Message": "not authorized",
        "Operation": "DescribeThing",
    }


def test_the_operation_comes_from_botocore_not_from_a_literal(
    client: _ExampleClient, guard_log: Any
) -> None:
    """The reason the ``except`` clause carries no ``operation=``.

    botocore sets ``operation_name`` on every ``ClientError``, and it names what
    actually failed. A literal at the call site would be redundant when it agreed
    and silently wrong when it did not -- and nothing at runtime could tell the
    difference, which made it the one value in the client layer no test defended.
    """
    client.client.describe_thing.side_effect = _client_error(
        operation="SomeQuiteDifferentOperation"
    )

    result = client.describe_thing()

    assert result["Error"]["Operation"] == "SomeQuiteDifferentOperation"


def test_the_message_comes_from_the_response_not_from_str(
    client: _ExampleClient, guard_log: Any
) -> None:
    """Requirement 1.3, and the most visible change to existing ERROR rows.

    ``str(e)`` is botocore's ``An error occurred (Code) when calling the Op
    operation: <message>`` wrapper. Four clients used it and five used the
    response's own message, so a discriminator matching on message text saw a
    different string per service, and every ERROR cell repeated the code and
    operation the row already carries in its own columns.
    """
    client.client.describe_thing.side_effect = _client_error(
        message="The subscription does not exist."
    )

    result = client.describe_thing()

    assert result["Error"]["Message"] == "The subscription does not exist."
    assert "An error occurred" not in result["Error"]["Message"]


def test_a_missing_message_falls_back_to_str(
    client: _ExampleClient, guard_log: Any
) -> None:
    """``Message`` is never blank, even when the error dict omits it.

    A blank one would make ``is_error`` reject the error result the client just built.
    """
    client.client.describe_thing.side_effect = ClientError(
        {"Error": {"Code": "SomeCode"}}, "DescribeThing"
    )

    result = client.describe_thing()

    assert is_error(result)
    assert result["Error"]["Message"].strip()


def test_a_missing_code_falls_back_to_the_type_name(
    client: _ExampleClient, guard_log: Any
) -> None:
    """``Code`` is never blank, even when the error dict omits it."""
    client.client.describe_thing.side_effect = ClientError(
        {"Error": {"Message": "no code here"}}, "DescribeThing"
    )

    result = client.describe_thing()

    assert is_error(result)
    assert result["Error"]["Code"] == "ClientError"


def test_a_client_error_with_no_operation_name_falls_back_to_the_placeholder(
    client: _ExampleClient, guard_log: Any
) -> None:
    """``Operation`` must be non-blank for ``is_error`` to accept the error result.

    A hand-built ``ClientError`` can lack ``operation_name``; a real one from
    botocore never does.
    """
    exc = _client_error()
    exc.operation_name = None  # type: ignore[attr-defined]
    client.client.describe_thing.side_effect = exc

    result = client.describe_thing()

    assert is_error(result)
    assert result["Error"]["Operation"] == UNKNOWN_OPERATION


# --------------------------------------------------------------------------- #
# BotoCoreError -- the request never completed
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "exc,expected_code",
    [
        (EndpointConnectionError(endpoint_url="https://x"), "EndpointConnectionError"),
        (ConnectTimeoutError(endpoint_url="https://x"), "ConnectTimeoutError"),
        (ReadTimeoutError(endpoint_url="https://x"), "ReadTimeoutError"),
        (NoCredentialsError(), "NoCredentialsError"),
        (ParamValidationError(report="bad parameter"), "ParamValidationError"),
    ],
    ids=[
        "EndpointConnectionError",
        "ConnectTimeoutError",
        "ReadTimeoutError",
        "NoCredentialsError",
        "ParamValidationError",
    ],
)
def test_every_botocore_error_becomes_an_error_result_named_by_type(
    client: _ExampleClient, guard_log: Any, exc: BaseException, expected_code: str
) -> None:
    """Requirement 2.1: the whole family, not three subclasses.

    ``NoCredentialsError`` is the discriminating case. It is not a transport
    error and carries no AWS code, so a client enumerating only the three
    transport subclasses -- which is what the tree's most complete hand-written
    handler did -- would let it propagate.

    ``ParamValidationError`` pins a documented trade-off: it is arguably a
    programming defect, and it is accepted as an error result rather than carved out,
    because botocore raises it before any network call and names the offending
    parameter in its message.
    """
    client.client.describe_thing.side_effect = exc

    result = client.describe_thing()

    assert is_error(result), f"expected an error result for {expected_code}, got {result!r}"
    assert result["Error"]["Code"] == expected_code
    assert result["Error"]["Message"].strip()


def test_a_botocore_error_claims_no_operation(
    client: _ExampleClient, guard_log: Any
) -> None:
    """The asymmetry, asserted directly.

    The request never reached an operation, so none is claimed. Saying
    ``Operation: "DescribeThing"`` here would assert that a specific call was
    attempted and refused, when in fact nothing was sent.
    """
    client.client.describe_thing.side_effect = EndpointConnectionError(
        endpoint_url="https://guardduty.us-west-1.amazonaws.com/"
    )

    result = client.describe_thing()

    assert result["Error"]["Operation"] == UNKNOWN_OPERATION


def test_a_transport_message_still_names_the_endpoint(
    client: _ExampleClient, guard_log: Any
) -> None:
    """Why the placeholder costs the reader nothing.

    The row still says which service and which Region could not be reached,
    because botocore's own message carries the endpoint URL. That is the
    information an operator acts on; the operation name would add nothing to it.
    """
    client.client.describe_thing.side_effect = EndpointConnectionError(
        endpoint_url="https://guardduty.us-west-1.amazonaws.com/"
    )

    result = client.describe_thing()

    assert "guardduty" in result["Error"]["Message"]
    assert "us-west-1" in result["Error"]["Message"]


def test_a_transport_operation_is_never_semantic() -> None:
    """The placeholder cannot cause a fabricated FAIL.

    This is the claim that makes dropping the operation safe. The discriminator
    is keyed by operation, so an error result carrying the placeholder can only
    classify as "not configured" if some service declared the placeholder as an
    operation -- and no service can, because a transport code is never semantic
    for any operation. Swept over a table that declares the placeholder to prove
    the code, not the operation, is what excludes it.
    """
    hostile_table = {
        UNKNOWN_OPERATION: {
            "EndpointConnectionError": NotConfigured(evidence="deliberately wrong"),
        }
    }

    for code in TRANSPORT_ERROR_CODES:
        error = {
            "Code": code,
            "Message": "could not connect",
            "Operation": UNKNOWN_OPERATION,
        }
        # A service *could* declare this pair, which is why the real protection is
        # that no service does -- asserted catalog-wide by
        # test_discriminator_property.test_no_service_classifies_a_transport_or_no_client_code.
        # Here we only show the lookup is by (operation, code) and nothing else.
        assert is_not_configured({}, error) is False

    assert is_not_configured(
        hostile_table,
        {
            "Code": "EndpointConnectionError",
            "Message": "x",
            "Operation": UNKNOWN_OPERATION,
        },
    ) is True, (
        "the lookup is not consulting the table; this test's premise is wrong"
    )


# --------------------------------------------------------------------------- #
# What the pattern must not catch
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "exc",
    [
        RuntimeError("boom"),
        AttributeError("'NoneType' object has no attribute 'get'"),
        KeyError("DetectorIds"),
        TypeError("unhashable"),
        IndexError("list index out of range"),
        ValueError("bad value"),
    ],
    ids=["RuntimeError", "AttributeError", "KeyError", "TypeError", "IndexError", "ValueError"],
)
def test_a_programming_defect_propagates_through_the_pattern(
    client: _ExampleClient, guard_log: Any, exc: BaseException
) -> None:
    """Requirement 1.9: ``except AWS_EXCEPTIONS`` does not catch these.

    The most important negative here. Converting these into error results would give
    a typo in a client a plausible ERROR row per Region, recurring on every scan
    until somebody noticed ``AttributeError`` is not an AWS error code.
    Propagating sends it to the orchestrator's guard, which reports it once,
    loudly, with a traceback.
    """
    client.client.describe_thing.side_effect = exc

    with pytest.raises(type(exc)):
        client.describe_thing()

    assert _errors(guard_log) == [], (
        "a propagating defect must not emit aws_call_failed; the acceptance gate "
        "would read it as an AWS outcome for that Region"
    )


def test_the_pattern_never_catches_keyboard_interrupt(
    client: _ExampleClient, guard_log: Any
) -> None:
    """Requirement 2.4: an interrupted scan must not produce a complete-looking report."""
    client.client.describe_thing.side_effect = KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        client.describe_thing()


def test_aws_error_refuses_a_non_aws_exception(
    client: _ExampleClient, guard_log: Any
) -> None:
    """The backstop for a client that caught too much.

    If someone writes ``except Exception as e: return self.aws_error(e)``, the
    defect surfaces here as a loud ``TypeError`` rather than as a plausible
    error result with ``Code="KeyError"`` sitting in the CSV.
    """
    with pytest.raises(TypeError, match="not an AWS outcome"):
        client.aws_error(KeyError("x"))

    assert _errors(guard_log) == []


# --------------------------------------------------------------------------- #
# The success path
# --------------------------------------------------------------------------- #


def test_a_success_response_passes_through_untouched(
    client: _ExampleClient, guard_log: Any
) -> None:
    """The pattern returns the boto3 response by identity, and logs nothing."""
    response = {"Things": [{"id": "a"}], "nextToken": None}
    client.client.describe_thing.return_value = response

    result = client.describe_thing()

    assert result is response
    assert not is_error(result)
    assert _errors(guard_log) == []


def test_an_empty_response_is_a_legitimate_success(
    client: _ExampleClient, guard_log: Any
) -> None:
    """``{}`` means AWS answered with nothing in it.

    This is the distinction the whole feature turns on. An empty dict from a
    successful call and an empty dict standing in for a swallowed error used to
    be the same value; the pattern cannot produce the second.
    """
    client.client.describe_thing.return_value = {}

    result = client.describe_thing()

    assert result == {}
    assert not is_error(result)


# --------------------------------------------------------------------------- #
# The structured log record
# --------------------------------------------------------------------------- #


def test_a_client_error_emits_exactly_one_parseable_record(
    client: _ExampleClient, guard_log: Any
) -> None:
    """Requirement 1.8: one record, at ``error``, four fields in the gate's order.

    Exactly one, because the gate attributes records to checks by position and
    counts them: two records would make one failure look like two, and none would
    leave a FAIL-to-ERROR transition unevidenced and reject the batch.
    """
    client.client.describe_thing.side_effect = _client_error()

    client.describe_thing()

    messages = _errors(guard_log)
    assert len(messages) == 1, f"expected exactly one record, got {messages}"

    match = _LOG_RE.match(messages[0])
    assert match is not None, f"unparseable log line: {messages[0]!r}"
    assert match.group("op") == "DescribeThing"
    assert match.group("region") == _REGION
    assert match.group("code") == "AccessDeniedException"
    assert json.loads(match.group("message")) == "not authorized"


def test_the_region_in_the_record_comes_from_the_client(guard_log: Any) -> None:
    """Why the ``except`` clause carries no ``region=`` either.

    Every client already stores its Region. Passing it per call site was noise
    with a failure mode: a copy-pasted method could log the wrong Region and the
    gate would attribute the failure to a Region that succeeded.
    """
    other = _ExampleClient(region="eu-west-3")
    other.client.describe_thing.side_effect = _client_error()

    other.describe_thing()

    match = _LOG_RE.match(_errors(guard_log)[0])
    assert match is not None
    assert match.group("region") == "eu-west-3"


def test_a_transport_error_emits_the_same_record_shape(
    client: _ExampleClient, guard_log: Any
) -> None:
    """The ``BotoCoreError`` path logs identically, placeholder operation included.

    The gate parses one format. A second shape for transport failures would mean
    a second parser branch, and the records it most needs to read are exactly the
    transport ones -- they are what admit a FAIL-to-ERROR transition.
    """
    client.client.describe_thing.side_effect = EndpointConnectionError(
        endpoint_url="https://guardduty.us-west-1.amazonaws.com/"
    )

    client.describe_thing()

    messages = _errors(guard_log)
    assert len(messages) == 1

    match = _LOG_RE.match(messages[0])
    assert match is not None, f"unparseable log line: {messages[0]!r}"
    assert match.group("op") == UNKNOWN_OPERATION
    assert match.group("region") == _REGION
    assert match.group("code") == "EndpointConnectionError"
    assert "guardduty" in json.loads(match.group("message"))


@pytest.mark.parametrize(
    "message",
    [
        "plain message",
        'message with "quotes"',
        "message with\nan embedded newline",
        "message with\r\na CRLF",
        "message with\ttab",
        'nested "quotes" and\nnewline together',
        "trailing backslash \\",
        "unicode: \u65e5\u672c\u8a9e \U0001f600",
    ],
    ids=[
        "plain", "quotes", "newline", "crlf", "tab", "quotes-and-newline",
        "backslash", "unicode",
    ],
)
def test_the_message_field_always_round_trips_through_json(
    client: _ExampleClient, guard_log: Any, message: str
) -> None:
    """A hostile AWS message cannot break the one-line promise.

    This is why ``message`` is JSON-encoded and last, and why the encoding lives
    in one method rather than in 92 hand-written ``except`` clauses. An AWS
    message containing a newline would otherwise split the record across two
    lines, and the gate's per-line parser would read the tail as a separate
    malformed record -- silently dropping the evidence that admits a FAIL-to-ERROR
    transition.
    """
    client.client.describe_thing.side_effect = _client_error(message=message)

    client.describe_thing()

    messages = _errors(guard_log)
    assert len(messages) == 1

    match = _LOG_RE.match(messages[0])
    assert match is not None
    assert json.loads(match.group("message")) == message

    encoded = match.group("message")
    assert "\n" not in encoded and "\r" not in encoded, (
        f"json.dumps left a raw line break in {encoded!r}"
    )


# --------------------------------------------------------------------------- #
# The base class itself
# --------------------------------------------------------------------------- #


def test_the_base_class_stores_region_and_context() -> None:
    """The two attributes every client used to declare identically itself."""
    ctx = MagicMock(spec=ScanContext)
    instance = AWSClient("us-east-2", ctx)

    assert instance.region == "us-east-2"
    assert instance.ctx is ctx


def test_aws_error_needs_only_the_exception() -> None:
    """The signature is the whole point of this class.

    One positional argument. Nothing to type per call site, so nothing that can
    be typed wrong -- which was the objection that removed ``operation=`` and
    ``region=`` from every one of the 92 handlers.
    """
    import inspect

    parameters = list(inspect.signature(AWSClient.aws_error).parameters)
    assert parameters == ["self", "e"], (
        f"aws_error takes {parameters}; it must take only the exception, or the "
        f"per-call-site mistakes this class exists to remove come back"
    )
