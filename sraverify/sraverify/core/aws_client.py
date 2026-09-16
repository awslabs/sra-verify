"""
The base class every ``<Service>Client`` inherits.

It does two things and nothing else: it holds the ``region`` and ``ctx`` that
every client already stored identically in its own ``__init__``, and it provides
:meth:`AWSClient.aws_error`, the one line every client's ``except`` clause is.

The canonical client method::

    class GuardDutyClient(AWSClient):
        def __init__(self, region: str, ctx: ScanContext):
            super().__init__(region, ctx)
            self.client = ctx.get_client("guardduty", region=region)

        def get_detector_details(self, detector_id: str) -> Mapping[str, Any]:
            try:
                return self.client.get_detector(DetectorId=detector_id)
            except AWS_EXCEPTIONS as e:
                return self.aws_error(e)

That ``except`` clause is byte-identical in every method of every client. There
is nothing on it to type per call site -- no operation name, no Region -- and so
nothing on it that can be wrong in a way a test would not catch. The boto3 call
itself is still direct and visible; this class sits *beside* it, not between it
and the API.

Why the ``except`` clause has no parameters
--------------------------------------------

Because a value typed at 92 call sites is a value that will be typed wrong at one
of them, and an operation literal is the one thing in the client layer no test can
defend.

The Region comes from ``self.region``. The operation comes from botocore where
botocore has it, and is a placeholder where it does not:

* A ``ClientError`` means AWS answered with an error code, and botocore sets
  ``e.operation_name`` on every one. That is the operation that actually failed,
  and it is more trustworthy than any literal could be.
* A ``BotoCoreError`` -- a timeout, missing credentials, an unreachable endpoint,
  a malformed parameter -- means the request never completed. botocore attaches
  no operation, because none was processed. The error result's ``Operation`` is
  :data:`~sraverify.core.aws_errors.UNKNOWN_OPERATION` and nothing downstream
  needs more: such a code is never semantic, so the discriminator does not
  consult the operation, and the message already names the endpoint.
"""
from __future__ import annotations

import json
from typing import Any, Final

from botocore.exceptions import BotoCoreError, ClientError

from sraverify.core.aws_errors import UNKNOWN_OPERATION, ErrorResult, error_result
from sraverify.core.logging import logger
from sraverify.core.scan_context import ScanContext

#: The exception families a client method catches. Exactly these two, named as a
#: tuple so an ``except`` clause cannot narrow the pair by accident -- writing
#: ``except ClientError`` alone is what let transport failures escape seven
#: clients and cost each affected check its whole output for the account.
#:
#: Anything else -- ``AttributeError``, ``KeyError``, ``TypeError`` -- is a
#: programming defect in the client and must propagate to the orchestrator's
#: guard. A handler that caught ``Exception`` would turn a typo into a plausible
#: ERROR row per Region, recurring on every scan until somebody noticed that
#: ``AttributeError`` is not an AWS error code.
AWS_EXCEPTIONS: Final = (ClientError, BotoCoreError)


class AWSClient:
    """Base for every ``<Service>Client``: the shared attributes and the one handler."""

    def __init__(self, region: str, ctx: ScanContext) -> None:
        """Store the Region and the per-scan context.

        Subclasses acquire their boto3 clients here, in ``__init__``, and nowhere
        else. ``ctx.get_client`` reads bundled endpoint data and issues no network
        call, so its failure is deterministic and belongs to the orchestrator's
        guard -- not inside a method's ``try``, where it would be caught as a
        ``BotoCoreError`` and turned into an error result describing an AWS outcome
        that never happened.

        Args:
            region: The Region this wrapper serves. A global service passes
                ``"global"``.
            ctx: The per-scan context.
        """
        self.region = region
        self.ctx = ctx

    def aws_error(self, e: Exception) -> ErrorResult:
        """
        Build the error result for a caught AWS exception, and log it.

        The only line a client's ``except`` clause contains. See the module
        docstring for why it takes nothing but the exception.

        Emits exactly one ``debug``-level record::

            aws_call_failed operation=<Op> region=<Region> code=<Code> message=<JSON>

        ``message`` is last and ``json.dumps``-encoded -- quoted, with embedded
        newlines and quotes escaped -- so an AWS message containing a newline
        cannot break the one-line promise: one failed call is always one line.

        ``debug`` rather than ``error``, because **this tier cannot know how bad
        this is.** A failed AWS call is not a verdict. ``AccessDeniedException:
        Macie is not enabled`` is a normal, expected observation that the check
        tier turns into a FAIL row; ``AccessDeniedException`` naming a principal
        and an action is a broken scan. Only the check tier can tell them apart,
        via ``is_not_configured``, and a log level is a classification -- so
        emitting ``error`` here assigns a severity one tier before the
        information needed to assign it exists.

        Emitting it at ``error`` made the tool contradict itself: an audit-account
        scan printed five ERROR lines and then reported ``Error: 0``, because all
        five failures were semantic and became FAIL rows. The invariant now is
        that an ERROR-level record means an ERROR row, and
        ``test_no_error_level_records_without_error_rows`` holds it.

        Nothing is lost by the demotion. A semantic failure's FAIL row states the
        reason in ``ActualValue``; an ERROR row carries the operation, code and
        message verbatim. The report is the artefact, the summary counts the
        ERROR rows, and ``--debug`` still yields every raw record for anyone
        auditing a classification.

        Args:
            e: The caught exception. Must be a ``ClientError`` or ``BotoCoreError``.

        Returns:
            An :func:`~sraverify.core.aws_errors.error_result`.

        Raises:
            TypeError: If ``e`` is neither. A client that reached here with
                anything else has caught too much, and the right report of that
                is a loud failure rather than a plausible error result whose ``Code``
                is ``KeyError``.
        """
        if isinstance(e, ClientError):
            err = e.response.get("Error", {})
            # The response's own message, not str(e): botocore's str() wraps it
            # in "An error occurred (Code) when calling the Op operation: ...",
            # which repeats the code and operation the row already carries in
            # its own cells and gives a discriminator matching on message text a
            # different string per service.
            code = err.get("Code") or type(e).__name__
            message = err.get("Message") or str(e)
            operation = getattr(e, "operation_name", None) or UNKNOWN_OPERATION
        elif isinstance(e, BotoCoreError):
            # No AWS code exists, so the exception's type name is the code --
            # EndpointConnectionError, NoCredentialsError -- and no operation was
            # processed, so none is claimed.
            code = type(e).__name__
            message = str(e) or code
            operation = UNKNOWN_OPERATION
        else:
            raise TypeError(
                f"aws_error: {type(e).__name__} is not an AWS outcome. A client "
                f"must catch only AWS_EXCEPTIONS; anything else is a programming "
                f"defect and must propagate."
            )

        logger.debug(
            f"aws_call_failed operation={operation} region={self.region} "
            f"code={code} message={json.dumps(message)}"
        )
        return error_result(code=code, message=message, operation=operation)
