"""Top-level pytest configuration for the sraverify test suite.

Two jobs: keep the AWS SDK's logging out of the test output, and keep the suite
offline.

Silences chatty boto3/botocore loggers during tests so test output stays
focused on the property and unit test results.
"""
import logging

import pytest


def _silence_aws_sdk_loggers() -> None:
    """Raise the log level on the boto3/botocore logger trees to WARNING.

    The AWS SDK logs at INFO/DEBUG with high volume during normal client
    construction. Silencing the loggers at the top of the tests package
    keeps pytest output readable when running unit and property tests
    that exercise mocked or real boto3 client construction paths.
    """
    for logger_name in (
        "boto3",
        "botocore",
        "botocore.credentials",
        "botocore.endpoint",
        "botocore.hooks",
        "botocore.loaders",
        "botocore.parsers",
        "botocore.retryhandler",
        "s3transfer",
        "urllib3",
    ):
        logging.getLogger(logger_name).setLevel(logging.WARNING)


_silence_aws_sdk_loggers()


#: Message the refused transport raises with. Asserted on by
#: ``tests/property/test_availability_property.py``, so the two agree.
_OFFLINE_MESSAGE = (
    "the sraverify test suite is offline: a test attempted an HTTP request to "
    "{url!r}. No test may issue an AWS call (Requirement 7.9). If this fires "
    "from a contract test, its mock is not intercepting the boto3 call it "
    "thinks it is."
)


@pytest.fixture(autouse=True)
def _no_aws_calls(monkeypatch):
    """Property 19: refuse every outbound HTTP request, for the whole suite.

    The suite already made no AWS call. This proves it rather than asserting it,
    and the distinction is load-bearing for the contract tests: they work by
    making a mocked boto3 method raise ``ClientError`` and checking what the
    client returns. If a mock were wired to the wrong attribute, the real call
    would go out instead -- against whatever credentials happen to be in the
    environment -- and the test could still pass, because a real
    ``AccessDeniedException`` produces an error result too. With the transport
    refused, that mistake surfaces as this message instead of as a green run.

    Patches only ``send``. Client **construction** stays fully functional and
    must: ``ScanContext.get_client`` builds a client per ``(service, Region)``,
    and ``core/availability.py`` reads botocore's bundled endpoint data through a
    real ``Session``. Neither touches the network, and blocking them would break
    a large part of the suite for no gain.

    Autouse rather than opt-in, so a test added later is covered without anyone
    remembering to ask.

    Args:
        monkeypatch: pytest's monkeypatch fixture, so the patch is undone per
            test rather than leaking across the session.
    """
    import botocore.httpsession

    def _refuse(self, request):
        """Refuse to send.

        Args:
            self: The ``URLLib3Session`` instance.
            request: The prepared botocore request.

        Raises:
            AssertionError: Always.
        """
        raise AssertionError(
            _OFFLINE_MESSAGE.format(url=getattr(request, "url", "<unknown>"))
        )

    monkeypatch.setattr(botocore.httpsession.URLLib3Session, "send", _refuse)
