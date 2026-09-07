"""Top-level pytest configuration for the sraverify test suite.

Silences chatty boto3/botocore loggers during tests so test output stays
focused on the property and unit test results.
"""
import logging


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
