"""Legal value sets for finding and metadata fields."""

from enum import StrEnum


class Status(StrEnum):
    """Outcome of a check for one region and one resource."""

    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"


class Severity(StrEnum):
    """Severity of a check's finding."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AccountType(StrEnum):
    """Account role a check applies to.

    The members' values are exactly the ``--account-type`` choices, so the CLI
    is fed ``[t.value for t in AccountType] + ["all"]`` rather than carrying a
    second list of account-type strings.
    """

    APPLICATION = "application"
    AUDIT = "audit"
    LOG_ARCHIVE = "log-archive"
    MANAGEMENT = "management"
