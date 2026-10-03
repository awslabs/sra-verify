"""Typed errors for catalog and selection failures.

The first three errors below are import-time failures -- a catalog defect that
no invocation can work around. The next three are usage failures, and are the
ones ``sraverify.cli.main()`` catches to exit non-zero. The last,
``ScanPreconditionError``, is neither: it reports a failed identity or Region
lookup from inside one check and never escapes ``run_checks``. Keeping them in
one module lets ``scanner.py`` and ``cli.py`` import every ``except`` clause from
a single place.
"""

from __future__ import annotations

from typing import Final, Literal, Mapping

_UNSET: Final = object()  # private sentinel: "no bad value was supplied"


class SRAVerifyError(Exception):
    """Base for every error this package raises deliberately."""


class MetadataError(SRAVerifyError):
    """A CheckMeta declaration carries a value that fails validation."""


class CheckIdentityError(SRAVerifyError):
    """A check's metadata, class name, and module file name disagree,
    or a check module declares a check with no metadata at all."""


class DuplicateCheckIdError(SRAVerifyError):
    """Two distinct classes claim the same check ID."""


class UnknownCheckError(SRAVerifyError):
    """--check named an ID that is not in the registry."""

    def __init__(self, check_id: str, suggestions: list[str]) -> None:
        """Record the unmatched ID and the near-miss registry keys.

        Args:
            check_id: The check ID supplied on the command line, verbatim.
            suggestions: Registry keys close enough to be worth offering,
                most similar first. May be empty.
        """
        self.check_id = check_id
        self.suggestions = suggestions
        hint = f" Did you mean: {', '.join(suggestions)}?" if suggestions else ""
        super().__init__(f"Unknown check '{check_id}'.{hint}")


class NoChecksSelectedError(SRAVerifyError):
    """The filter combination matched zero checks.

    Raised with the three filter values as positional args --- ``account_type``,
    ``service``, ``check_id``, where ``None`` marks a filter that was not supplied
    and ``"all"`` is the account-type equivalent. The args tuple is deliberately
    left as those three values rather than replaced by a composed message: a
    library caller needs them separately to explain the failure in its own terms.

    ``__str__`` renders them as a sentence, because the CLI logs ``str(exc)`` and
    the default rendering of a three-arg exception is the raw tuple --
    ``('audit', None, 'SRA-MACIE-05')`` --- which makes an operator work out which
    value is which before they can act on it.
    """

    def __str__(self) -> str:
        """Render the filter combination as an actionable sentence.

        Returns:
            The supplied filters, named as the flags that set them, and a pointer
            to the inventory command.
        """
        account_type, service, check_id = (list(self.args) + [None, None, None])[:3]
        parts = [f"--account-type {account_type}"]
        if service is not None:
            parts.append(f"--service {service!r}")
        if check_id is not None:
            parts.append(f"--check {check_id}")
        return (
            f"No checks matched {', '.join(parts)}. "
            "Run --list-checks to see which checks exist for that account type."
        )


class PartitionUndeterminedError(SRAVerifyError):
    """The scan Region, and so the partition, could not be determined.

    Attributes:
        reason: "absent" when neither --regions nor the session supplied a
            Region; "invalid" when the first --regions value was supplied but
            is not a usable Region string.
        bad_value: The rejected first --regions value when reason is
            "invalid" (which may itself be None, e.g. regions=[None]);
            None when reason is "absent". Read reason, not bad_value, to tell
            the two cases apart.
    """

    reason: Literal["absent", "invalid"]
    bad_value: object | None

    def __init__(self, bad_value: object = _UNSET) -> None:
        if bad_value is _UNSET:
            self.reason = "absent"
            self.bad_value = None
            msg = (
                "Cannot determine the AWS partition: no --regions value was given "
                "and the session has no Region. Pass --regions (for example "
                "--regions us-east-1), or set AWS_DEFAULT_REGION or region = in "
                "the AWS profile. boto3 does not read AWS_REGION by itself."
            )
        else:
            self.reason = "invalid"
            self.bad_value = bad_value
            msg = (
                "Cannot determine the AWS partition: the first --regions value "
                f"{bad_value!r} is not a Region name. Pass a Region name as the "
                "first --regions value."
            )
        super().__init__(msg)


class ScanPreconditionError(SRAVerifyError):
    """A check read the account identity or Region list, and the lookup failed.

    Raised by SecurityCheck's context properties; caught by run_checks' per-check
    guard, never by a check. Not a usage error: the CLI never sees it.

    Attributes:
        check_id: The check that read the failed fact.
        lookup: ``"identity"`` or ``"regions"``.
        error: The error result's ``Error`` sub-dict.
    """

    def __init__(self, *, check_id: str, lookup: str, error: Mapping[str, str]) -> None:
        self.check_id = check_id
        self.lookup = lookup          # "identity" or "regions"
        self.error = error            # the error result's "Error" sub-dict
        super().__init__(
            f"{check_id}: {lookup} lookup failed: "
            f"{error['Operation']} failed: {error['Code']}: {error['Message']}"
        )
