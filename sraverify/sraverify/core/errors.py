"""Typed errors for catalog and selection failures.

The first three errors below are import-time failures -- a catalog defect that
no invocation can work around. The last two are usage failures, and are the
ones ``main()`` catches to exit non-zero. Keeping them in one module lets
``main.py`` import every ``except`` clause from a single place.
"""

from __future__ import annotations


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
