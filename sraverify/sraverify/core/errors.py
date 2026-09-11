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
    """The filter combination matched zero checks."""
