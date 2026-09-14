"""The check registry -- the one authoritative catalog of checks.

``SecurityCheck.__init_subclass__`` is the only writer: importing a check
module executes its class body, which fires the hook, which calls
:func:`register`. There is no decorator to apply and no dictionary to
hand-maintain, so a check file's presence on disk is the whole of its
registration.

The registry is written once, at import time, and read-only thereafter.
:func:`all_checks` is the only read path and hands back a mapping proxy over a
sorted copy, so a caller can neither mutate the catalog nor observe it in a
non-deterministic order.

To keep the runtime dependency edge running one way -- from ``core/check.py``
into this module -- ``SecurityCheck`` is imported here for annotations only,
under ``TYPE_CHECKING``.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING, Mapping

from sraverify.core.errors import DuplicateCheckIdError

if TYPE_CHECKING:
    from sraverify.core.check import SecurityCheck


_REGISTRY: dict[str, type["SecurityCheck"]] = {}


def register(check_id: str, cls: type["SecurityCheck"]) -> None:
    """Add *cls* to the catalog under *check_id*.

    Idempotent for the same class object, so a module imported twice under the
    same name stays harmless. A *different* class claiming an ID that is
    already present is a catalog defect and raises.

    Args:
        check_id: The check ID to register under, taken from the class's
            validated ``meta.check_id``.
        cls: The check class claiming that ID.

    Raises:
        DuplicateCheckIdError: A different class already holds *check_id*.
            The error carries the check ID and both classes.
    """
    existing = _REGISTRY.get(check_id)
    if existing is not None and existing is not cls:
        raise DuplicateCheckIdError(check_id, existing, cls)
    _REGISTRY[check_id] = cls


def all_checks() -> Mapping[str, type["SecurityCheck"]]:
    """Return a read-only view of the catalog, sorted by check ID.

    The proxy wraps a copy, so a later registration is not visible through a
    view already handed out, and a caller cannot reach the live registry.
    Ascending lexicographic key order makes ``--list-checks`` output and
    duplicate diagnostics reproducible.

    Returns:
        A read-only mapping of check ID to check class, ordered by ascending
        lexicographic check ID.
    """
    return MappingProxyType(dict(sorted(_REGISTRY.items())))
