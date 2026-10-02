"""
The scan Region rule: the one place that decides which Region, and so which
AWS partition, a scan addresses.

``resolve_scan_region`` is a pure function. It issues no AWS call, reads no
file, builds no client, and never calls ``ScanContext.get_enabled_regions()``.
Three callers apply it to the same inputs: ``SRAVerify`` (before the banner and
before ``run_checks`` builds a context), ``get_session`` (before
``sts:AssumeRole``), and ``ScanContext.__init__`` (to store ``ctx.scan_region``).

It lives in its own module because ``core/session.py`` needs it before a
``ScanContext`` exists, and it imports only ``core.errors`` so the import graph
stays one-way.
"""
from __future__ import annotations

from collections.abc import Sequence

from sraverify.core.errors import PartitionUndeterminedError


def _usable(value: object) -> bool:
    """Whether ``value`` is a usable Region string.

    A ``str`` that is non-blank and carries no leading or trailing whitespace.
    The value is not checked against botocore endpoint data: an unknown name
    resolves to the ``aws`` partition, which is today's behaviour for a typo.
    """
    return isinstance(value, str) and bool(value.strip()) and value == value.strip()


def resolve_scan_region(regions: Sequence[str] | None, session: object) -> str:
    """Return the scan Region, or raise when it cannot be determined.

    Precedence, first match wins:

    a. ``regions[0]`` when ``regions`` is non-empty. A non-empty ``regions``
       whose first element is not a usable Region string raises
       ``PartitionUndeterminedError(bad_value=regions[0])`` and does **not**
       fall through: explicit input wins, and explicit input that is wrong is
       a usage error.
    b. ``session.region_name`` when ``regions`` is ``None`` or empty and the
       value is a usable Region string. A non-``str`` value (``None``, an
       unconfigured ``MagicMock`` attribute) or a padded one counts as absent.
       ``session.region_name`` already folds in boto3's own precedence
       (``Session(region_name=...)``, ``AWS_DEFAULT_REGION``, the profile's
       ``region =``), so nothing here re-reads the environment. boto3 does
       not read ``AWS_REGION`` into ``region_name``; it is deliberately not
       consulted here either, so the guard and the clients built from the
       same session can never disagree about the Region.
    c. Otherwise raise ``PartitionUndeterminedError()``.

    Args:
        regions: The explicit ``--regions`` list, or ``None``.
        session: The boto3 session (or any object with ``region_name``).

    Returns:
        The scan Region, exactly as held by ``regions`` or the session.

    Raises:
        PartitionUndeterminedError: ``reason == "invalid"`` for an unusable
            first ``regions`` value; ``reason == "absent"`` when neither
            candidate supplies a Region.
    """
    if regions:
        first = regions[0]
        if _usable(first):
            return first
        raise PartitionUndeterminedError(bad_value=first)

    session_region = getattr(session, "region_name", None)
    if _usable(session_region):
        return session_region

    raise PartitionUndeterminedError()
