"""
Properties 13 and 6a: no confessing FAIL, no ``except`` in ``execute()``, no
direct SDK access from a check.

Static, by AST, over every ``services/*/checks/sra_*.py``. Static because the
condition is about what a check *can* say, not about what it happened to say on
one scan: the 14 confessing GuardDuty modules produced **zero** rows in the
2026-09-12 baseline, purely because GuardDuty was healthy that day. A run-time
test would have found nothing wrong with any of them.

**Why a confessing FAIL is the defect this whole feature exists to remove.**
FAIL means AWS was asked and the control is not in place. ERROR means the
question went unanswered. A row that says FAIL and "Unable to retrieve detector
details" is asserting the first while describing the second, and the dashboards
count it as a finding -- so somebody goes looking for a misconfiguration that was
never observed, and nobody learns that the control was not evaluated. 112 rows in
the baseline, 3.7% of the report.

**Why ``except`` inside ``execute()`` is forbidden outright**, not just when it
resolves to ``failed()``: after the client contract lands, a client returns
normally for every ``ClientError`` and every ``BotoCoreError``. The only thing
left for a check to catch is a programming defect, and the orchestrator's guard
is what should report that -- loudly, once, with a traceback. A check that
catches one is hiding it.

All three properties are now asserted unconditionally over all 158 check
modules. While the migration ran they were keyed to a per-module ledger, which is
gone; see the note where it used to be declared.

Validates: Requirements 2.8, 4.7, 4.11, 7.5b, 7.6.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

import pytest

import sraverify.services

_SERVICES_ROOT: Path = Path(sraverify.services.__file__).resolve().parent


def _check_modules() -> list[Path]:
    """Return every check module in the tree, sorted.

    Returns:
        Absolute paths to ``services/*/checks/sra_*.py``, in a stable order.
    """
    return sorted(
        path
        for path in _SERVICES_ROOT.rglob("checks/sra_*.py")
        if "__pycache__" not in path.parts
    )


#: Snapshotted at import so collection is stable and a failure names its module.
_CHECK_MODULES: list[Path] = _check_modules()


def _module_key(path: Path) -> str:
    """Return the ``<service>/<file>.py`` key used by the ledger and the test IDs.

    Args:
        path: A check module path.

    Returns:
        e.g. ``"guardduty/sra_guardduty_02.py"``.
    """
    return f"{path.parent.parent.name}/{path.name}"


def _module_ids() -> list[str]:
    """Return the parametrize IDs, one per check module.

    Returns:
        The module keys, so a failure names the offending check without the
        reader opening the assertion.
    """
    return [_module_key(path) for path in _CHECK_MODULES]


# --------------------------------------------------------------------------- #
# The ledger
#
# Keyed by module name rather than by service, and split by property, because a
# module can hold one defect and not the other: cloudtrail_08 has both an
# ``except`` inside ``execute()`` and a ``failed()`` interpolating the caught
# exception, while config_01 has only the confessing wording.
# --------------------------------------------------------------------------- #

#: The three ledgers that used to live here are gone.
#:
#: They named, by module, every check that violated one of this file's three
#: properties before the client-error-contract migration: 28 modules with a
#: confessing ``failed()``, 7 with an ``except`` inside ``execute()``, and 1
#: reaching the SDK directly. Each entry carried ``pytest.mark.xfail(strict=True)``,
#: so a module that was migrated but still listed produced an XPASS and failed the
#: run -- the ledger could not outlive the work. All three are empty and deleted,
#: and every one of the 158 check modules is now asserted unconditionally.
def _module_params() -> list[Any]:
    """Return parametrize values over every check module, unmarked.

    Args:
        None.

    Returns:
        A list of ``pytest.param`` values, one per check module.
    """
    return [
        pytest.param(path, id=_module_key(path)) for path in _CHECK_MODULES
    ]


# --------------------------------------------------------------------------- #
# Non-vacuity
# --------------------------------------------------------------------------- #


def test_the_catalog_of_check_modules_is_complete() -> None:
    """158 check modules, so an enumeration bug cannot read as a pass."""
    assert len(_CHECK_MODULES) >= 150, (
        f"found {len(_CHECK_MODULES)} check modules; the catalog holds 158 and "
        f"the walk is broken"
    )


# --------------------------------------------------------------------------- #
# Property 13 -- no confessing failed()
# --------------------------------------------------------------------------- #

#: Requirement 4.7's prose patterns, case-insensitively. These are wordings that
#: *admit* the row is reporting an inability to determine, which is precisely
#: what FAIL must not be used for.
_CONFESSING_PATTERNS: tuple[str, ...] = (
    r"failed to (retrieve|get|fetch|access|determine|check)",
    r"unable to (retrieve|get|fetch|access|determine|check)",
    r"could not (be )?(determine|determined|retrieve|retrieved|access|accessed)",
    r"error (retrieving|getting|fetching|checking|accessing|determining)",
)

_CONFESSING_RE = re.compile("|".join(_CONFESSING_PATTERNS), re.IGNORECASE)


def _parse(path: Path) -> ast.Module:
    """Parse a check module.

    Args:
        path: The module to parse.

    Returns:
        The parsed module.
    """
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _string_literal_parts(node: ast.AST) -> list[str]:
    """Return the literal string portions of a ``str`` or f-string node.

    An f-string's interpolations are excluded, because their runtime value is
    unknowable statically; the literal text around them is what carries the
    confessing wording.

    Args:
        node: The ``actual_value`` argument node.

    Returns:
        Every literal string fragment.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.JoinedStr):
        return [
            value.value
            for value in node.values
            if isinstance(value, ast.Constant) and isinstance(value.value, str)
        ]
    return []


def _interpolated_names(node: ast.AST) -> set[str]:
    """Return every name interpolated into an f-string.

    Args:
        node: The ``actual_value`` argument node.

    Returns:
        The set of ``Name`` identifiers appearing inside ``FormattedValue``
        slots.
    """
    names: set[str] = set()
    if not isinstance(node, ast.JoinedStr):
        return names
    for value in node.values:
        if isinstance(value, ast.FormattedValue):
            for sub in ast.walk(value):
                if isinstance(sub, ast.Name):
                    names.add(sub.id)
    return names


def _caught_exception_names(tree: ast.Module) -> set[str]:
    """Return every name bound by an ``except ... as`` clause in the module.

    Args:
        tree: A parsed check module.

    Returns:
        The bound names.
    """
    return {
        handler.name
        for handler in ast.walk(tree)
        if isinstance(handler, ast.ExceptHandler) and handler.name
    }


def _failed_calls(tree: ast.Module) -> list[ast.Call]:
    """Return every ``self.failed(...)`` call in the module.

    Args:
        tree: A parsed check module.

    Returns:
        The matching ``Call`` nodes.
    """
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "failed"
    ]


@pytest.mark.parametrize(
    "path", _module_params(), ids=None
)
def test_no_failed_call_confesses_an_undetermined_state(path: Path) -> None:
    """Property 13: a FAIL row's wording never admits it could not determine.

    Two clauses, both from Requirement 4.7:

    * the ``actual_value`` literal text matching one of the prose patterns, and
    * the ``actual_value`` interpolating a name bound by ``except ... as``, which
      is how an exception's own text reaches a FAIL cell.

    The second clause is why the cloudtrail timestamp trio is in scope even
    though their wording reads confidently: ``f"... {e}"`` puts a ``ValueError``
    into a cell that claims the control is absent.
    """
    tree = _parse(path)
    caught = _caught_exception_names(tree)
    offenders: list[str] = []

    for call in _failed_calls(tree):
        for keyword in call.keywords:
            if keyword.arg != "actual_value":
                continue

            for fragment in _string_literal_parts(keyword.value):
                match = _CONFESSING_RE.search(fragment)
                if match:
                    offenders.append(
                        f"L{call.lineno}: confessing wording "
                        f"{match.group(0)!r} in {fragment[:60]!r}"
                    )

            leaked = _interpolated_names(keyword.value) & caught
            if leaked:
                offenders.append(
                    f"L{call.lineno}: interpolates the caught exception "
                    f"{sorted(leaked)} into a FAIL"
                )

    assert offenders == [], (
        f"{_module_key(path)} reports an undetermined state as FAIL:\n  "
        + "\n  ".join(offenders)
        + "\nA FAIL asserts AWS said the control is absent. Where the scan could "
        "not tell, yield error() with the operation and code, or -- if the code is "
        "semantic for its operation -- a discriminated failed() naming the "
        "condition AWS reported."
    )


# --------------------------------------------------------------------------- #
# Property 6a -- no except inside execute(), no direct SDK access
# --------------------------------------------------------------------------- #


def _execute_functions(tree: ast.Module) -> list[ast.FunctionDef]:
    """Return every function named ``execute`` in the module.

    Args:
        tree: A parsed check module.

    Returns:
        The matching function definitions, sync and async.
    """
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "execute"
    ]


def _handler_label(handler: ast.ExceptHandler) -> str:
    """Render an ``except`` clause's type for a failure message.

    Args:
        handler: The handler node.

    Returns:
        A readable label, ``"bare"`` for a bare ``except:``.
    """
    if handler.type is None:
        return "bare except"
    return f"except {ast.unparse(handler.type)}"


@pytest.mark.parametrize(
    "path", _module_params(), ids=None
)
def test_no_check_catches_an_exception_inside_execute(path: Path) -> None:
    """Property 6a: ``execute()`` contains no ``try``/``except`` at all.

    Not "no ``except`` that resolves to ``failed()``" -- none. Once no client
    raises for an AWS outcome, the only exception a check can catch is a
    programming defect in some tier, and the orchestrator's guard is what should
    report that: one synthetic ERROR row and a traceback, rather than a plausible
    row and silence.
    """
    offenders: list[str] = []
    for function in _execute_functions(_parse(path)):
        for node in ast.walk(function):
            if isinstance(node, ast.Try):
                handlers = ", ".join(_handler_label(h) for h in node.handlers)
                offenders.append(f"L{node.lineno}: {handlers}")

    assert offenders == [], (
        f"{_module_key(path)} catches inside execute():\n  "
        + "\n  ".join(offenders)
        + "\nAfter the client contract a client returns normally for every "
        "ClientError and BotoCoreError, so anything reaching here is a "
        "programming defect and belongs to the orchestrator's guard."
    )


#: The attribute chains that mean "this check went round the client layer".
_SDK_CHAINS: tuple[str, ...] = (
    "session.client",
    "boto3.client",
    "boto3.Session",
    "_ctx.get_client",
)


def _attribute_chain(node: ast.Attribute) -> str:
    """Render an attribute access as a dotted string, best effort.

    Args:
        node: The attribute node.

    Returns:
        e.g. ``"self.session.client"``.
    """
    parts: list[str] = []
    current: ast.AST = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


@pytest.mark.parametrize(
    "path", _module_params(), ids=None
)
def test_no_check_reaches_the_sdk_directly(path: Path) -> None:
    """Property 6a: every AWS call goes through a ``<Service>Client``.

    A call made outside a client wrapper is outside the transport guard and
    outside the error result model, so its failure has no defined shape and reaches
    the check body as a raised exception -- which is how ``accessanalyzer_02``
    ended up with a bare ``except`` resolving to ``failed()``.
    """
    offenders = [
        f"L{node.lineno}: {chain}"
        for node in ast.walk(_parse(path))
        if isinstance(node, ast.Attribute)
        and (chain := _attribute_chain(node)).endswith(_SDK_CHAINS)
    ]

    assert offenders == [], (
        f"{_module_key(path)} reaches the SDK directly:\n  "
        + "\n  ".join(offenders)
        + "\nRoute the call through the service's <Service>Client so it returns "
        "and returns the error result shape."
    )


# --------------------------------------------------------------------------- #
# The patterns themselves
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "wording,should_match",
    [
        ("Failed to retrieve Macie organization configuration", True),
        ("Unable to retrieve detector details", True),
        ("exists but status could not be determined", True),
        ("but the bucket owner could not be determined", True),
        ("Error retrieving trail status", True),
        ("unable to CHECK the configuration", True),
        ("COULD NOT BE RETRIEVED", True),
        # Legitimate FAIL wordings that must not be caught. Each is a real
        # ActualValue from the tree, and each states an observed absence.
        ("No GuardDuty detector in this Region", False),
        ("Audit account 111122223333 is not set up as query access subscriber", False),
        ("No public access block configuration found", False),
        ("Macie is not enabled in this Region", False),
        ("Inspector state status: NOT_ENABLED", False),
        ("Trail is not multi-region", False),
        # Near misses, to pin the patterns' edges.
        ("Retrieved the configuration successfully", False),
        ("The check determined that logging is disabled", False),
        ("Access is denied by the bucket policy", False),
    ],
)
def test_the_confessing_patterns_match_what_they_should(
    wording: str, should_match: bool
) -> None:
    """The detector is tested, not just used.

    A pattern set this consequential -- it gates 28 modules and the gate's
    totals -- should not be trusted on inspection. The negative cases matter
    more than the positives: an over-broad pattern would force a genuine
    "the control is absent" FAIL to be reworded into something vaguer, which is
    the opposite of the intent.
    """
    assert bool(_CONFESSING_RE.search(wording)) is should_match, (
        f"{wording!r}: expected match={should_match}"
    )
