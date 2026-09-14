"""Property-based test for the unknown-check-ID usage error (task 11.7).

This module implements **Property 17: unknown check ID exits without output**:

    ``_select(check_id=x)`` for ``x`` not in the registry raises
    ``UnknownCheckError``; the CLI exits 2 and creates no file.

**Validates: Requirements 9.4, 9.7, 9.14**

Why this property is worth pinning
----------------------------------

The pre-change CLI answered a mistyped ``--check`` by logging, returning an
empty finding list, writing a header-only CSV, and exiting 0. In the CodeBuild
fan-out that is indistinguishable from a member account that genuinely produced
nothing: the pandas consolidation step reads a valid CSV, finds zero rows, and
the account silently disappears from the report. Three separate observable
behaviors have to hold together for that failure mode to stay closed, and this
module asserts all three:

  * ``_select`` **raises** rather than returning an empty mapping;
  * the CLI **exits 2**, argparse's own convention for a usage error, which is
    also what argparse returns for a bad ``--account-type``, so the surface is
    internally consistent;
  * **no file exists** at the resolved output path afterwards. Asserted for
    both an explicit ``--output`` and the timestamped default, because the two
    resolve down different branches in ``main()`` and only the explicit one has
    a path a test can name in advance.

Three things about the shape of the tests
-----------------------------------------

**The suggestion ordering is asserted, not just the exception type.** Criterion
9.4 requires at most three registry keys at similarity 0.6 or better, ordered
most similar first *with ties broken by ascending check ID*. That last clause
is why ``main._near_misses`` exists at all instead of a one-line call to
``difflib.get_close_matches``: ``get_close_matches`` selects with
``heapq.nlargest`` over ``(ratio, key)`` tuples, so equally-similar keys come
back in **descending** key order. Over the synthetic catalog below,
``get_close_matches("SRA-GUARDDUTY-0", ...)`` returns ``05, 04, 03`` where 9.4
requires ``01, 02, 03``. Two fixtures pin exactly that, so a future
simplification back to the stdlib helper fails here rather than shipping a
"did you mean" list that points at the wrong end of a service's checks.

**The AWS boundary is asserted, not merely avoided.** ``main()`` constructs a
real ``SRAVerify``, which builds a boto3 ``Session``, and it calls
``print_banner``, which calls ``sts:GetCallerIdentity``. On the exit-2 path
neither should reach AWS: ``_select`` raises while ``print_banner``'s arguments
are still being evaluated, so the banner never runs. Rather than trusting that,
these tests install a session whose ``client()`` records the call and refuses,
and assert it was never called -- which holds even if the banner *did* run, and
so verifies the absence of an AWS call rather than assuming it.

**The catalog is replaced, not sampled.** ``core.registry._REGISTRY`` is
module-level process state. Every test here runs inside ``isolated_registry``,
which snapshots it, empties it, and restores it afterwards, and installs seven
synthetic entries in its place. Two reasons: the real catalog is empty during Phase 2 and full from
Phase 3 on, so a test reading it would assert different things at different
points in the change; and fixed keys are what make the exact suggestion lists
above assertable at all.
"""
from __future__ import annotations

import difflib
import importlib
import importlib.machinery
import sys
import types
from pathlib import Path

import pytest
from hypothesis import HealthCheck, event, given, settings
from hypothesis import strategies as st

from sraverify.core import registry
from sraverify.core.enums import AccountType, Severity
from sraverify.core.errors import SRAVerifyError, UnknownCheckError
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.tests.property.strategies import check_ids


# --------------------------------------------------------------------------- #
# Import bootstrap
# --------------------------------------------------------------------------- #

def _ensure_main_importable() -> None:
    """Make ``import sraverify.main`` work during the Phase 2 / Phase 3 window.

    ``main.py`` imports ``sraverify.services`` for its registration side
    effect, and that import walks all 158 check modules. Until the last check
    body is migrated an unmigrated check raises ``CheckIdentityError`` at
    class-creation time, so the ``services`` package cannot be imported and
    neither can ``main``.

    Same shape as the root ``conftest.py`` bootstrap for the top-level package,
    and for the same reason: try the real import, and only if it fails install
    a body-less stub module under the name ``main.py`` needs to find in
    ``sys.modules``. The stub carries the real package directory as its
    ``__path__``, so an individual ``sraverify.services.<svc>.base`` import
    still resolves normally for any other test module in the session.

    Once Phase 3 is complete the ``try`` takes its first branch, the stub is
    never built, and this function is a no-op -- which is what keeps these
    tests running unchanged after the migration lands.
    """
    if "sraverify.main" in sys.modules:
        return
    try:
        importlib.import_module("sraverify.services")
    except Exception:
        sys.modules.pop("sraverify.services", None)
        services_dir = Path(registry.__file__).parent.parent / "services"
        stub = types.ModuleType("sraverify.services")
        stub.__doc__ = (
            "Stub for sraverify.services, installed by "
            "test_unknown_check_exit_property because the real package cannot "
            "be imported while check migration is in progress. Registers "
            "nothing; every test in this module installs its own catalog."
        )
        stub.__path__ = [str(services_dir)]
        spec = importlib.machinery.ModuleSpec(
            "sraverify.services", loader=None, is_package=True
        )
        spec.submodule_search_locations = stub.__path__  # type: ignore[assignment]
        stub.__spec__ = spec
        sys.modules["sraverify.services"] = stub


_ensure_main_importable()

from sraverify.main import (  # noqa: E402  (must follow the bootstrap above)
    DEFAULT_OUTPUT,
    SUGGESTION_CUTOFF,
    SUGGESTION_LIMIT,
    SRAVerify,
    _near_misses,
    main,
)


# --------------------------------------------------------------------------- #
# The synthetic catalog
# --------------------------------------------------------------------------- #

#: Seven keys chosen so the similarity landscape has the three shapes 9.4
#: distinguishes: a five-way tie (the GuardDuty block), a strict winner
#: followed by a tie (``SRA-GUARDDUTY-01`` against the rest of that block for a
#: query missing the trailing ``Y``), and keys far enough away to fall below
#: the 0.6 cutoff. Five GuardDuty entries rather than three so the
#: three-suggestion cap is exercised by a genuine surplus of candidates.
_CATALOG: tuple[tuple[str, str, AccountType], ...] = (
    ("SRA-GUARDDUTY-01", "GuardDuty", AccountType.APPLICATION),
    ("SRA-GUARDDUTY-02", "GuardDuty", AccountType.APPLICATION),
    ("SRA-GUARDDUTY-03", "GuardDuty", AccountType.AUDIT),
    ("SRA-GUARDDUTY-04", "GuardDuty", AccountType.APPLICATION),
    ("SRA-GUARDDUTY-05", "GuardDuty", AccountType.MANAGEMENT),
    ("SRA-MACIE-01", "Macie", AccountType.APPLICATION),
    ("SRA-S3-01", "S3", AccountType.LOG_ARCHIVE),
)

#: Frozen for the strategy filter below, which runs at draw time and therefore
#: cannot depend on a function-scoped fixture having run.
_CATALOG_IDS = frozenset(check_id for check_id, _, _ in _CATALOG)


def _meta(check_id: str, service: str, account_type: AccountType) -> CheckMeta:
    """Build a real, fully-validated ``CheckMeta`` for a synthetic check.

    A real ``CheckMeta`` rather than a stand-in: ``_select`` reads
    ``meta.check_id``, ``meta.account_type``, and ``meta.service``, and the
    validation rules are what guarantee those are the types the selector
    expects. A hand-rolled namespace would let this module pass while the real
    selector met something else.

    Args:
        check_id: The check ID, which must satisfy the ``SRA-<SERVICE>-NN``
            format rule.
        service: The display name the service filter matches against.
        account_type: The account-type member the account-type filter matches
            against.

    Returns:
        A validated ``CheckMeta``.
    """
    return CheckMeta(
        check_id=check_id,
        title="Synthetic control used only by the selection tests",
        description="Synthetic metadata. This check has no execute() body.",
        check_logic="Declared for selection tests; never executed.",
        severity=Severity.HIGH,
        account_type=account_type,
        service=service,
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(text="Nothing to remediate; synthetic check."),
    )


def _check_class(check_id: str, service: str, account_type: AccountType) -> type:
    """Return a throwaway class carrying ``meta``, registered directly.

    Deliberately **not** a ``SecurityCheck`` subclass declared in a real
    ``sra_*.py`` file. ``_select`` reads ``cls.meta`` and nothing else, so a
    bare class with a real ``CheckMeta`` is a sufficient and honest stand-in,
    and registering it by hand keeps ``__init_subclass__``'s file-stem and
    class-name identity rules -- Requirement 4's business, tested in
    ``tests/unit/core/test_check_registration.py`` -- out of a selection test.

    Args:
        check_id: The ID to register under.
        service: The ``meta.service`` value.
        account_type: The ``meta.account_type`` value.

    Returns:
        A new class whose only attribute is ``meta``.
    """
    return type(
        check_id.replace("-", "_"),
        (),
        {"meta": _meta(check_id, service, account_type)},
    )


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture
def isolated_registry():
    """Snapshot ``_REGISTRY``, empty it for the test, and restore it afterwards.

    ``_REGISTRY`` is module-level state shared by the whole process. The
    snapshot is a shallow copy, and restoration mutates the original dict in
    place rather than rebinding the name, so a module that captured a reference
    to it still sees the restored contents.

    Emptying it here rather than only in ``catalog`` means the exact suggestion
    lists asserted below never depend on whether some earlier module in the
    session left the 158 real checks resident.
    """
    saved = dict(registry._REGISTRY)
    registry._REGISTRY.clear()
    try:
        yield registry._REGISTRY
    finally:
        registry._REGISTRY.clear()
        registry._REGISTRY.update(saved)


@pytest.fixture
def catalog(isolated_registry) -> list[str]:
    """Replace the catalog with ``_CATALOG`` and return its keys, sorted.

    Clearing first is the point: the real registry is empty during Phase 2 and
    holds 158 checks from Phase 3 on, and the exact suggestion lists asserted
    below must not depend on which of those two it is.
    """
    isolated_registry.clear()
    for check_id, service, account_type in _CATALOG:
        registry.register(check_id, _check_class(check_id, service, account_type))
    return list(registry.all_checks())


class _RefusingSession:
    """A boto3 ``Session`` stand-in that records and refuses every client build.

    ``region_name`` is a real attribute because ``main()`` reads
    ``sra.session.region_name`` while evaluating ``print_banner``'s arguments,
    which happens before ``_select`` raises.

    ``client()`` records the call *and then* raises, so the recording survives
    a caller that swallows the exception -- which ``print_banner`` does, in a
    bare ``except Exception``. Asserting ``client_calls == []`` therefore
    detects an attempted AWS call whether or not anyone noticed it failing.
    """

    region_name = "us-east-1"

    def __init__(self) -> None:
        self.client_calls: list[tuple] = []

    def client(self, *args, **kwargs):
        self.client_calls.append((args, kwargs))
        raise AssertionError(
            "the exit-2 usage-error path must build no AWS client; "
            f"asked for {args!r} {kwargs!r}"
        )


@pytest.fixture
def refusing_session(monkeypatch) -> _RefusingSession:
    """Install a ``_RefusingSession`` in place of the real session builder.

    Patches the name ``get_session`` in ``sraverify.main``'s namespace, which
    is where ``SRAVerify.__init__`` looks it up, so no credential resolution,
    no profile lookup, and no ``assume_role`` happens even before the question
    of an API call arises.
    """
    session = _RefusingSession()
    monkeypatch.setattr("sraverify.main.get_session", lambda **kwargs: session)
    return session


# --------------------------------------------------------------------------- #
# Strategies and the reference implementation of 9.4
# --------------------------------------------------------------------------- #

@st.composite
def _mutated_catalog_ids(draw: st.DrawFn) -> str:
    """Draw a real catalog key with one small typo applied.

    This is the source that makes the suggestion clauses of 9.4 non-vacuous.
    ``check_ids()`` draws service tokens from the whole of ``A``-``Z``, so it
    essentially never lands within 0.6 of ``SRA-GUARDDUTY-01`` and every
    ordering assertion would be checked against an empty list. A one-character
    edit of a real key is both the mistake an operator actually makes and the
    input that produces a crowded suggestion list.

    Five edits, each a real typo class: a different two-digit suffix, a deleted
    character, a substituted character, two adjacent characters transposed, and
    the whole ID lower-cased -- which is unknown precisely because 9.4 matches
    case-sensitively.

    Args:
        draw: Supplied by ``st.composite``.

    Returns:
        A mutated check ID, which the filter in ``unknown_check_ids`` may still
        reject if the mutation happened to produce another real key.
    """
    key = draw(st.sampled_from(sorted(_CATALOG_IDS)))
    kind = draw(
        st.sampled_from(
            ["renumber", "delete", "substitute", "transpose", "lower"]
        )
    )
    if kind == "renumber":
        number = draw(st.integers(min_value=0, max_value=99))
        return f"{key[:-2]}{number:02d}"
    if kind == "delete":
        index = draw(st.integers(min_value=0, max_value=len(key) - 1))
        return key[:index] + key[index + 1:]
    if kind == "substitute":
        index = draw(st.integers(min_value=0, max_value=len(key) - 1))
        replacement = draw(
            st.sampled_from("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
        )
        return key[:index] + replacement + key[index + 1:]
    if kind == "transpose":
        index = draw(st.integers(min_value=0, max_value=len(key) - 2))
        return (
            key[:index] + key[index + 1] + key[index] + key[index + 2:]
        )
    return key.lower()


def unknown_check_ids() -> st.SearchStrategy[str]:
    """Return a strategy for values absent from ``_CATALOG``.

    Three sources, drawn together on purpose:

      * ``_mutated_catalog_ids()`` -- a real key with one typo, which is what
        lands close enough to produce suggestions and so is the only source
        that exercises 9.4's ordering and cap clauses;
      * ``check_ids()`` -- well-formed ``SRA-<SERVICE>-NN`` strings naming
        services that do not exist, which is the far side of the same mistake;
      * arbitrary text -- the rest of the input space, including the empty
        string. ``_select``'s guard is ``check_id is not None``, so ``--check=``
        reaches the registry lookup as ``""`` rather than being treated as "no
        filter supplied".

    The filter is against the module-level ``_CATALOG_IDS`` rather than the
    live registry, because a strategy is evaluated at draw time and must not
    depend on a fixture. It is also what makes the mutation source safe: an
    edit that happens to produce another real key is discarded rather than
    asserted to be unknown.

    Returns:
        A strategy producing strings that are not registry keys.
    """
    return st.one_of(
        _mutated_catalog_ids(), check_ids(), st.text(max_size=24)
    ).filter(lambda value: value not in _CATALOG_IDS)


def _reference_near_misses(check_id: str, keys: list[str]) -> list[str]:
    """Criterion 9.4's suggestion list, computed the obvious way.

    An independent restatement of the rule rather than a copy of the
    implementation: score every key, keep those at or above the cutoff, sort by
    descending similarity with ascending check ID inside a tie, take the first
    three. ``main._near_misses`` reaches the same answer through difflib's
    ``real_quick_ratio``/``quick_ratio`` short-circuits, which are upper bounds
    on ``ratio`` and so can only skip keys that would have failed the cutoff
    anyway. If those short-circuits are ever misapplied -- compared the wrong
    way round, say -- this reference disagrees and the property fails.

    Args:
        check_id: The unmatched value.
        keys: The registry keys to score against.

    Returns:
        Up to ``SUGGESTION_LIMIT`` keys, possibly empty.
    """
    matcher = difflib.SequenceMatcher()
    matcher.set_seq2(check_id)
    scored = []
    for key in keys:
        matcher.set_seq1(key)
        ratio = matcher.ratio()
        if ratio >= SUGGESTION_CUTOFF:
            scored.append((key, ratio))
    scored.sort(key=lambda pair: (-pair[1], pair[0]))
    return [key for key, _ in scored[:SUGGESTION_LIMIT]]


def _ratio(key: str, check_id: str) -> float:
    """The difflib similarity of *key* to *check_id*, on difflib's 0-to-1 scale."""
    matcher = difflib.SequenceMatcher()
    matcher.set_seq2(check_id)
    matcher.set_seq1(key)
    return matcher.ratio()


# --------------------------------------------------------------------------- #
# Property 17, first half: _select raises (Requirement 9.4)
# --------------------------------------------------------------------------- #

@given(unknown=unknown_check_ids())
@settings(
    # `catalog` is function-scoped, so hypothesis reuses one installed catalog
    # across the draws of a single test. That is exactly what is wanted here:
    # the catalog is a fixed constant, the fixture only puts it in place, and
    # nothing in the test mutates it -- `_select` is a pure read.
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_select_raises_unknown_check_error_for_any_unregistered_id(
    unknown: str, catalog: list[str], refusing_session: _RefusingSession
) -> None:
    """Property 17: an ID outside the registry reaches ``UnknownCheckError``.

    ``account_type`` is left at ``'all'`` and ``service`` at ``None``, so the
    only filter in play is the check ID: an unknown ID must produce
    ``UnknownCheckError`` and never ``NoChecksSelectedError``, which is the
    error for a *known* ID that contradicts another filter.

    Validates: Requirements 9.4
    """
    sra = SRAVerify()

    with pytest.raises(UnknownCheckError) as excinfo:
        sra._select(check_id=unknown)

    # The unmatched value is carried verbatim -- not stripped, not upper-cased,
    # not normalized. 9.4 matches exactly and case-sensitively, so the operator
    # has to be shown the string they actually supplied.
    assert excinfo.value.check_id == unknown, (
        f"UnknownCheckError carried {excinfo.value.check_id!r}, "
        f"not the supplied {unknown!r}"
    )
    assert unknown in str(excinfo.value), (
        f"the rendered message {str(excinfo.value)!r} does not name {unknown!r}"
    )

    # Selection is a pure read of cls.meta: no client, therefore no AWS call.
    assert refusing_session.client_calls == [], (
        f"_select built an AWS client: {refusing_session.client_calls!r}"
    )


@given(unknown=unknown_check_ids())
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_carried_suggestions_satisfy_criterion_9_4(
    unknown: str, catalog: list[str], refusing_session: _RefusingSession
) -> None:
    """Property 17: the suggestion list obeys every clause of criterion 9.4.

    Six clauses, asserted separately so a failure names which one broke: at
    most three; drawn from the registry; each at or above the cutoff; ordered
    by non-increasing similarity; ties broken by ascending check ID; and no
    eligible key excluded in favor of a less similar one.

    Validates: Requirements 9.4
    """
    sra = SRAVerify()

    with pytest.raises(UnknownCheckError) as excinfo:
        sra._select(check_id=unknown)
    suggestions = excinfo.value.suggestions

    # Recorded so `--hypothesis-show-statistics` shows how often the ordering
    # and cap clauses below had anything to order or cap. An empty list is a
    # legal answer, so without this the run could pass while never once
    # exercising them.
    event(f"suggestions: {len(suggestions)}")

    assert isinstance(suggestions, list), (
        f"suggestions is {type(suggestions).__name__}, not a list"
    )
    assert len(suggestions) <= SUGGESTION_LIMIT, (
        f"{len(suggestions)} suggestions for {unknown!r}, "
        f"maximum is {SUGGESTION_LIMIT}: {suggestions!r}"
    )
    assert len(set(suggestions)) == len(suggestions), (
        f"suggestions for {unknown!r} repeat a key: {suggestions!r}"
    )

    for suggestion in suggestions:
        assert suggestion in catalog, (
            f"suggested {suggestion!r} for {unknown!r}, which is not a "
            f"registry key"
        )
        assert _ratio(suggestion, unknown) >= SUGGESTION_CUTOFF, (
            f"suggested {suggestion!r} for {unknown!r} at similarity "
            f"{_ratio(suggestion, unknown):.4f}, below the "
            f"{SUGGESTION_CUTOFF} cutoff"
        )

    # Ordering: most similar first, ascending check ID inside a tie.
    for left, right in zip(suggestions, suggestions[1:]):
        left_ratio = _ratio(left, unknown)
        right_ratio = _ratio(right, unknown)
        assert left_ratio >= right_ratio, (
            f"suggestions for {unknown!r} are not most-similar-first: "
            f"{left!r} ({left_ratio:.4f}) before {right!r} "
            f"({right_ratio:.4f})"
        )
        if left_ratio == right_ratio:
            assert left < right, (
                f"a tie at similarity {left_ratio:.4f} for {unknown!r} is "
                f"broken descending: {left!r} before {right!r}"
            )

    # The best three, not merely three eligible ones.
    assert suggestions == _reference_near_misses(unknown, catalog), (
        f"suggestions for {unknown!r} were {suggestions!r}; criterion 9.4 "
        f"requires {_reference_near_misses(unknown, catalog)!r}"
    )

    assert refusing_session.client_calls == []


def test_the_cutoff_and_the_limit_are_the_declared_values() -> None:
    """The two numbers criterion 9.4 names are 0.6 and 3.

    Pinned literally, because every other assertion in this module reads them
    from ``main`` and so would follow a change to either without complaint.

    Validates: Requirements 9.4
    """
    assert SUGGESTION_CUTOFF == 0.6
    assert SUGGESTION_LIMIT == 3


def test_a_five_way_tie_is_broken_by_ascending_check_id(catalog) -> None:
    """The tie-break clause of 9.4, on the fixture that motivated the helper.

    ``SRA-GUARDDUTY-0`` is equally similar to all five GuardDuty keys, at
    0.9677. 9.4 requires the first three in ascending ID order.
    ``difflib.get_close_matches`` returns ``05, 04, 03`` here -- it selects
    with ``heapq.nlargest`` over ``(ratio, key)`` tuples, so a tie comes back
    in descending key order. That is the whole reason ``_near_misses`` scores
    the keys itself instead of delegating, and this is the assertion that
    catches a future simplification back to the stdlib helper.

    Validates: Requirements 9.4
    """
    ratios = {key: _ratio(key, "SRA-GUARDDUTY-0") for key in catalog}
    guardduty = [key for key in catalog if key.startswith("SRA-GUARDDUTY-")]
    # The tie is real, not an artifact of a particular difflib version.
    assert len(set(ratios[key] for key in guardduty)) == 1, (
        f"the fixture no longer produces a tie: {ratios!r}"
    )

    assert _near_misses("SRA-GUARDDUTY-0", catalog) == [
        "SRA-GUARDDUTY-01",
        "SRA-GUARDDUTY-02",
        "SRA-GUARDDUTY-03",
    ]


def test_a_strict_winner_precedes_a_tie_broken_ascending(catalog) -> None:
    """Both ordering clauses of 9.4 at once, on one query.

    ``SRA-GUARDDUT-01`` (the trailing ``Y`` dropped) scores 0.9677 against
    ``SRA-GUARDDUTY-01`` and 0.9032 against each of ``02`` through ``05``. So
    the strict winner must come first -- ordering by similarity -- and the
    remaining two slots must be filled from the tie in ascending ID order.
    A helper that sorted by ID alone would produce the same list here; the
    five-way-tie fixture above is what separates the two, and a helper that
    sorted by similarity alone would fail there. Neither fixture is redundant.

    Validates: Requirements 9.4
    """
    assert _near_misses("SRA-GUARDDUT-01", catalog) == [
        "SRA-GUARDDUTY-01",
        "SRA-GUARDDUTY-02",
        "SRA-GUARDDUTY-03",
    ]


def test_fewer_than_three_eligible_keys_yields_a_shorter_list(catalog) -> None:
    """The cap is a maximum, not a quota.

    ``SRA-MACIE-0`` reaches the cutoff against exactly two keys:
    ``SRA-MACIE-01`` at 0.9565 and ``SRA-S3-01`` at exactly 0.6. The second is
    the cutoff boundary, included because 9.4 says "at least 0.6" -- a helper
    using ``>`` would drop it. Padding the list to three with the next-best
    key regardless of similarity would produce a "did you mean" line naming a
    GuardDuty check for a Macie typo.

    Validates: Requirements 9.4
    """
    assert _ratio("SRA-S3-01", "SRA-MACIE-0") == pytest.approx(SUGGESTION_CUTOFF)

    assert _near_misses("SRA-MACIE-0", catalog) == [
        "SRA-MACIE-01",
        "SRA-S3-01",
    ]


@pytest.mark.parametrize(
    "unknown",
    ["", "kubernetes", "zzzzzzzzzzzzzzzz", "   "],
    ids=["empty", "unrelated-word", "unrelated-letters", "whitespace"],
)
def test_nothing_near_enough_yields_an_empty_list_and_a_hintless_message(
    unknown: str, catalog: list[str], refusing_session: _RefusingSession
) -> None:
    """9.4's empty-list clause, and the message that goes with it.

    An empty suggestion list is a legitimate answer, and it must not render as
    a dangling ``Did you mean: ?``. ``UnknownCheckError`` suppresses the hint
    clause entirely when it has nothing to offer.

    Validates: Requirements 9.4
    """
    sra = SRAVerify()

    with pytest.raises(UnknownCheckError) as excinfo:
        sra._select(check_id=unknown)

    assert excinfo.value.suggestions == []
    assert "Did you mean" not in str(excinfo.value), (
        f"a hintless error still rendered a hint: {str(excinfo.value)!r}"
    )
    assert refusing_session.client_calls == []


def test_unknown_check_error_is_an_sraverify_error(
    catalog, refusing_session: _RefusingSession
) -> None:
    """``main()``'s ``except`` clause leans on the shared base class.

    Validates: Requirements 9.4, 9.7
    """
    sra = SRAVerify()

    with pytest.raises(SRAVerifyError):
        sra._select(check_id="SRA-GUARDDUTY-99")


def test_a_registered_id_does_not_raise(
    catalog, refusing_session: _RefusingSession
) -> None:
    """The property is not vacuous: a real ID still selects.

    Without this, a ``_select`` that raised ``UnknownCheckError``
    unconditionally would satisfy every other assertion in this module.

    Validates: Requirements 9.4
    """
    sra = SRAVerify()

    selected = sra._select(check_id="SRA-GUARDDUTY-01")

    assert list(selected) == ["SRA-GUARDDUTY-01"]
    assert refusing_session.client_calls == []


# --------------------------------------------------------------------------- #
# Property 17, second half: the CLI exits 2 and writes nothing
# (Requirements 9.7, 9.14)
# --------------------------------------------------------------------------- #

@given(unknown=unknown_check_ids())
@settings(
    # tmp_path, monkeypatch, catalog and refusing_session are all
    # function-scoped, so hypothesis reuses one of each across the draws of a
    # single test. Harmless and in fact useful here: the assertion is that the
    # directory stays empty, so a file created by an earlier draw is caught by
    # a later one too.
    suppress_health_check=[HealthCheck.function_scoped_fixture],
    deadline=None,
)
def test_the_cli_exits_2_and_creates_no_file_for_any_unknown_id(
    unknown: str,
    catalog: list[str],
    refusing_session: _RefusingSession,
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    """Property 17: an unknown ``--check`` exits 2 with nothing written.

    The value is passed as ``--check=<value>`` rather than as two arguments, so
    a drawn string beginning with ``-`` reaches ``_select`` as a value instead
    of being parsed as an unknown option -- which would also exit 2, and for
    the wrong reason, making the assertion pass vacuously.

    ``--output`` is explicit and inside ``tmp_path``, which is the only path
    this test may create anything at. Its absence afterwards is the whole point
    of 9.14: the pre-change CLI wrote a header-only CSV here and exited 0.

    Validates: Requirements 9.7, 9.14
    """
    output_file = tmp_path / "findings.csv"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sraverify",
            f"--check={unknown}",
            "--output",
            str(output_file),
            # Supplied so region resolution is never even a possibility; the
            # scan is not reached, but nothing about that should depend on a
            # lazy ec2:DescribeRegions call being skipped by luck.
            "--regions",
            "us-east-1",
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        main()

    assert excinfo.value.code == 2, (
        f"--check={unknown!r} exited {excinfo.value.code!r}, expected 2"
    )

    # No file at the resolved output path, and none anywhere else under
    # tmp_path either -- the CLI must not have synthesized a neighbouring name.
    assert not output_file.exists(), (
        f"the exit-2 path created {output_file}"
    )
    assert list(tmp_path.iterdir()) == [], (
        f"the exit-2 path created {[p.name for p in tmp_path.iterdir()]} "
        f"under {tmp_path}"
    )

    # No AWS client was built, so no API call was attempted. `_select` raises
    # while print_banner's arguments are still being evaluated, which is also
    # why the banner text below is absent.
    assert refusing_session.client_calls == [], (
        f"the exit-2 path built an AWS client: {refusing_session.client_calls!r}"
    )

    # Nothing on stdout: no banner, and above all no scan summary. The summary
    # is the operator's evidence that a usable report exists, so it must not
    # appear when none does. The error itself goes to the shared logger, which
    # writes to stderr.
    out = capsys.readouterr().out
    assert "Scan complete" not in out, (
        f"the exit-2 path printed a scan summary: {out!r}"
    )
    assert "the security reference architecture verifier tool" not in out, (
        f"the exit-2 path printed the banner: {out!r}"
    )


def test_the_cli_creates_no_file_at_the_timestamped_default_path(
    catalog: list[str],
    refusing_session: _RefusingSession,
    tmp_path: Path,
    monkeypatch,
) -> None:
    """9.14 on the default output path, which the test cannot name in advance.

    With ``--output`` omitted, ``main()`` injects a ``_YYYYmmdd_HHMMSS`` stamp
    into ``sraverify_findings.csv``, so there is no single path to assert the
    absence of. Running with the working directory moved into ``tmp_path``
    turns it into an assertion that the directory is still empty, which covers
    every name the stamp could have produced -- and keeps the run from
    depositing a stray CSV in the repository if it ever regresses.

    The two branches are worth separating: the explicit-path test above
    exercises the branch that leaves ``args.output`` alone, and this one
    exercises the branch that rewrites it. A regression that created the file
    while resolving the stamp would only show up here.

    Validates: Requirements 9.7, 9.14
    """
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys, "argv", ["sraverify", "--check=SRA-GUARDDUTY-99", "--regions", "us-east-1"]
    )

    with pytest.raises(SystemExit) as excinfo:
        main()

    assert excinfo.value.code == 2
    assert list(tmp_path.iterdir()) == [], (
        f"the exit-2 path created {[p.name for p in tmp_path.iterdir()]} in "
        f"the working directory; the default output base name is "
        f"{DEFAULT_OUTPUT}"
    )
    assert refusing_session.client_calls == []


def test_the_exit_status_is_an_integer_2_not_a_message(
    catalog: list[str],
    refusing_session: _RefusingSession,
    tmp_path: Path,
    monkeypatch,
) -> None:
    """``sys.exit(2)`` and not ``sys.exit("...")``.

    ``SystemExit.code`` is whatever was passed, and a string argument makes the
    process exit 1 while printing that string to stderr. The CodeBuild fan-out
    distinguishes 1 (the scan ran, the write failed) from 2 (the filters were
    unusable), so the difference is observable and worth pinning as a type.

    Validates: Requirements 9.7
    """
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sraverify",
            "--check=SRA-GUARDDUTY-99",
            "--output",
            str(tmp_path / "findings.csv"),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        main()

    assert isinstance(excinfo.value.code, int)
    assert excinfo.value.code == 2
    assert not (tmp_path / "findings.csv").exists()
