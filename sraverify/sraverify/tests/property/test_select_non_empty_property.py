"""Property-based test for selection's non-empty guarantee (task 11.6).

This module implements **Property 16: ``_select`` never returns an empty
mapping**:

    ∀ ``account_type`` ∈ ``AccountType``, ∀ ``service`` in the service set:
    ``_select`` either returns a non-empty mapping whose every member matches
    the filters, or raises ``NoChecksSelectedError``. It never returns an empty
    mapping.

**Validates: Requirements 9.2, 9.5, 9.6**

Why the disjunction is the property
-----------------------------------

The failure this closes is not "selection returns the wrong checks", it is
"selection returns nothing and the scan looks clean". An empty mapping flows
straight through ``run_checks`` into a zero-row CSV and an exit code of 0, so a
mistyped ``--service GuardDuty2`` is indistinguishable from a fully compliant
account. Requirement 9.2 makes the empty result unrepresentable rather than
merely discouraged: the only two shapes ``_select`` can produce are a non-empty
mapping and a raise, and this property is the assertion that no third shape
exists for any filter combination.

The three filters interact, which is what makes this worth quantifying over
rather than spot-checking. ``--check`` **narrows** the intersection (9.6) rather
than replacing it, so a legal check ID paired with a contradicting account type
or service produces zero matches and must reach ``NoChecksSelectedError`` -- not
``UnknownCheckError``, because the ID is real, and not an empty mapping, because
that is the shape 9.2 forbids. Those two error paths are easy to conflate in
either direction, so ``test_a_registered_check_id_contradicting_a_filter_raises``
asserts the error *type* explicitly rather than settling for "something raised".

The service filter is drawn adversarially for the same reason: the design pins
full-value, ``str.lower()``-based matching with ``strip()`` applied to the
supplied value only, so the strategy includes case variants and padded values
(which must match) alongside prefixes, substrings, internally-respaced names,
and the empty string (which must not). ``"Alpha"`` matching ``"Alpha Service"``
would be a silently wider selection than the operator asked for; ``""`` matching
everything would be worse.

A synthetic catalog, not the real 158
-------------------------------------

Every test here runs against a small synthetic catalog installed over the
module-level ``_REGISTRY`` by ``_synthetic_catalog``, which snapshots and
restores it. Three reasons, in order of weight:

  * The property quantifies over "every account type and every service", and
    the assertions need to know which ``(account_type, service)`` pairs match
    *nothing* -- that is the half of the input space where the raise is the
    correct answer. Against the real catalog that set is a moving target; here
    it is derived from ``_SYNTHETIC``, a table declared literally below.
  * Task 11.6 lands in Phase 2, where the real catalog does not import at all
    (see ``_load_main``). A test that depended on the 158 could not run until
    task 15.
  * Without the snapshot-and-restore, synthetic entries would leak into the
    catalog for every later test module in the same pytest session.

The synthetic classes are created with ``type()`` in this module, whose file
stem does not begin with ``sra_``, so task 8.2's eligibility rule makes
``__init_subclass__`` return silently: they are neither validated for identity
nor registered. Registration is therefore explicit, via ``registry.register``.
``test_the_synthetic_catalog_is_installed_and_is_the_whole_catalog`` pins that
the installation actually took, since every assertion below is vacuous if the
catalog is not what this module thinks it is.

Importing ``main`` during Phase 2
---------------------------------

``main.py`` imports ``sraverify.services`` for its registration side effect, and
that import raises ``CheckIdentityError`` on the first unmigrated check until
Phase 3 completes. ``_load_main`` attempts the real import first and only falls
back to a stub ``sraverify.services`` in ``sys.modules``, removing the stub
again once ``main`` is loaded. So after Phase 3 this module exercises ``main``
imported exactly as production imports it, with no stub involved, and in the
meantime no stub is left behind for a sibling test module to trip over.
"""
from __future__ import annotations

import importlib
import sys
from types import MappingProxyType, ModuleType
from typing import Iterator, Optional

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sraverify.core import registry
from sraverify.core.check import SecurityCheck
from sraverify.core.enums import AccountType, Severity
from sraverify.core.errors import (
    NoChecksSelectedError,
    SRAVerifyError,
    UnknownCheckError,
)
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation


# ---------------------------------------------------------------------- #
# Importing main.py before Phase 3 has migrated the catalog.
# ---------------------------------------------------------------------- #


def _load_main() -> ModuleType:
    """Import and return ``sraverify.main``, tolerating an unmigrated catalog.

    The real import is attempted first and is the only path taken once Phase 3
    is complete, so this module ends up testing ``main`` exactly as production
    loads it -- registration side effect included -- rather than testing a
    permanently stubbed variant.

    The fallback covers Phase 2 only: ``import sraverify.services`` walks every
    check module, and an unmigrated check raises ``CheckIdentityError`` from
    ``__init_subclass__``. A stub module under that key satisfies ``main``'s
    side-effect import, and is removed immediately afterwards so a later
    ``import sraverify.services`` -- by a sibling test module, or by this
    process once the catalog imports again -- reaches the real package.

    Returns:
        The ``sraverify.main`` module.
    """
    already = sys.modules.get("sraverify.main")
    if already is not None:
        return already

    try:
        return importlib.import_module("sraverify.main")
    except Exception:
        # Deliberately broad. The Phase 2 failure is CheckIdentityError today
        # and could be MetadataError mid-migration, and neither is worth
        # enumerating here: if the retry below also fails, that exception
        # propagates and the module still fails to import loudly. The stub
        # bypasses discovery and nothing else, so it cannot mask a defect in
        # main.py itself.
        sys.modules.pop("sraverify.services", None)
        stub = ModuleType("sraverify.services")
        stub.__doc__ = (
            "Stub standing in for sraverify.services while the catalog is "
            "mid-migration. Registers nothing; the tests in this module "
            "install their own synthetic catalog."
        )
        # An empty __path__ keeps the stub a package, so an accidental
        # `sraverify.services.<anything>` import fails as ModuleNotFoundError
        # rather than as an AttributeError from a non-package parent.
        stub.__path__ = []  # type: ignore[attr-defined]
        sys.modules["sraverify.services"] = stub
        try:
            return importlib.import_module("sraverify.main")
        finally:
            sys.modules.pop("sraverify.services", None)


_main = _load_main()
SRAVerify = _main.SRAVerify


# ---------------------------------------------------------------------- #
# The synthetic catalog.
# ---------------------------------------------------------------------- #

#: The catalog these tests select over: ``(check_id, account_type, service)``.
#:
#: Shaped so the filter space has interesting corners rather than being a tidy
#: cross product. Every ``AccountType`` member appears; one service spans two
#: account types ("Alpha Service"), one spans two others ("Bravo"), and three
#: sit in exactly one each. That leaves many ``(account_type, service)`` pairs
#: matching nothing -- (application, "Bravo"), (log-archive, "Alpha Service"),
#: (audit, "Echo") -- which is the half of the space where the raise is the
#: correct answer, and therefore the half worth having.
_SYNTHETIC: tuple[tuple[str, AccountType, str], ...] = (
    ("SRA-ALPHA-01", AccountType.APPLICATION, "Alpha Service"),
    ("SRA-ALPHA-02", AccountType.APPLICATION, "Alpha Service"),
    ("SRA-ALPHA-03", AccountType.AUDIT, "Alpha Service"),
    ("SRA-BRAVO-01", AccountType.AUDIT, "Bravo"),
    ("SRA-BRAVO-02", AccountType.LOG_ARCHIVE, "Bravo"),
    ("SRA-CHARLIE-01", AccountType.MANAGEMENT, "Charlie Service"),
    ("SRA-DELTA-01", AccountType.APPLICATION, "Delta"),
    ("SRA-ECHO-01", AccountType.MANAGEMENT, "Echo"),
)

#: The check IDs in the synthetic catalog.
_CHECK_IDS: tuple[str, ...] = tuple(cid for cid, _, _ in _SYNTHETIC)

#: The service display names in the synthetic catalog.
_SERVICES: tuple[str, ...] = tuple(sorted({svc for _, _, svc in _SYNTHETIC}))

#: Every legal ``--account-type`` value: the enum's values plus the literal
#: ``'all'``, built the way ``parse_args`` builds the argparse choices so this
#: module carries no second list of account-type strings.
_ACCOUNT_TYPE_FILTERS: tuple[str, ...] = tuple(t.value for t in AccountType) + ("all",)

#: Service filter values that must match nothing. Prefixes and substrings of
#: real names are the interesting ones: the design pins full-value matching, so
#: ``--service Alpha`` selecting the two "Alpha Service" checks would be a
#: silently wider scan than the operator asked for. ``""`` and ``" "`` are here
#: because an emptiness special case would make them match everything, which is
#: the worst version of the same defect.
_ABSENT_SERVICES: tuple[str, ...] = (
    "",
    " ",
    "Alpha",
    "Service",
    "Alpha  Service",
    "AlphaService",
    "Alpha-Service",
    "Bravo Service",
    "Delta Service",
    "Zulu",
    "Zulu Service",
    "Alpha Service Extra",
)

#: ``--check`` values absent from the synthetic catalog. ``"sra-alpha-01"`` is
#: here because check IDs match exactly and case-sensitively, unlike services,
#: and ``"SRA-ALPHA-01 "`` because no ``strip()`` is applied to this filter.
_UNKNOWN_CHECK_IDS: tuple[str, ...] = (
    "",
    "SRA-ALPHA-04",
    "SRA-ALPHA-99",
    "SRA-ZULU-01",
    "sra-alpha-01",
    "SRA-ALPHA-1",
    "SRA-ALPHA-01 ",
    " SRA-ALPHA-01",
    "ALPHA-01",
    "not a check id",
)


def _meta(check_id: str, account_type: AccountType, service: str) -> CheckMeta:
    """Build a real, fully validated ``CheckMeta`` for a synthetic check.

    A real ``CheckMeta`` rather than a stand-in object, because ``_select``
    reads ``meta.account_type`` and ``meta.service`` and the account-type
    comparison depends on ``AccountType`` being a ``StrEnum`` -- a plain string
    stand-in would let a broken comparison pass here and fail in production.

    Args:
        check_id: The synthetic check ID, in ``SRA-<SERVICE>-NN`` shape.
        account_type: The account type this synthetic check applies to.
        service: The service display name, mixed case as the real ones are.

    Returns:
        A validated ``CheckMeta``.
    """
    return CheckMeta(
        check_id=check_id,
        # First token is not one of the forbidden ones, and the whole string is
        # whitespace-normalized, so validation rules 4 and 5 are satisfied.
        title=f"Synthetic control {check_id} is configured",
        description=f"Synthetic description for {check_id}.",
        check_logic="Reads the synthetic catalog and asserts nothing.",
        severity=Severity.MEDIUM,
        account_type=account_type,
        service=service,
        resource_type="AWS::Synthetic::Resource",
        remediation=Remediation(text=f"Nothing to remediate for {check_id}."),
    )


def _synthetic_check(
    check_id: str, account_type: AccountType, service: str
) -> type[SecurityCheck]:
    """Return a concrete ``SecurityCheck`` subclass carrying real metadata.

    Created with ``type()`` in this module, whose file stem does not begin with
    ``sra_``, so ``__init_subclass__`` returns silently: the class is neither
    identity-checked nor registered, and the caller registers it explicitly.
    ``execute`` is supplied so the class is concrete, which keeps it a faithful
    stand-in even though selection never instantiates it.

    Args:
        check_id: The check ID, also the basis for the class name.
        account_type: The account type for the metadata.
        service: The service display name for the metadata.

    Returns:
        A concrete subclass of ``SecurityCheck`` with a validated ``meta``.
    """

    def execute(self: SecurityCheck) -> Iterator[Finding]:
        """Yield nothing."""
        yield from ()

    return type(
        check_id.replace("-", "_"),
        (SecurityCheck,),
        {
            "__doc__": f"Synthetic check standing in for {check_id}.",
            "meta": _meta(check_id, account_type, service),
            "execute": execute,
        },
    )


#: One class per row of ``_SYNTHETIC``, built once at import.
_SYNTHETIC_CLASSES: dict[str, type[SecurityCheck]] = {
    check_id: _synthetic_check(check_id, account_type, service)
    for check_id, account_type, service in _SYNTHETIC
}


@pytest.fixture(scope="module", autouse=True)
def _synthetic_catalog() -> Iterator[None]:
    """Install the synthetic catalog over ``_REGISTRY`` for this module.

    Snapshots the module-level registry, replaces its contents with the
    synthetic classes, and restores the snapshot afterwards. The dict is
    mutated in place rather than rebound, so ``all_checks()`` -- which reads
    ``_REGISTRY`` on every call -- sees the synthetic catalog while this module
    runs and the real one again afterwards.

    Module-scoped deliberately: a function-scoped fixture combined with
    ``@given`` trips hypothesis's ``function_scoped_fixture`` health check, and
    the installation is identical for every draw, so there is nothing to
    re-do per example.
    """
    saved = dict(registry._REGISTRY)
    registry._REGISTRY.clear()
    try:
        for check_id, cls in _SYNTHETIC_CLASSES.items():
            registry.register(check_id, cls)
        yield
    finally:
        registry._REGISTRY.clear()
        registry._REGISTRY.update(saved)


def _selector() -> "SRAVerify":
    """Return an ``SRAVerify`` whose ``_select`` is callable, built without AWS.

    ``SRAVerify.__init__`` configures logging and builds a boto3 ``Session``,
    neither of which ``_select`` reads: selection touches only ``cls.meta`` on
    the registered classes. Bypassing ``__init__`` with ``__new__`` keeps these
    tests credential-free and offline, which is what lets them quantify over
    hundreds of filter combinations.

    Returns:
        An uninitialized ``SRAVerify`` instance, sufficient for ``_select``.
    """
    return SRAVerify.__new__(SRAVerify)


def _expected(
    account_type: str, service: Optional[str], check_id: Optional[str]
) -> set[str]:
    """The check IDs that ought to match, derived from ``_SYNTHETIC``.

    Computed from the literal table rather than from the registry, so a defect
    in the catalog installation shows up as a mismatch here rather than
    cancelling out.

    Args:
        account_type: An account-type value, or ``'all'`` for no filter.
        service: A service filter as it would be supplied on the command line,
            or ``None`` for no filter.
        check_id: A check ID, or ``None`` for no filter.

    Returns:
        The set of matching check IDs, possibly empty.
    """
    wanted = None if service is None else service.strip().lower()
    return {
        cid
        for cid, own_type, own_service in _SYNTHETIC
        # --check narrows rather than replaces (9.6), so it is one conjunct
        # among three and not a short circuit past the other two.
        if (check_id is None or cid == check_id)
        and (account_type == "all" or own_type.value == account_type)
        and (wanted is None or own_service.lower() == wanted)
    }


# ---------------------------------------------------------------------- #
# Strategies.
# ---------------------------------------------------------------------- #


def account_type_filters() -> st.SearchStrategy[str]:
    """Return a strategy over every legal ``--account-type`` value.

    Returns:
        A strategy producing the four ``AccountType`` values and ``'all'``.
    """
    return st.sampled_from(_ACCOUNT_TYPE_FILTERS)


def service_filters() -> st.SearchStrategy[Optional[str]]:
    """Return a strategy over ``--service`` values, matching and not.

    Four populations, and the split matters:

      * ``None`` -- the filter was not supplied.
      * A catalog service verbatim, and case variants of one, all of which must
        match, since matching is ``str.lower()``-based.
      * A catalog service padded with surrounding whitespace, which must match,
        since ``strip()`` is applied to the supplied value.
      * ``_ABSENT_SERVICES``, none of which may match.

    Returns:
        A strategy producing ``str`` or ``None``.
    """
    exact = st.sampled_from(_SERVICES)
    cased = exact.flatmap(
        lambda name: st.sampled_from(
            [name, name.lower(), name.upper(), name.title(), name.swapcase()]
        )
    )
    padded = st.builds(
        lambda name, left, right: f"{left}{name}{right}",
        exact,
        st.sampled_from(["", " ", "  ", "\t", "\n"]),
        st.sampled_from(["", " ", "  ", "\t", "\n"]),
    )
    return st.one_of(
        st.none(), exact, cased, padded, st.sampled_from(_ABSENT_SERVICES)
    )


def check_id_filters() -> st.SearchStrategy[Optional[str]]:
    """Return a strategy over ``--check`` values, known and unknown.

    Returns:
        A strategy producing ``None``, a registered check ID, or one of the
        unknown values that must reach ``UnknownCheckError``.
    """
    return st.one_of(
        st.none(),
        st.sampled_from(_CHECK_IDS),
        st.sampled_from(_UNKNOWN_CHECK_IDS),
    )


#: Every ``(check_id, account_type, service)`` triple whose check ID is real and
#: whose other filters contradict it. Enumerated rather than drawn-and-filtered
#: so the population is exactly the contradictions and hypothesis wastes no
#: draws rejecting agreeable combinations.
_CONTRADICTIONS: tuple[tuple[str, str, Optional[str]], ...] = tuple(
    (check_id, account_type, service)
    for check_id, own_type, own_service in _SYNTHETIC
    for account_type in _ACCOUNT_TYPE_FILTERS
    for service in (None,) + _SERVICES
    if not (
        (account_type == "all" or account_type == own_type.value)
        and (service is None or service.lower() == own_service.lower())
    )
)


# ---------------------------------------------------------------------- #
# Property 16.
# ---------------------------------------------------------------------- #


@given(
    account_type=account_type_filters(),
    service=service_filters(),
    check_id=check_id_filters(),
)
def test_select_returns_a_non_empty_matching_mapping_or_raises(
    account_type: str, service: Optional[str], check_id: Optional[str]
) -> None:
    """Property 16: ``_select`` never returns an empty mapping.

    Either a non-empty mapping whose every member matches every supplied
    filter, or a raise. There is no third outcome for any filter combination,
    and in particular no empty mapping.

    Validates: Requirements 9.2, 9.5, 9.6
    """
    sra = _selector()
    expected = _expected(account_type, service, check_id)

    # ---- An unmatched --check is a different failure -------------------- #
    # 9.4's error, kept distinct from 9.5's: the ID does not exist, so there
    # is nothing for the other two filters to narrow.
    if check_id is not None and check_id not in _CHECK_IDS:
        with pytest.raises(UnknownCheckError) as excinfo:
            sra._select(account_type, service, check_id)
        assert excinfo.value.check_id == check_id, (
            f"UnknownCheckError does not carry the supplied ID: "
            f"{excinfo.value.check_id!r} != {check_id!r}"
        )
        assert len(excinfo.value.suggestions) <= 3, (
            f"UnknownCheckError carries more than three suggestions: "
            f"{excinfo.value.suggestions!r}"
        )
        return

    # ---- Nothing matches: a raise, never an empty mapping -------------- #
    if not expected:
        with pytest.raises(NoChecksSelectedError) as excinfo:
            sra._select(account_type, service, check_id)
        error = excinfo.value
        # Not an UnknownCheckError: the two are siblings under SRAVerifyError
        # and neither subclasses the other, so a caller distinguishing them
        # can keep doing so.
        assert not isinstance(error, UnknownCheckError), (
            "an empty filter combination was reported as an unknown check ID"
        )
        # 9.5: the error carries all three filter values as supplied, with
        # None marking a filter that was not supplied. Without them the
        # operator sees "no checks selected" and cannot tell which of three
        # filters was the mistake.
        assert error.args == (account_type, service, check_id), (
            f"NoChecksSelectedError does not carry the three filters: "
            f"{error.args!r}"
        )
        return

    # ---- Something matches: a non-empty, fully matching mapping -------- #
    selected = sra._select(account_type, service, check_id)

    assert selected, (
        f"_select returned an empty mapping for account_type={account_type!r}, "
        f"service={service!r}, check_id={check_id!r}; it must raise "
        f"NoChecksSelectedError instead"
    )
    assert len(selected) > 0
    assert set(selected) == expected, (
        f"selection mismatch for account_type={account_type!r}, "
        f"service={service!r}, check_id={check_id!r}: expected {sorted(expected)}, "
        f"got {sorted(selected)}"
    )

    for selected_id, cls in selected.items():
        meta = cls.meta
        assert cls is _SYNTHETIC_CLASSES[selected_id], (
            f"{selected_id} maps to {cls!r}, not the registered class"
        )
        # The mapping's key is the check's own ID, so a caller iterating it can
        # trust the key without reading meta.
        assert meta.check_id == selected_id, (
            f"key {selected_id!r} does not match meta.check_id "
            f"{meta.check_id!r}"
        )
        if account_type != "all":
            assert meta.account_type == account_type, (
                f"{selected_id} has account_type {meta.account_type!r}, which "
                f"does not match the filter {account_type!r}"
            )
        if service is not None:
            assert meta.service.lower() == service.strip().lower(), (
                f"{selected_id} has service {meta.service!r}, which does not "
                f"match the filter {service!r}"
            )
        if check_id is not None:
            assert selected_id == check_id, (
                f"--check {check_id!r} selected {selected_id!r} as well"
            )


@pytest.mark.parametrize("account_type", _ACCOUNT_TYPE_FILTERS)
@pytest.mark.parametrize("service", (None,) + _SERVICES)
def test_every_account_type_and_service_pair_is_non_empty_or_raises(
    account_type: str, service: Optional[str]
) -> None:
    """The ∀ in Property 16, swept exhaustively rather than sampled.

    Property 16 quantifies over every ``AccountType`` member and every service
    in the set. Both are small and closed, so the cross product is enumerable
    and enumeration beats sampling here: it guarantees the pairs that match
    nothing -- (application, "Bravo"), (audit, "Echo") -- are all visited on
    every run rather than on most runs.

    Validates: Requirements 9.2, 9.5
    """
    sra = _selector()
    expected = _expected(account_type, service, None)

    if not expected:
        with pytest.raises(NoChecksSelectedError) as excinfo:
            sra._select(account_type, service, None)
        assert excinfo.value.args == (account_type, service, None)
        return

    selected = sra._select(account_type, service, None)

    assert selected
    assert set(selected) == expected
    assert all(
        account_type == "all" or cls.meta.account_type == account_type
        for cls in selected.values()
    )
    assert all(
        service is None or cls.meta.service.lower() == service.strip().lower()
        for cls in selected.values()
    )


@given(triple=st.sampled_from(_CONTRADICTIONS))
def test_a_registered_check_id_contradicting_a_filter_raises_no_checks_selected(
    triple: tuple[str, str, Optional[str]],
) -> None:
    """Requirement 9.6: ``--check`` narrows the intersection.

    The ID is real, so this is not an unknown check; the other filters exclude
    it, so the intersection is empty. Both wrong answers are plausible
    implementations and both are asserted against: replacing the set with the
    single ID would return a one-entry mapping, and short-circuiting on
    ``--check`` before the other filters would do the same.

    Validates: Requirements 9.2, 9.5, 9.6
    """
    check_id, account_type, service = triple
    sra = _selector()

    # Precondition, asserted rather than assumed: the ID is in the catalog, so
    # UnknownCheckError is not the correct answer here.
    assert check_id in registry.all_checks()
    assert _expected(account_type, service, check_id) == set()

    with pytest.raises(NoChecksSelectedError) as excinfo:
        sra._select(account_type, service, check_id)

    error = excinfo.value
    assert not isinstance(error, UnknownCheckError), (
        f"--check {check_id!r} contradicting account_type={account_type!r} / "
        f"service={service!r} was reported as an unknown check ID"
    )
    assert isinstance(error, SRAVerifyError)
    assert error.args == (account_type, service, check_id), (
        f"NoChecksSelectedError does not carry the three filters: {error.args!r}"
    )


@given(check_id=st.sampled_from(_CHECK_IDS))
def test_a_registered_check_id_alone_selects_exactly_itself(
    check_id: str,
) -> None:
    """The other side of 9.6: agreeing filters select the one check.

    Without this, ``test_a_registered_check_id_contradicting_a_filter_raises``
    would pass on an implementation that rejects every ``--check``.

    Validates: Requirements 9.2, 9.6
    """
    sra = _selector()
    own_type = _SYNTHETIC_CLASSES[check_id].meta.account_type
    own_service = _SYNTHETIC_CLASSES[check_id].meta.service

    for account_type in ("all", own_type.value):
        for service in (None, own_service, own_service.upper(), f"  {own_service} "):
            selected = sra._select(account_type, service, check_id)

            assert set(selected) == {check_id}, (
                f"--check {check_id!r} with account_type={account_type!r} and "
                f"service={service!r} selected {sorted(selected)}"
            )
            assert selected[check_id] is _SYNTHETIC_CLASSES[check_id]


def test_no_filters_selects_the_whole_catalog() -> None:
    """The unfiltered call is the widest non-empty answer, not a special case.

    Validates: Requirements 9.2
    """
    sra = _selector()

    selected = sra._select()

    assert set(selected) == set(_CHECK_IDS)
    assert sra._select("all", None, None) == selected


def test_the_returned_mapping_is_a_plain_dict_the_caller_may_hold() -> None:
    """``_select`` hands back its own dict, not the registry's read-only view.

    ``run_checks`` groups the result by service and reads ``len()`` off it, so
    the return value has to be an ordinary mapping. Returning
    ``all_checks()``'s ``MappingProxyType`` unchanged for the no-filter case
    would be an easy accident and would make the two branches behave
    differently.

    Validates: Requirements 9.2
    """
    sra = _selector()

    unfiltered = sra._select()
    filtered = sra._select("application", None, None)

    for selected in (unfiltered, filtered):
        assert isinstance(selected, dict)
        assert not isinstance(selected, MappingProxyType)
        # Mutating the returned mapping does not reach the catalog.
        selected.pop(next(iter(selected)))
    assert set(registry.all_checks()) == set(_CHECK_IDS)


# ---------------------------------------------------------------------- #
# Guards. Every assertion above is vacuous if these do not hold.
# ---------------------------------------------------------------------- #


def test_the_synthetic_catalog_is_installed_and_is_the_whole_catalog() -> None:
    """Pin the fixture's effect, and that the classes carry real metadata.

    Validates: Requirements 9.2
    """
    catalog = registry.all_checks()

    assert set(catalog) == set(_CHECK_IDS)
    for check_id, account_type, service in _SYNTHETIC:
        cls = catalog[check_id]
        assert cls is _SYNTHETIC_CLASSES[check_id]
        assert isinstance(cls.meta, CheckMeta)
        assert cls.meta.check_id == check_id
        assert cls.meta.account_type is account_type
        assert cls.meta.service == service


def test_the_synthetic_catalog_spans_several_account_types_and_services() -> None:
    """The property's ∀ is only meaningful over a catalog that spans the space.

    A single-account-type catalog would let every account-type assertion above
    pass trivially.

    Validates: Requirements 9.2
    """
    assert {account_type for _, account_type, _ in _SYNTHETIC} == set(AccountType)
    assert len(_SERVICES) >= 3


def test_some_filter_pairs_match_nothing_so_the_raise_branch_is_exercised() -> None:
    """At least one ``(account_type, service)`` pair must match nothing.

    If every pair matched something, Property 16 would never reach its raise
    branch and the empty-mapping defect it exists to catch would go untested.

    Validates: Requirements 9.2, 9.5
    """
    empty_pairs = [
        (account_type, service)
        for account_type in (t.value for t in AccountType)
        for service in _SERVICES
        if not _expected(account_type, service, None)
    ]

    assert empty_pairs, (
        "every account-type/service pair matches at least one synthetic check; "
        "the raise branch of Property 16 is never reached"
    )
    assert _CONTRADICTIONS, "no contradictory --check combination to test"


def test_declaring_a_synthetic_subclass_does_not_register_it() -> None:
    """Registration here is explicit, and has to be.

    ``__init_subclass__`` returns silently for a subclass whose defining
    module's file stem does not begin with ``sra_``, which is what lets this
    module declare eight ``SecurityCheck`` subclasses without tripping the
    identity rules. The corollary is that a class created and *not* passed to
    ``registry.register`` never reaches the catalog -- so if this ever changed,
    ``_synthetic_catalog`` would be installing a different catalog than it
    thinks.

    Validates: Requirements 9.2
    """
    unregistered = _synthetic_check(
        "SRA-FOXTROT-01", AccountType.APPLICATION, "Foxtrot"
    )

    assert "SRA-FOXTROT-01" not in registry.all_checks()
    assert unregistered not in set(registry.all_checks().values())


def test_main_is_the_real_module_and_select_reads_the_live_registry() -> None:
    """The import shim loaded ``sraverify.main`` itself, not a stand-in.

    And ``_select`` reads the registry through ``all_checks()`` on every call,
    which is what makes the synthetic catalog visible to it at all. A module
    that had captured the catalog at import time would still be answering with
    the real one.

    Validates: Requirements 9.2
    """
    assert _main.__name__ == "sraverify.main"
    assert _main.__file__ is not None and _main.__file__.endswith("main.py")
    assert SRAVerify.__module__ == "sraverify.main"

    # No stub left behind for a sibling test module to inherit.
    stub = sys.modules.get("sraverify.services")
    assert stub is None or getattr(stub, "__file__", None) is not None

    # Reads the live registry: a check removed from it disappears from the
    # selection without main.py being reloaded.
    sra = _selector()
    assert "SRA-ECHO-01" in sra._select()
    removed = registry._REGISTRY.pop("SRA-ECHO-01")
    try:
        assert "SRA-ECHO-01" not in sra._select()
    finally:
        registry._REGISTRY["SRA-ECHO-01"] = removed
