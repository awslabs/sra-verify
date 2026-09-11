"""Property-based test for the cost of selection (task 11.5).

This module implements **Property 15: selection never instantiates a check**:

    Selection filters never instantiate a check class. Asserted by patching
    ``SecurityCheck.__init__`` with a counter (or a ``__new__`` spy) and
    confirming zero calls across ``_select``, ``get_available_checks``, and
    ``get_available_services`` for every filter combination.

**Validates: Requirements 9.1, 9.8, 9.9, 9.11**

What the property is actually protecting
----------------------------------------

Before this change, metadata was imperative instance state assigned inside each
check's ``__init__``, so the only way to read a check's account type or service
was to build one. ``run_checks`` and the two inventory functions each rebuilt the
whole catalog to filter it, and a default scan performed **474** constructions to
run 158 checks. A ``--check SRA-GUARDDUTY-01`` run performed **161** to run 1.
None of those 316 surplus constructions did anything except read four strings
back off an object that had just written them.

Metadata is now a validated ``CheckMeta`` ``ClassVar``, so every filter reads
``cls.meta`` off the class. The reduction to 158 and to 1 is therefore not an
optimization applied on top of the filters -- it is a consequence of the filters
having nothing to construct. This property is the assertion that pins it, and it
is worth pinning as a property rather than as a single count: the regression that
reintroduces the cost does not announce itself as "474 constructions" but as one
innocuous ``check_class().service`` inside one filter branch, reachable only for
some filter combinations. Quantifying over the filter space is what finds that.

Requirement 9.1 also says selection issues **zero AWS API calls**. That half is
covered structurally rather than by intercepting botocore: a check reaches AWS
only through ``self._ctx``, which only ``initialize(ctx)`` sets, and
``initialize`` is only ever called on an instance. Zero instances is therefore
zero opportunity, and the ``SRAVerify`` under test here is built with a sentinel
in place of a boto3 ``Session`` -- so if any code path on these three functions
did try to reach AWS, it would raise ``AttributeError`` rather than quietly
succeed against the developer's real credentials.

The complement, and why 9.11 is here
------------------------------------

Zero is only half of requirement 9.11. The other half is that the orchestrator
constructs **exactly one** instance of each selected check -- not zero, which
would mean nothing ran. ``test_a_scan_constructs_exactly_one_instance_per_selected_check``
asserts that half over a real ``run_checks`` call, which is possible without
credentials: ``ScanContext`` construction touches no network, and the account
identity lookup that does is already tolerated as non-fatal by design
(Requirement 10.5), so the scan proceeds with empty account strings. Without
that test this module would be satisfied by a ``_select`` that returned an empty
mapping and a ``run_checks`` that ran nothing.

Both spies, not one
-------------------

The design offers ``__init__`` or ``__new__``. This module installs both and
asserts both are silent, because they fail differently. A subclass that defines
its own ``__init__`` without calling ``super().__init__()`` is invisible to the
``__init__`` counter but not to the ``__new__`` counter; conversely an object
resurrected from a cache and re-initialized in place is invisible to ``__new__``
but not to ``__init__``. ``test_the_spy_observes_a_real_construction`` is what
keeps the whole module from passing vacuously on a spy that was never wired in.

Fixtures are self-contained
---------------------------

The registry is module-level process state, so every test here runs inside
``_synthetic_catalog()``, which snapshots ``_REGISTRY``, swaps in a small
purpose-built catalog, and restores the snapshot afterwards. The catalog is
synthetic on purpose: the property is about the *filters*, and depending on the
real 158 would make the assertions drift every time a check is added, and would
make this module unrunnable in Phase 2 where most checks do not yet import.

The synthetic classes are declared in this module, whose file stem does not
begin with ``sra_``, so ``SecurityCheck.__init_subclass__`` returns silently and
none of them registers itself. They are therefore registered explicitly through
``registry.register`` -- which is also the honest shape, since what is under
test is selection over a catalog, not registration.
"""
from __future__ import annotations

import contextlib
import sys
import types
from typing import Any, Iterator, List, Optional

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from sraverify.core import registry
from sraverify.core.check import SecurityCheck
from sraverify.core.enums import AccountType, Severity
from sraverify.core.errors import NoChecksSelectedError, UnknownCheckError
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation


# ---------------------------------------------------------------------- #
# Importing main.py, in Phase 2 and in Phase 3 alike.
# ---------------------------------------------------------------------- #


def _load_sra_verify() -> type:
    """Return ``SRAVerify``, importing ``sraverify.main`` if it is not loaded.

    ``main.py`` carries ``import sraverify.services`` for its registration side
    effect. During Phase 2 of this change that walk raises
    ``CheckIdentityError`` on the first check body that has not been migrated
    yet, so importing ``main`` fails for a reason that has nothing to do with
    what this module tests. A stub is installed under
    ``sys.modules["sraverify.services"]`` so the import completes, and removed
    immediately afterwards so a later test module that legitimately imports a
    service package still gets the real one.

    The failed first attempt can register whatever checks *were* migrated before
    the walk hit one that was not, so the registry is rolled back to its
    pre-attempt contents. Nothing here relies on the real catalog -- every test
    supplies its own -- and leaving a partial one behind would leak into other
    modules sharing the process.

    Once Phase 3 completes the first attempt succeeds and none of the fallback
    runs, which is why the stub is scoped to the ``except`` branch rather than
    installed unconditionally.

    Returns:
        The ``SRAVerify`` class from ``sraverify.main``.
    """
    try:
        from sraverify.main import SRAVerify
        return SRAVerify
    except Exception:
        pass

    saved = dict(registry._REGISTRY)
    registry._REGISTRY.clear()
    registry._REGISTRY.update(saved)

    stub = types.ModuleType("sraverify.services")
    stub.__doc__ = (
        "Test stub standing in for the services package, whose import walks "
        "every check module. Installed only for the duration of importing "
        "sraverify.main."
    )
    # A package with nowhere to search: nothing can accidentally import a real
    # service module *through* the stub while it is installed.
    stub.__path__ = []  # type: ignore[attr-defined]
    sys.modules["sraverify.services"] = stub
    try:
        from sraverify.main import SRAVerify
    finally:
        if sys.modules.get("sraverify.services") is stub:
            del sys.modules["sraverify.services"]
        parent = sys.modules.get("sraverify")
        if getattr(parent, "services", None) is stub:
            delattr(parent, "services")
        registry._REGISTRY.clear()
        registry._REGISTRY.update(saved)
    return SRAVerify


SRAVerify = _load_sra_verify()


# ---------------------------------------------------------------------- #
# A sentinel in place of a boto3 Session.
# ---------------------------------------------------------------------- #


class _NoSession:
    """Stands in for a boto3 ``Session`` and refuses to behave like one.

    ``SRAVerify.__init__`` calls ``get_session(...)`` only when no session is
    supplied, and ``get_session`` reads the developer's real credentials. A
    sentinel avoids that while making the absence load-bearing: it carries no
    ``client`` attribute, so any attempt to reach AWS from a code path under
    test raises ``AttributeError`` instead of succeeding quietly. That is what
    turns the "zero AWS API calls" half of Requirement 9.1 into something this
    module can observe.
    """


def _selector(regions: Optional[List[str]] = None) -> Any:
    """Return an ``SRAVerify`` wired to no credentials.

    Args:
        regions: Region list to hand the scan. Supplied as a single real region
            by the ``run_checks`` test so the context never needs to resolve
            enabled regions, which would be an AWS call.

    Returns:
        An ``SRAVerify`` instance.
    """
    return SRAVerify(session=_NoSession(), regions=regions)


# ---------------------------------------------------------------------- #
# The synthetic catalog.
# ---------------------------------------------------------------------- #

#: ``(check_id, service display name, account type)`` for each synthetic check.
#:
#: Shaped to make the filter space interesting rather than merely populated:
#:
#:   * every ``AccountType`` member is represented, so no account-type filter
#:     is vacuous;
#:   * "Alpha Service" spans two account types and "Bravo Guard" spans two
#:     more, so a service filter and an account-type filter can each be
#:     satisfiable alone yet contradictory together -- the combination that
#:     reaches ``NoChecksSelectedError`` through criterion 9.6;
#:   * "Delta" holds a single check, so ``--check`` narrowing a one-element
#:     service is covered;
#:   * "Alpha Service" carries an internal space and mixed case, which is what
#:     the ``strip()``-and-lower-case matching rule of criterion 9.3 operates
#:     on.
_CATALOG_SPEC = (
    ("SRA-ALPHA-01", "Alpha Service", AccountType.APPLICATION),
    ("SRA-ALPHA-02", "Alpha Service", AccountType.AUDIT),
    ("SRA-BRAVO-01", "Bravo Guard", AccountType.LOG_ARCHIVE),
    ("SRA-BRAVO-02", "Bravo Guard", AccountType.MANAGEMENT),
    ("SRA-CHARLIE-01", "Charlie", AccountType.APPLICATION),
    ("SRA-CHARLIE-07", "Charlie", AccountType.APPLICATION),
    ("SRA-DELTA-01", "Delta", AccountType.AUDIT),
)


def _yield_nothing(self: SecurityCheck) -> Iterator[Finding]:
    """Yield no findings.

    Selection must never reach this, and the ``run_checks`` test wants a scan
    that completes without touching AWS, so an empty generator serves both.
    """
    return iter(())


def _setup_no_clients(self: SecurityCheck) -> None:
    """Register no client wrappers.

    The base ``_setup_clients`` raises ``NotImplementedError``, which
    ``initialize`` would surface and ``run_checks`` would convert into a
    synthetic ERROR row. Overriding it keeps the ``run_checks`` test asserting
    about construction counts rather than about error rows.
    """
    self._clients.clear()


def _synthetic_check(
    check_id: str, service: str, account_type: AccountType
) -> type[SecurityCheck]:
    """Build one throwaway check class carrying a real validated ``CheckMeta``.

    The metadata is a genuine ``CheckMeta``, constructed and therefore
    validated, so the filters read exactly the shape of attribute they read in
    production. Only the *values* are synthetic.

    Created through ``type()`` rather than a class statement so the seven
    entries of ``_CATALOG_SPEC`` stay a table. Either way the class is declared
    in this module, whose file stem does not begin with ``sra_``, so
    ``__init_subclass__`` returns silently and the class does not register
    itself.

    Args:
        check_id: The check ID, which must satisfy ``CheckMeta``'s format rule.
        service: The service display name the service filter matches on.
        account_type: The account type the account-type filter matches on.

    Returns:
        A concrete ``SecurityCheck`` subclass, unregistered.
    """
    meta = CheckMeta(
        check_id=check_id,
        title=f"Synthetic control {check_id} states its expectation as a fact",
        description=(
            "Synthetic check used to exercise the selection filters without "
            "depending on the real catalog."
        ),
        check_logic="Yields no findings.",
        severity=Severity.MEDIUM,
        account_type=account_type,
        service=service,
        resource_type="AWS::Synthetic::Resource",
        remediation=Remediation(text="Nothing to remediate; this check is synthetic."),
    )
    return type(
        check_id.replace("-", "_"),
        (SecurityCheck,),
        {
            "__doc__": f"Throwaway check standing in for {check_id}.",
            "meta": meta,
            "execute": _yield_nothing,
            "_setup_clients": _setup_no_clients,
        },
    )


#: The synthetic catalog, built once. Registration happens per test, inside
#: ``_synthetic_catalog()``; these classes hold no per-scan state, so reusing
#: the class objects across tests is safe and keeps each example cheap.
_SYNTHETIC_CHECKS = tuple(_synthetic_check(*spec) for spec in _CATALOG_SPEC)

#: Every check ID in the synthetic catalog.
_CHECK_IDS = tuple(cls.meta.check_id for cls in _SYNTHETIC_CHECKS)

#: Every service display name in the synthetic catalog, deduplicated and sorted
#: the way ``get_available_services`` sorts.
_SERVICES = tuple(sorted({cls.meta.service for cls in _SYNTHETIC_CHECKS}))

#: The ``--account-type`` values the CLI accepts.
_ACCOUNT_TYPES = tuple(t.value for t in AccountType) + ("all",)


@contextlib.contextmanager
def _synthetic_catalog() -> Iterator[None]:
    """Swap the synthetic catalog in for the duration of the block.

    ``_REGISTRY`` is module-level process state. The snapshot is a shallow copy
    and restoration mutates the original dict in place rather than rebinding
    the name, so ``main.py``'s already-imported ``all_checks`` reference keeps
    seeing the restored contents.
    """
    saved = dict(registry._REGISTRY)
    registry._REGISTRY.clear()
    try:
        for cls in _SYNTHETIC_CHECKS:
            registry.register(cls.meta.check_id, cls)
        yield
    finally:
        registry._REGISTRY.clear()
        registry._REGISTRY.update(saved)


# ---------------------------------------------------------------------- #
# The instantiation spy.
# ---------------------------------------------------------------------- #


class _Spy:
    """Records every check construction observed while installed."""

    def __init__(self) -> None:
        """Start with both ledgers empty."""
        #: Classes passed to ``SecurityCheck.__new__``, in call order.
        self.new_calls: List[type] = []
        #: Types of the instances passed to ``SecurityCheck.__init__``.
        self.init_calls: List[type] = []

    @property
    def total(self) -> int:
        """The number of calls seen across both hooks."""
        return len(self.new_calls) + len(self.init_calls)

    def __repr__(self) -> str:
        """Render both ledgers, so a failure message names the culprits."""
        return (
            f"_Spy(new={[c.__name__ for c in self.new_calls]}, "
            f"init={[c.__name__ for c in self.init_calls]})"
        )


@contextlib.contextmanager
def _instantiation_spy() -> Iterator[_Spy]:
    """Count check constructions for the duration of the block.

    Both hooks are installed, because each is blind to a case the other
    catches: ``__init__`` misses a subclass that overrides it without calling
    ``super()``, and ``__new__`` misses re-initialization of an already-created
    object. Neither hook changes behavior -- both delegate to what was there
    before -- so code under the spy runs exactly as it would without it.

    ``__new__`` is wrapped in ``staticmethod`` explicitly: the implicit
    conversion Python applies to a ``__new__`` in a class *body* does not apply
    to one assigned afterwards.
    """
    spy = _Spy()
    original_init = SecurityCheck.__init__
    had_new = "__new__" in vars(SecurityCheck)
    original_new = vars(SecurityCheck).get("__new__")

    def counting_init(self: SecurityCheck, *args: Any, **kwargs: Any) -> None:
        spy.init_calls.append(type(self))
        original_init(self, *args, **kwargs)

    def counting_new(cls: type, *args: Any, **kwargs: Any) -> Any:
        spy.new_calls.append(cls)
        return object.__new__(cls)

    SecurityCheck.__init__ = counting_init  # type: ignore[method-assign]
    SecurityCheck.__new__ = staticmethod(counting_new)  # type: ignore[assignment]
    try:
        yield spy
    finally:
        SecurityCheck.__init__ = original_init  # type: ignore[method-assign]
        if had_new:
            SecurityCheck.__new__ = original_new  # type: ignore[assignment]
        else:
            del SecurityCheck.__new__


# ---------------------------------------------------------------------- #
# Strategies over the filter space.
# ---------------------------------------------------------------------- #


def account_type_filters() -> st.SearchStrategy[str]:
    """Return a strategy over the ``--account-type`` values.

    Drawn from ``AccountType`` itself plus the literal ``'all'``, mirroring how
    the CLI derives its choices (criterion 9.10), so a member added to the enum
    widens this property without an edit here.
    """
    return st.sampled_from(_ACCOUNT_TYPES)


def service_filters() -> st.SearchStrategy[Optional[str]]:
    """Return a strategy over the ``--service`` value, including ``None``.

    Three populations, all of which selection must survive without
    constructing anything:

      * the real display names, plus the case and surrounding-whitespace
        variants criterion 9.3 says must still match;
      * near misses that must match nothing -- a prefix, a substring, and an
        inner-whitespace variant -- because "matches nothing" reaches
        ``NoChecksSelectedError``, a code path the matching draws never take;
      * ``None``, meaning the filter was not supplied.
    """
    exact = st.sampled_from(_SERVICES)
    variants = exact.flatmap(
        lambda name: st.sampled_from(
            [
                name,
                name.lower(),
                name.upper(),
                name.swapcase(),
                f"  {name}",
                f"{name}\t",
                f"  {name}  ",
            ]
        )
    )
    non_matching = st.sampled_from(
        [
            "",
            " ",
            "Alph",                 # prefix of a real name
            "lpha Serv",            # substring of a real name
            "Alpha  Service",       # inner whitespace is not normalized away
            "AlphaService",
            "GuardDuty",            # a real service, absent from this catalog
            "Épsilon",
        ]
    )
    return st.one_of(st.none(), variants, non_matching)


def check_id_filters() -> st.SearchStrategy[Optional[str]]:
    """Return a strategy over the ``--check`` value, including ``None``.

    Covers the registered IDs, values that reach ``UnknownCheckError`` with
    suggestions (a transposed digit, a lower-cased ID -- the match is
    case-sensitive), values that reach it with none, and ``None``.
    """
    known = st.sampled_from(_CHECK_IDS)
    unknown = st.sampled_from(
        [
            "SRA-ALPHA-03",         # near miss, same service
            "SRA-ALPHA-10",
            "sra-alpha-01",         # matching is case-sensitive
            "SRA-ALPHA-01 ",        # and exact: no strip on this filter
            "SRA-ECHO-01",
            "SRA-GUARDDUTY-01",
            "",
            "nonsense",
        ]
    )
    return st.one_of(st.none(), known, unknown)


# ---------------------------------------------------------------------- #
# Wiring checks: without these the property could pass vacuously.
# ---------------------------------------------------------------------- #


def test_the_spy_observes_a_real_construction() -> None:
    """The spy is wired in, so zero elsewhere means something.

    A spy that silently failed to install would make every assertion in this
    module trivially true. This is the test that fails first if that happens.

    Validates: Requirements 9.1, 9.11
    """
    cls = _SYNTHETIC_CHECKS[0]

    with _instantiation_spy() as spy:
        instance = cls()

        assert spy.new_calls == [cls], repr(spy)
        assert spy.init_calls == [cls], repr(spy)

    # The instance is intact and ordinary: the spy delegated rather than
    # replaced, so nothing observed under it ran differently.
    assert isinstance(instance, SecurityCheck)
    assert instance._ctx is None
    assert instance._clients == {}
    assert list(instance.execute()) == []


def test_the_spy_uninstalls_itself() -> None:
    """Leaving the block restores ``SecurityCheck`` exactly.

    The spy mutates a class shared by the whole process. A leaked
    ``__init__`` or a leaked ``__new__`` would follow every later test module
    in the session, so restoration is asserted rather than assumed.

    Validates: Requirements 9.1, 9.11
    """
    before_init = SecurityCheck.__init__
    had_new_before = "__new__" in vars(SecurityCheck)

    with _instantiation_spy():
        assert SecurityCheck.__init__ is not before_init

    assert SecurityCheck.__init__ is before_init
    assert ("__new__" in vars(SecurityCheck)) is had_new_before

    # And construction still works, unobserved.
    _SYNTHETIC_CHECKS[0]()


def test_the_synthetic_catalog_is_what_selection_sees() -> None:
    """Inside the block the catalog is exactly the seven synthetic checks.

    The property below asserts that selection constructs nothing. Over an empty
    catalog that would hold for free. This pins the population, and the
    restoration on the way out.

    Validates: Requirements 9.1, 9.8
    """
    outside = dict(registry.all_checks())

    with _synthetic_catalog():
        catalog = registry.all_checks()
        assert tuple(catalog) == tuple(sorted(_CHECK_IDS))
        assert set(catalog.values()) == set(_SYNTHETIC_CHECKS)

    assert dict(registry.all_checks()) == outside


# ---------------------------------------------------------------------- #
# Property 15.
# ---------------------------------------------------------------------- #


@settings(max_examples=300, deadline=None)
@given(
    account_type=account_type_filters(),
    service=service_filters(),
    check_id=check_id_filters(),
)
def test_selection_constructs_no_check_for_any_filter_combination(
    account_type: str, service: Optional[str], check_id: Optional[str]
) -> None:
    """Property 15: ``_select`` and both inventory functions instantiate nothing.

    Quantified over the whole filter space, and asserted on the failing paths
    as well as the succeeding one: ``UnknownCheckError`` and
    ``NoChecksSelectedError`` are reached by different branches of ``_select``,
    and a construction on the way to raising would count just the same.

    Validates: Requirements 9.1, 9.8, 9.9, 9.11
    """
    sra = _selector()

    with _synthetic_catalog(), _instantiation_spy() as spy:
        selected = None
        try:
            selected = sra._select(account_type, service, check_id)
        except (UnknownCheckError, NoChecksSelectedError):
            # A usage error, not a check failure. Either way nothing is built.
            pass

        listed = sra.get_available_checks(account_type)
        services = sra.get_available_services()

        assert spy.new_calls == [], (
            f"selection built {len(spy.new_calls)} check instance(s) for "
            f"account_type={account_type!r}, service={service!r}, "
            f"check_id={check_id!r}: {spy!r}"
        )
        assert spy.init_calls == [], (
            f"selection initialized {len(spy.init_calls)} check instance(s) "
            f"for account_type={account_type!r}, service={service!r}, "
            f"check_id={check_id!r}: {spy!r}"
        )
        assert spy.total == 0

        # ---- The structural half of the same claim ------------------- #
        # A mapping of instances would satisfy a broken spy; classes cannot be
        # produced without reading `meta` off the class, which is the point.
        if selected is not None:
            assert selected, "_select returned an empty mapping"
            for key, value in selected.items():
                assert isinstance(value, type), (
                    f"_select returned a non-class for {key!r}: {value!r}"
                )
                assert issubclass(value, SecurityCheck)
                assert not isinstance(value, SecurityCheck)
                assert value.meta.check_id == key

        # ``get_available_checks`` returns plain strings, so no instance can be
        # hiding in its values either.
        for key, info in listed.items():
            assert isinstance(key, str)
            assert all(isinstance(v, str) for v in info.values()), (
                f"get_available_checks leaked a non-str value for {key!r}: {info!r}"
            )

        assert services == list(_SERVICES)


@settings(max_examples=200, deadline=None)
@given(
    account_type=account_type_filters(),
    service=service_filters(),
    check_id=check_id_filters(),
)
def test_repeated_selection_stays_free(
    account_type: str, service: Optional[str], check_id: Optional[str]
) -> None:
    """Selection cost does not accumulate across calls.

    The pre-change 474 was three passes over the catalog, not one, so a
    regression could reappear as a construction on a *later* call -- a lazily
    built cache of instances, say, that the first call populates and the second
    reads. Calling each function three times inside one spy window catches
    that shape; a single call per window would not.

    Validates: Requirements 9.1, 9.8, 9.9
    """
    sra = _selector()

    with _synthetic_catalog(), _instantiation_spy() as spy:
        for _ in range(3):
            with contextlib.suppress(UnknownCheckError, NoChecksSelectedError):
                sra._select(account_type, service, check_id)
            sra.get_available_checks(account_type)
            sra.get_available_services()

        assert spy.total == 0, (
            f"repeated selection built {spy.total} check instance(s) for "
            f"account_type={account_type!r}, service={service!r}, "
            f"check_id={check_id!r}: {spy!r}"
        )


@settings(max_examples=100, deadline=None)
@given(account_type=account_type_filters())
def test_listing_the_inventory_constructs_nothing_and_reads_only_metadata(
    account_type: str,
) -> None:
    """Criterion 9.8: ``--list-checks`` and ``--list-services`` build nothing.

    Separated from the combined property because the CLI reaches these two
    without ever calling ``_select``: ``--list-checks`` returns before the scan
    path is entered. A regression confined to the inventory path would
    otherwise be masked by ``_select`` in the same spy window.

    Validates: Requirements 9.8, 9.9
    """
    sra = _selector()

    with _synthetic_catalog(), _instantiation_spy() as spy:
        listed = sra.get_available_checks(account_type)
        services = sra.get_available_services()

        assert spy.total == 0, repr(spy)

    expected_ids = {
        cls.meta.check_id
        for cls in _SYNTHETIC_CHECKS
        if account_type == "all" or cls.meta.account_type == account_type
    }
    assert set(listed) == expected_ids
    assert services == list(_SERVICES)


# ---------------------------------------------------------------------- #
# The complement: exactly one construction per selected check (9.11).
# ---------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "account_type,service,check_id",
    [
        pytest.param("all", None, None, id="default-scan"),
        pytest.param("all", None, "SRA-ALPHA-01", id="single-check"),
        pytest.param("application", None, None, id="account-type-only"),
        pytest.param("all", "alpha service", None, id="service-only"),
        pytest.param("audit", "Delta", "SRA-DELTA-01", id="all-three-filters"),
    ],
)
def test_a_scan_constructs_exactly_one_instance_per_selected_check(
    account_type: str, service: Optional[str], check_id: Optional[str]
) -> None:
    """Criterion 9.11: one construction per selected check, and no more.

    The other half of Property 15. Zero constructions during selection is only
    an improvement if the scan itself still builds each selected check exactly
    once -- ``_select`` returning an empty mapping would satisfy every
    assertion above.

    Runs without credentials. ``ScanContext`` construction touches no network,
    the region list is supplied so nothing resolves enabled regions, and the
    one lookup that would reach AWS -- the account identity resolved once
    before the loop -- is already tolerated as non-fatal by design
    (Requirement 10.5), so the scan proceeds with empty account strings. The
    synthetic checks override ``_setup_clients`` to register no wrappers and
    yield no findings, so the scan completes with zero rows.

    Validates: Requirements 9.1, 9.11
    """
    sra = _selector(regions=["us-east-1"])

    with _synthetic_catalog():
        selected = sra._select(account_type, service, check_id)

        with _instantiation_spy() as spy:
            findings = sra.run_checks(
                account_type=account_type, service=service, check_id=check_id
            )

    # Zero findings, so every construction below is accounted for by selection
    # rather than by an error row standing in for a check that failed to build.
    assert findings == [], f"synthetic checks produced findings: {findings!r}"

    assert len(spy.new_calls) == len(selected), (
        f"expected {len(selected)} construction(s) for the selected checks, "
        f"saw {len(spy.new_calls)}: {spy!r}"
    )
    assert spy.new_calls == spy.init_calls, (
        f"__new__ and __init__ disagree on what was built: {spy!r}"
    )
    assert sorted(cls.meta.check_id for cls in spy.new_calls) == sorted(selected), (
        f"the classes constructed are not the ones selected: {spy!r}"
    )

    # One construction each, not one per region and not one per filter pass.
    assert len(set(spy.new_calls)) == len(spy.new_calls), (
        f"a check was constructed more than once: {spy!r}"
    )
