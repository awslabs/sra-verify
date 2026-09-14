"""Unit tests for ``SRAVerify._select`` -- the filter matrix and both error paths.

``_select`` is the whole of check selection: it resolves the three CLI filters
against the registry, reads ``cls.meta`` and nothing else, and either returns a
non-empty mapping or raises one of two typed usage errors. Four concerns get
weight here, in the order they can bite an operator:

  * **The matrix itself.** Account type, service, and check ID compose as an
    intersection. ``--check`` *narrows* that intersection rather than replacing
    it (Requirement 9.6), so a legal check ID contradicting a supplied account
    type or service yields zero matches and reaches
    ``NoChecksSelectedError`` -- **not** ``UnknownCheckError``. Getting that
    backwards would tell an operator their check ID is misspelled when it is
    their filter combination that is wrong.
  * **Service matching is full-value and ASCII-lower-cased.** ``str.lower()``,
    not ``casefold()``, no prefix match, no substring match, ``strip()`` on the
    supplied value only (9.3). ``--service Security`` matching "Security Hub"
    would silently widen a targeted scan.
  * **Suggestion ordering.** ``_near_misses`` is a hand-written helper, not
    ``difflib.get_close_matches``, precisely because 9.4 mandates ties broken by
    *ascending* check ID while ``get_close_matches`` returns them descending.
    The tie test below asserts the ascending order and contrasts it with
    difflib's, so a "simplification" back to ``get_close_matches`` fails here.
  * **Nothing is constructed.** 9.1 is a performance and safety claim at once:
    selection issues no AWS call because it builds no check. A ``no_instantiation``
    spy counts ``SecurityCheck.__init__`` calls across the whole matrix.

Two pieces of scaffolding are worth explaining, since neither is obvious:

``_import_main`` stubs ``sraverify.services`` in ``sys.modules`` when it is not
already imported, then restores it. ``main.py`` imports that package purely for
its registration side effect, and during Phase 2 the package does not import at
all -- every check body is still unmigrated. The stub makes this module
importable now and stays correct after Phase 3: these tests register their own
synthetic catalog and would have to clear the real 158 checks regardless, so
whether the real package loaded is immaterial to every assertion below.

``isolated_registry`` snapshots the module-level ``_REGISTRY`` around each test,
empties it for the duration, and restores it afterwards, mirroring the fixture
in ``test_registry.py``. Without the snapshot the synthetic catalog leaks into
the real one for every later test module in the session; without the emptying
the real 158 checks stay selectable alongside the synthetic ones.

Requirements 9.2, 9.3, 9.4, 9.5, 9.6.
"""
from __future__ import annotations

import difflib
import importlib
import sys
import types
from types import MappingProxyType

import pytest

from sraverify.core import registry
from sraverify.core.check import SecurityCheck
from sraverify.core.enums import AccountType, Severity
from sraverify.core.errors import (
    NoChecksSelectedError,
    SRAVerifyError,
    UnknownCheckError,
)
from sraverify.core.metadata import CheckMeta, Remediation


# --------------------------------------------------------------------------
# Importing main.py without importing the real service catalog
# --------------------------------------------------------------------------

def _import_main():
    """Import ``sraverify.main``, stubbing ``sraverify.services`` if needed.

    ``main.py`` carries ``import sraverify.services`` for its side effect: the
    import walks 18 service packages and 158 check modules, and each class body
    registers itself. Two reasons not to let that run here:

      * During Phase 2 it *cannot* run -- an unmigrated check raises
        ``CheckIdentityError`` and the import fails, taking ``main`` with it.
      * Even once it can, these tests replace the catalog with a synthetic one,
        so the real 158 entries are cleared before the first assertion.

    A bare ``ModuleType`` satisfies the import statement, because Python checks
    ``sys.modules`` before it looks at the filesystem. The stub is removed in
    the ``finally``, so a later test module in the same session still gets the
    real package. When ``sraverify.services`` is *already* imported -- another
    module got there first -- nothing is stubbed and nothing is restored.
    """
    if "sraverify.main" in sys.modules:
        return sys.modules["sraverify.main"]

    stub = None
    if "sraverify.services" not in sys.modules:
        stub = types.ModuleType("sraverify.services")
        # __path__ makes it a package, so an unexpected submodule import fails
        # as ModuleNotFoundError rather than as a confusing TypeError.
        stub.__path__ = []
        sys.modules["sraverify.services"] = stub

    try:
        return importlib.import_module("sraverify.main")
    finally:
        if stub is not None:
            if sys.modules.get("sraverify.services") is stub:
                del sys.modules["sraverify.services"]
            parent = sys.modules.get("sraverify")
            if getattr(parent, "services", None) is stub:
                delattr(parent, "services")


_main = _import_main()


def test_the_services_stub_did_not_outlive_the_import():
    """The scaffolding leaves ``sys.modules`` as it found it.

    A stub left behind would be handed to the next test module that imports
    ``sraverify.services`` expecting the real package, and it would report an
    empty catalog rather than failing -- the worst available outcome. Either the
    entry is gone or it is a real module with a file.
    """
    module = sys.modules.get("sraverify.services")

    assert module is None or getattr(module, "__file__", None) is not None


SRAVerify = _main.SRAVerify
SUGGESTION_CUTOFF = _main.SUGGESTION_CUTOFF
SUGGESTION_LIMIT = _main.SUGGESTION_LIMIT


# --------------------------------------------------------------------------
# Synthetic checks carrying real CheckMeta
# --------------------------------------------------------------------------

def _check_class(check_id: str, *, service: str, account_type: AccountType,
                 severity: Severity = Severity.MEDIUM) -> type:
    """Build a throwaway ``SecurityCheck`` subclass with real validated metadata.

    The metadata is a genuine ``CheckMeta``, so ``_select`` reads exactly the
    attribute shape it reads in production -- ``account_type`` as an
    ``AccountType`` member rather than a string is the part that matters, since
    the account-type filter compares a member against a plain CLI string.

    ``__init_subclass__`` fires on class creation and returns silently: this
    module's file stem is ``test_select``, which does not begin with ``sra_``,
    so the class is ineligible for automatic registration. Each test registers
    what it wants explicitly, which is what makes the catalog per-test rather
    than whatever happens to be on disk.

    ``execute`` is supplied so the class is concrete and therefore
    *instantiable*. That is deliberate: a class that cannot be constructed
    would make the no-instantiation spy vacuous.
    """
    meta = CheckMeta(
        check_id=check_id,
        title=f"{service} is configured for {check_id}",
        description=f"Synthetic metadata for {check_id}, used by selection tests.",
        check_logic="Reads nothing and calls no AWS API.",
        severity=severity,
        account_type=account_type,
        service=service,
        resource_type="AWS::Test::Resource",
        remediation=Remediation(text=f"Configure {service}."),
    )
    return type(
        check_id.replace("-", "_"),
        (SecurityCheck,),
        {"meta": meta, "execute": lambda self: iter(())},
    )


#: The default synthetic catalog: (check_id, service, account_type).
#:
#: Shaped to make the matrix answerable rather than to mirror the real one.
#: "GuardDuty" carries two checks under two different account types, so an
#: account-type filter has something to narrow. "Security Hub" and
#: "Security Lake" share a prefix and a first word, which is what the
#: no-prefix-match and no-substring-match rules need. "Firewall Manager" is
#: the fixture for the ``lower()``-versus-``casefold()`` distinction.
DEFAULT_SPECS = (
    ("SRA-TESTGD-01", "GuardDuty", AccountType.APPLICATION),
    ("SRA-TESTGD-02", "GuardDuty", AccountType.AUDIT),
    ("SRA-TESTSH-01", "Security Hub", AccountType.AUDIT),
    ("SRA-TESTSL-01", "Security Lake", AccountType.LOG_ARCHIVE),
    ("SRA-TESTFM-01", "Firewall Manager", AccountType.APPLICATION),
    ("SRA-TESTORG-01", "Organizations", AccountType.MANAGEMENT),
)


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

@pytest.fixture
def isolated_registry():
    """Snapshot ``_REGISTRY``, empty it for the test, and restore it afterwards.

    Same shape as ``test_registry.py``'s fixture: the restore mutates the
    original dict in place rather than rebinding the name, so ``main.py``'s
    ``all_checks`` -- which closes over that dict -- sees the restored contents.

    It also empties the registry, so a test that reads the catalog without
    going through ``catalog`` below sees an empty one rather than whatever the
    session happens to have imported. ``import sraverify.main`` pulls in
    ``sraverify.services`` and leaves all 158 real checks resident, which would
    otherwise make selection results depend on module execution order.
    """
    saved = dict(registry._REGISTRY)
    registry._REGISTRY.clear()
    try:
        yield registry._REGISTRY
    finally:
        registry._REGISTRY.clear()
        registry._REGISTRY.update(saved)


@pytest.fixture
def catalog(isolated_registry):
    """Factory replacing the catalog with a synthetic one.

    Clears the registry first, so a test's expectations are the whole truth
    about what is selectable rather than a subset of the real 158 checks.
    Returns the mapping of check ID to class it registered, so a test can
    assert on class *identity* and not merely on keys.
    """
    def factory(specs=DEFAULT_SPECS):
        isolated_registry.clear()
        classes = {}
        for check_id, service, account_type in specs:
            cls = _check_class(check_id, service=service, account_type=account_type)
            registry.register(check_id, cls)
            classes[check_id] = cls
        return classes

    return factory


@pytest.fixture
def registered(catalog):
    """The default synthetic catalog, registered."""
    return catalog()


@pytest.fixture
def selector():
    """An ``SRAVerify`` whose ``__init__`` never ran.

    ``_select`` touches no instance state -- it reads the registry and the
    arguments it was handed. Constructing a real ``SRAVerify`` would build a
    boto3 session through ``get_session``, which needs credentials and belongs
    to no part of what these tests assert.
    """
    return object.__new__(SRAVerify)


@pytest.fixture
def no_instantiation(monkeypatch):
    """Count ``SecurityCheck.__init__`` calls; yields the counter list.

    Selection must construct nothing (9.1). The synthetic classes are concrete
    and instantiable, so a regression that starts building instances to read
    metadata off them would be caught here rather than showing up as a slow
    scan and a surprise AWS call.
    """
    calls: list[type] = []
    original = SecurityCheck.__init__

    def counting_init(self, *args, **kwargs):
        calls.append(type(self))
        return original(self, *args, **kwargs)

    monkeypatch.setattr(SecurityCheck, "__init__", counting_init)
    return calls


# --------------------------------------------------------------------------
# No filters (Requirement 9.6)
# --------------------------------------------------------------------------

def test_no_filters_returns_the_whole_catalog(selector, registered):
    result = selector._select(account_type="all", service=None, check_id=None)

    assert set(result) == set(registered)


def test_the_defaults_are_no_filters(selector, registered):
    # A library caller writing SRAVerify()._select() must get everything.
    assert set(selector._select()) == set(registered)


def test_the_returned_values_are_the_registered_class_objects(selector, registered):
    result = selector._select()

    for check_id, cls in registered.items():
        assert result[check_id] is cls


def test_the_result_is_a_plain_mutable_dict(selector, registered):
    result = selector._select()

    # Not the registry's MappingProxyType: run_checks and the banner iterate it,
    # and a caller narrowing it further must not be poking at the live catalog.
    assert isinstance(result, dict)
    assert not isinstance(result, MappingProxyType)
    result.clear()
    assert len(registry.all_checks()) == len(registered)


# --------------------------------------------------------------------------
# The account-type filter (Requirement 9.2)
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("account_type", "expected"),
    [
        pytest.param(
            "application", {"SRA-TESTGD-01", "SRA-TESTFM-01"}, id="application"
        ),
        pytest.param("audit", {"SRA-TESTGD-02", "SRA-TESTSH-01"}, id="audit"),
        pytest.param("log-archive", {"SRA-TESTSL-01"}, id="log-archive"),
        pytest.param("management", {"SRA-TESTORG-01"}, id="management"),
    ],
)
def test_account_type_retains_only_matching_checks(
    selector, registered, account_type, expected
):
    assert set(selector._select(account_type=account_type)) == expected


def test_every_account_type_member_is_an_accepted_filter_value(selector, registered):
    # The CLI derives its choices from AccountType, so each member must be a
    # value the filter understands -- including "log-archive", whose member name
    # (LOG_ARCHIVE) differs from its value.
    for member in AccountType:
        assert selector._select(account_type=member.value)


def test_the_filter_compares_a_strenum_member_against_a_plain_string(
    selector, registered
):
    # meta.account_type is a member, the CLI hands over a str. _select compares
    # them directly with no .value, which only works because AccountType is a
    # StrEnum. This is the assertion that fails if it stops being one.
    assert isinstance(registered["SRA-TESTGD-02"].meta.account_type, AccountType)
    assert registered["SRA-TESTGD-02"].meta.account_type == "audit"
    assert set(selector._select(account_type="audit")) == {
        "SRA-TESTGD-02",
        "SRA-TESTSH-01",
    }


def test_all_is_a_sentinel_and_not_a_value_to_match(selector, registered):
    # No check declares account_type="all"; "all" means "do not filter".
    assert set(selector._select(account_type="all")) == set(registered)


def test_an_account_type_matching_nothing_raises(selector, catalog):
    catalog([("SRA-TESTGD-01", "GuardDuty", AccountType.APPLICATION)])

    with pytest.raises(NoChecksSelectedError):
        selector._select(account_type="management")


def test_an_account_type_that_is_not_a_legal_value_matches_nothing(selector, registered):
    # argparse rejects this before _select sees it, but _select is also a
    # library entry point. It must raise rather than silently return everything.
    with pytest.raises(NoChecksSelectedError):
        selector._select(account_type="account")


# --------------------------------------------------------------------------
# The service filter (Requirement 9.3)
# --------------------------------------------------------------------------

def test_service_matches_the_display_name_exactly(selector, registered):
    assert set(selector._select(service="GuardDuty")) == {
        "SRA-TESTGD-01",
        "SRA-TESTGD-02",
    }


@pytest.mark.parametrize(
    "supplied",
    [
        pytest.param("GuardDuty", id="as-declared"),
        pytest.param("guardduty", id="lower"),
        pytest.param("GUARDDUTY", id="upper"),
        pytest.param("GuArDdUtY", id="mixed"),
    ],
)
def test_service_matching_is_case_insensitive(selector, registered, supplied):
    assert set(selector._select(service=supplied)) == {
        "SRA-TESTGD-01",
        "SRA-TESTGD-02",
    }


@pytest.mark.parametrize(
    "supplied",
    [
        pytest.param("Security Hub", id="as-declared"),
        pytest.param("security hub", id="lower"),
        pytest.param("SECURITY HUB", id="upper"),
    ],
)
def test_a_multi_word_service_name_matches_in_full(selector, registered, supplied):
    assert set(selector._select(service=supplied)) == {"SRA-TESTSH-01"}


@pytest.mark.parametrize(
    "supplied",
    [
        pytest.param("  GuardDuty", id="leading"),
        pytest.param("GuardDuty  ", id="trailing"),
        pytest.param("  GuardDuty  ", id="both"),
        pytest.param("\tGuardDuty\n", id="tab-and-newline"),
    ],
)
def test_surrounding_whitespace_on_the_supplied_value_is_stripped(
    selector, registered, supplied
):
    # A shell or a CSV of service names readily contributes these.
    assert set(selector._select(service=supplied)) == {
        "SRA-TESTGD-01",
        "SRA-TESTGD-02",
    }


def test_interior_whitespace_is_not_normalized(selector, registered):
    # strip() only. "Security  Hub" with two spaces is a different value, and
    # meta.service is whitespace-normalized by CheckMeta rule 4, so no check
    # can carry the doubled form either.
    with pytest.raises(NoChecksSelectedError):
        selector._select(service="Security  Hub")


@pytest.mark.parametrize(
    "supplied",
    [
        pytest.param("Security", id="prefix-shared-by-two-services"),
        pytest.param("Guard", id="prefix"),
        pytest.param("GuardDuty Detector", id="declared-name-is-the-prefix"),
        pytest.param("Duty", id="suffix"),
        pytest.param("uardDut", id="substring"),
        pytest.param("Hub", id="second-word-only"),
    ],
)
def test_no_prefix_or_substring_match(selector, registered, supplied):
    # --service Security silently widening a targeted scan to Security Hub plus
    # Security Lake is the failure this rule exists to prevent.
    with pytest.raises(NoChecksSelectedError):
        selector._select(service=supplied)


def test_lower_not_casefold_so_a_lookalike_does_not_match(selector, registered):
    # U+FB01 LATIN SMALL LIGATURE FI: casefold() expands it to "fi" and would
    # match "Firewall Manager"; lower() leaves it alone and must not.
    with pytest.raises(NoChecksSelectedError):
        selector._select(service="\ufb01rewall Manager")

    # Same value spelled with ASCII letters does match, so the test above is
    # about the folding rule and not about the fixture being unreachable.
    assert set(selector._select(service="firewall manager")) == {"SRA-TESTFM-01"}


def test_case_mapping_is_ascii_and_locale_independent(selector, catalog):
    # "Inspector" is the classic locale hazard: a Turkish-locale lower of "I"
    # yields a dotless i. Python's str.lower() is locale-independent, and this
    # asserts _select inherits that.
    catalog([("SRA-TESTINS-01", "Inspector", AccountType.APPLICATION)])

    assert set(selector._select(service="INSPECTOR")) == {"SRA-TESTINS-01"}


@pytest.mark.parametrize(
    "supplied",
    [
        pytest.param("", id="empty"),
        pytest.param("   ", id="whitespace-only"),
        pytest.param("NoSuchService", id="unknown"),
    ],
)
def test_a_service_matching_nothing_raises(selector, registered, supplied):
    # An empty string is a supplied filter, not an absent one: only None means
    # "no service filter".
    with pytest.raises(NoChecksSelectedError):
        selector._select(service=supplied)


def test_the_service_and_account_type_filters_intersect(selector, registered):
    assert set(selector._select(account_type="audit", service="GuardDuty")) == {
        "SRA-TESTGD-02"
    }


def test_an_empty_intersection_of_service_and_account_type_raises(selector, registered):
    # Both filters match something on their own; together they match nothing.
    assert selector._select(account_type="management")
    assert selector._select(service="GuardDuty")

    with pytest.raises(NoChecksSelectedError):
        selector._select(account_type="management", service="GuardDuty")


# --------------------------------------------------------------------------
# The check-ID filter narrows rather than replaces (Requirement 9.6)
# --------------------------------------------------------------------------

def test_a_known_check_id_selects_exactly_that_check(selector, registered):
    result = selector._select(check_id="SRA-TESTGD-01")

    assert list(result) == ["SRA-TESTGD-01"]
    assert result["SRA-TESTGD-01"] is registered["SRA-TESTGD-01"]


def test_a_check_id_with_an_agreeing_account_type_survives(selector, registered):
    assert list(
        selector._select(account_type="application", check_id="SRA-TESTGD-01")
    ) == ["SRA-TESTGD-01"]


def test_a_check_id_with_an_agreeing_service_survives(selector, registered):
    assert list(selector._select(service="GuardDuty", check_id="SRA-TESTGD-01")) == [
        "SRA-TESTGD-01"
    ]


def test_all_three_filters_agreeing_yields_the_one_check(selector, registered):
    assert list(
        selector._select(
            account_type="application", service="GuardDuty", check_id="SRA-TESTGD-01"
        )
    ) == ["SRA-TESTGD-01"]


def test_a_legal_check_id_contradicting_the_account_type_is_no_checks_selected(
    selector, registered
):
    # THE distinction this criterion exists for: the ID is real and spelled
    # correctly, so UnknownCheckError would send the operator hunting for a
    # typo that is not there. The filter combination is what is wrong.
    with pytest.raises(NoChecksSelectedError):
        selector._select(account_type="management", check_id="SRA-TESTGD-01")


def test_a_legal_check_id_contradicting_the_service_is_no_checks_selected(
    selector, registered
):
    with pytest.raises(NoChecksSelectedError):
        selector._select(service="Security Hub", check_id="SRA-TESTGD-01")


def test_a_legal_check_id_contradicting_both_is_no_checks_selected(
    selector, registered
):
    with pytest.raises(NoChecksSelectedError):
        selector._select(
            account_type="management", service="Security Hub", check_id="SRA-TESTGD-01"
        )


def test_a_contradicted_check_id_does_not_raise_unknown_check(selector, registered):
    # Belt and braces on the same distinction, stated as the negative: these
    # two errors drive different exit paths in the CLI and different operator
    # actions, so confusing them is a real defect and not a wording choice.
    with pytest.raises(NoChecksSelectedError) as excinfo:
        selector._select(account_type="audit", check_id="SRA-TESTGD-01")

    assert not isinstance(excinfo.value, UnknownCheckError)


# --------------------------------------------------------------------------
# UnknownCheckError (Requirement 9.4)
# --------------------------------------------------------------------------

def test_an_unknown_check_id_raises_unknown_check_error(selector, registered):
    with pytest.raises(UnknownCheckError) as excinfo:
        selector._select(check_id="SRA-NOSUCH-01")

    assert excinfo.value.check_id == "SRA-NOSUCH-01"


def test_the_check_id_is_matched_case_sensitively(selector, registered):
    # Unlike --service. Check IDs are upper-case by construction (CHECK_ID_RE),
    # so a lower-case value is a mistake worth reporting rather than accepting.
    with pytest.raises(UnknownCheckError) as excinfo:
        selector._select(check_id="sra-testgd-01")

    assert excinfo.value.check_id == "sra-testgd-01"


def test_an_unknown_id_is_reported_before_the_other_filters_apply(selector, registered):
    # The ID is checked first, so a misspelling is reported as a misspelling
    # even when the account type would also have matched nothing.
    with pytest.raises(UnknownCheckError):
        selector._select(account_type="management", check_id="SRA-NOSUCH-01")


def test_suggestions_are_ordered_most_similar_first_with_ties_ascending(
    selector, catalog
):
    # Four keys equidistant from the supplied value (0.9286 apiece), so the
    # ordering is decided entirely by the tie-break. 9.4 says ascending check
    # ID; difflib.get_close_matches selects with heapq.nlargest over
    # (ratio, key) tuples and therefore returns ties DESCENDING. That
    # disagreement is the whole reason _near_misses is hand-written, so this
    # test asserts both halves: what we produce, and that difflib would not.
    keys = [
        "SRA-TESTSVC-01",
        "SRA-TESTSVC-02",
        "SRA-TESTSVC-03",
        "SRA-TESTSVC-05",
    ]
    catalog([(key, "Test Service", AccountType.APPLICATION) for key in keys])

    with pytest.raises(UnknownCheckError) as excinfo:
        selector._select(check_id="SRA-TESTSVC-04")

    suggestions = excinfo.value.suggestions
    assert suggestions == ["SRA-TESTSVC-01", "SRA-TESTSVC-02", "SRA-TESTSVC-03"]

    difflib_order = difflib.get_close_matches(
        "SRA-TESTSVC-04", keys, SUGGESTION_LIMIT, SUGGESTION_CUTOFF
    )
    assert difflib_order == ["SRA-TESTSVC-05", "SRA-TESTSVC-03", "SRA-TESTSVC-02"]
    assert suggestions != difflib_order


def test_similarity_outranks_the_ascending_tie_break(selector, catalog):
    # The tie-break is a tie-break and not a sort key: "SRA-OTHER-01" sorts
    # first alphabetically but is less similar (0.615 against 0.929), so it
    # must come second. Without this, "ties ascending" could be implemented as
    # "always ascending" and the tie test above would still pass.
    catalog(
        [
            ("SRA-TESTSVC-01", "Test Service", AccountType.APPLICATION),
            ("SRA-OTHER-01", "Other Service", AccountType.APPLICATION),
        ]
    )

    with pytest.raises(UnknownCheckError) as excinfo:
        selector._select(check_id="SRA-TESTSVC-04")

    assert excinfo.value.suggestions == ["SRA-TESTSVC-01", "SRA-OTHER-01"]


def test_at_most_three_suggestions_are_carried(selector, catalog):
    catalog(
        [
            (f"SRA-TESTSVC-{n:02d}", "Test Service", AccountType.APPLICATION)
            for n in range(1, 10)
        ]
    )

    with pytest.raises(UnknownCheckError) as excinfo:
        selector._select(check_id="SRA-TESTSVC-99")

    assert len(excinfo.value.suggestions) == SUGGESTION_LIMIT == 3


def test_suggestions_are_empty_when_nothing_reaches_the_cutoff(selector, registered):
    with pytest.raises(UnknownCheckError) as excinfo:
        selector._select(check_id="nope")

    # An empty list, not None and not a fabricated "closest anyway" guess: a
    # wrong suggestion is worse than none.
    assert excinfo.value.suggestions == []


def test_a_lower_case_id_yields_no_suggestions_rather_than_a_wrong_one(
    selector, registered
):
    # difflib scores "sra-testgd-01" against "SRA-TESTGD-01" at 0.29, below the
    # 0.6 cutoff, so the case-only mistake produces no hint. Asserted so the
    # behaviour is a recorded consequence of the cutoff rather than a surprise.
    with pytest.raises(UnknownCheckError) as excinfo:
        selector._select(check_id="sra-testgd-01")

    assert excinfo.value.suggestions == []


def test_every_suggestion_is_a_real_registry_key(selector, catalog):
    keys = [f"SRA-TESTSVC-{n:02d}" for n in range(1, 6)]
    catalog([(key, "Test Service", AccountType.APPLICATION) for key in keys])

    with pytest.raises(UnknownCheckError) as excinfo:
        selector._select(check_id="SRA-TESTSVC-09")

    assert set(excinfo.value.suggestions) <= set(keys)


def test_suggestions_ignore_the_account_type_and_service_filters(selector, registered):
    # Near misses are drawn from the whole registry, which is right: the
    # operator mistyped an ID, and the useful hint is what IDs exist. Both
    # GuardDuty checks are suggested even though the supplied account type
    # would have excluded SRA-TESTGD-01 outright.
    with pytest.raises(UnknownCheckError) as excinfo:
        selector._select(account_type="management", check_id="SRA-TESTGD-03")

    suggestions = excinfo.value.suggestions
    assert "SRA-TESTGD-01" in suggestions
    assert registered["SRA-TESTGD-01"].meta.account_type != "management"


def test_an_empty_registry_yields_no_suggestions(selector, catalog):
    catalog([])

    with pytest.raises(UnknownCheckError) as excinfo:
        selector._select(check_id="SRA-TESTGD-01")

    assert excinfo.value.suggestions == []


# --------------------------------------------------------------------------
# NoChecksSelectedError payload (Requirement 9.5)
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("kwargs", "expected_args"),
    [
        pytest.param(
            {"account_type": "management", "service": "GuardDuty"},
            ("management", "GuardDuty", None),
            id="account-type-and-service",
        ),
        pytest.param(
            {"service": "NoSuchService"},
            ("all", "NoSuchService", None),
            id="service-only",
        ),
        pytest.param(
            {"account_type": "management", "check_id": "SRA-TESTGD-01"},
            ("management", None, "SRA-TESTGD-01"),
            id="account-type-and-check-id",
        ),
        pytest.param(
            {
                "account_type": "audit",
                "service": "Organizations",
                "check_id": "SRA-TESTORG-01",
            },
            ("audit", "Organizations", "SRA-TESTORG-01"),
            id="all-three",
        ),
    ],
)
def test_no_checks_selected_carries_all_three_filter_values(
    selector, registered, kwargs, expected_args
):
    # None marks a filter that was not supplied, and "all" is the account-type
    # equivalent. The CLI logs these verbatim, so an operator can see the
    # combination that matched nothing without re-reading their command line.
    with pytest.raises(NoChecksSelectedError) as excinfo:
        selector._select(**kwargs)

    assert excinfo.value.args == expected_args


def test_the_supplied_service_value_is_carried_unstripped(selector, registered):
    # The filter strips before comparing; the error reports what was supplied,
    # which is what the operator has to correct.
    with pytest.raises(NoChecksSelectedError) as excinfo:
        selector._select(service="  NoSuchService  ")

    assert excinfo.value.args == ("all", "  NoSuchService  ", None)


def test_an_empty_registry_raises_no_checks_selected(selector, catalog):
    catalog([])

    with pytest.raises(NoChecksSelectedError) as excinfo:
        selector._select()

    assert excinfo.value.args == ("all", None, None)


def test_both_errors_are_sraverify_errors(selector, registered):
    # main() catches them together to exit 2, so the shared base is load-bearing.
    with pytest.raises(SRAVerifyError):
        selector._select(check_id="SRA-NOSUCH-01")
    with pytest.raises(SRAVerifyError):
        selector._select(service="NoSuchService")


def test_a_failed_selection_leaves_the_registry_untouched(selector, registered):
    before = dict(registry.all_checks())

    with pytest.raises(NoChecksSelectedError):
        selector._select(service="NoSuchService")
    with pytest.raises(UnknownCheckError):
        selector._select(check_id="SRA-NOSUCH-01")

    assert dict(registry.all_checks()) == before


# --------------------------------------------------------------------------
# Nothing is instantiated (Requirement 9.1)
# --------------------------------------------------------------------------

def test_selection_across_the_whole_matrix_instantiates_nothing(
    selector, registered, no_instantiation
):
    # Every successful shape plus both error paths, under one spy. Metadata is
    # a ClassVar, so there is never a reason to build an instance to read it --
    # and building one is how a scan starts touching AWS.
    selector._select()
    selector._select(account_type="application")
    selector._select(account_type="audit", service="GuardDuty")
    selector._select(service="  security hub  ")
    selector._select(check_id="SRA-TESTGD-01")
    selector._select(
        account_type="application", service="GuardDuty", check_id="SRA-TESTGD-01"
    )

    with pytest.raises(UnknownCheckError):
        selector._select(check_id="SRA-NOSUCH-01")
    with pytest.raises(NoChecksSelectedError):
        selector._select(account_type="management", check_id="SRA-TESTGD-01")
    with pytest.raises(NoChecksSelectedError):
        selector._select(service="Security")

    assert no_instantiation == []


def test_the_spy_would_notice_a_construction(registered, no_instantiation):
    # Guards against the test above passing because the spy is misinstalled:
    # the synthetic classes are concrete, so this really does construct one.
    registered["SRA-TESTGD-01"]()

    assert no_instantiation == [registered["SRA-TESTGD-01"]]
