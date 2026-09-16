"""Catalog-wide property test for declared, validated check metadata (task 17.3).

This module implements **Property 4: every registered check declares a
validated ``meta``**, as the design states it:

    One walk over the registry asserting, for every registered ``cls``:

    * ``"meta" in vars(cls)`` -- the class declares its own ``CheckMeta``
      rather than inheriting one, which is the run-time face of the 4.16 rule
      and of the decision to key eligibility on the module file name rather
      than on the presence of ``meta``.
    * ``cls.meta`` is a ``CheckMeta``, assignment to any of its fields raises,
      ``hash(cls.meta)`` succeeds, and no field holds a ``list``, a ``dict``,
      or a ``set`` -- the deep-immutability half of 2.4.
    * ``cls.meta`` compares equal to itself across two ``run_checks`` calls
      made under different accounts and different region lists, which is the
      observable form of 2.6.
    * No file is opened to obtain metadata, during import or during a scan
      (2.7). Asserted by patching ``builtins.open`` and ``Path.read_text``
      with a spy across ``import sraverify.services`` in a fresh interpreter
      and across a full ``run_checks``, and confirming no call whose path lies
      under ``services/``.

**Validates: Requirements 2.1, 2.4, 2.6, 2.7, 4.12, 4.16**

Why this enumerates rather than samples
---------------------------------------

The registry is a fixed finite set -- 158 entries, fully determined at import
time -- so the honest way to quantify over it is to visit every element, not to
draw from it. The two structural halves are therefore
``pytest.mark.parametrize`` over ``sorted(all_checks().items())``, computed once
at collection time, so a failure names the offending check ID in the test ID
rather than burying it in a hypothesis counterexample.

The two instrumented halves -- the twice-scanned metadata identity, and the
file spy -- are one test each, because each one runs a whole scan and running
158 of them would buy nothing.

This module reads the REAL registry
-----------------------------------

Four sibling property modules empty ``_REGISTRY`` inside a context manager for
the duration of a test and restore it afterwards, because they register
synthetic checks and a real catalog would send their scans to AWS. This module
does the opposite: it is *about* the real catalog, so it installs no such
fixture and clears nothing. ``_CATALOG`` is snapshotted at import so the
parametrization is stable, and the scan tests re-read ``all_checks()`` and
assert the live catalog still matches that snapshot -- which is also the
assertion that catches a sibling module leaking an emptied registry, in either
test-execution order.

No AWS, structurally rather than by convention
----------------------------------------------

The two scan tests run the whole 158-check catalog with no credentials and no
network:

  * ``_StubSession.client()`` returns a ``_StubClient`` whose every method
    raises ``ClientError``. Service ``client.py`` wrappers catch ``ClientError``
    and return their ``{"Error": {...}}`` error_result, so check bodies genuinely
    execute and take their FAIL-or-ERROR branches. That matters for the file
    spy: a session that merely *refused* to build a client would fail every
    check inside ``_setup_clients``, no ``execute()`` would run at all, and the
    spy would be watching an empty scan.
  * ``ctx._account_info`` is pre-seeded by the recording ``ScanContext``
    factory, so ``get_account_info()`` returns from its cache and never
    reaches STS. This is also how the two scans are given *different
    accounts*.

Anything a check raises that is not a ``ClientError`` is caught by the
orchestrator's per-check guard and becomes one synthetic ERROR row, so a scan
under stub clients completes regardless of how any individual check reacts to
a total API failure. These tests assert nothing about which rows come back --
only that the scan ran and that metadata did not move.
"""
from __future__ import annotations

import builtins
import contextlib
import dataclasses
import json
import os
import pathlib
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterator, Optional

import pytest
from botocore.exceptions import ClientError

import sraverify
import sraverify.main as main
import sraverify.services
from sraverify.core.check import SecurityCheck
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.core.registry import all_checks


# ---------------------------------------------------------------------- #
# The catalog, snapshotted at collection time.
# ---------------------------------------------------------------------- #

#: ``(check_id, cls)`` pairs in ascending check-ID order. Read once, at import,
#: so parametrized test IDs are stable and a failure names its check.
_CATALOG: list[tuple[str, type[SecurityCheck]]] = sorted(all_checks().items())

#: Directory the ``services`` package lives in. "Under ``services/``" is
#: resolved against this concrete path rather than against the bare word, so a
#: path that merely happens to contain a ``services`` component elsewhere in the
#: filesystem is not mistaken for a metadata read.
_SERVICES_ROOT: Path = Path(sraverify.services.__file__).resolve().parent

#: Parent of the ``sraverify`` package, handed to the child interpreter as
#: ``PYTHONPATH`` so the fresh-interpreter test imports *this* tree.
_PACKAGE_PARENT: Path = Path(sraverify.__file__).resolve().parent.parent

#: The container types Requirement 2.4 forbids anywhere inside a ``CheckMeta``.
#: A frozen dataclass holding a ``list`` is only shallowly frozen: the field
#: cannot be reassigned but ``meta.sra_sections.append(...)`` still mutates the
#: catalog for the rest of the process, and ``hash(meta)`` raises.
_FORBIDDEN_CONTAINERS: tuple[type, ...] = (list, dict, set)


def _catalog_ids() -> list[str]:
    """Check IDs in catalog order, used as parametrize IDs."""
    return [check_id for check_id, _ in _CATALOG]


def test_the_catalog_is_not_empty() -> None:
    """Guard against every parametrized assertion below holding vacuously.

    An empty registry would make both parametrized tests collect zero cases and
    the module would report all-green while asserting nothing. The floor is
    deliberately loose -- this module is not the place that pins the catalog
    size -- but it is not zero and not one.
    """
    assert len(_CATALOG) >= 100, (
        f"the registry holds {len(_CATALOG)} checks; Property 4 quantifies over "
        f"the real catalog and something has emptied or truncated it"
    )


# ---------------------------------------------------------------------- #
# Half 1 -- the class declares its OWN meta (2.1, 4.12, 4.16).
# ---------------------------------------------------------------------- #

@pytest.mark.parametrize("check_id,cls", _CATALOG, ids=_catalog_ids())
def test_registered_check_declares_its_own_meta(
    check_id: str, cls: type[SecurityCheck]
) -> None:
    """Property 4a: ``"meta" in vars(cls)`` for every registered check.

    ``vars(cls)``, not ``getattr(cls, "meta")``. The distinction is the whole
    point: ``getattr`` walks the MRO, so a check that declared no metadata of
    its own would happily answer with a *sibling's* or a base class's ``meta``
    and register under a check ID it does not own. Requirement 4.16 makes that
    an import failure, and this is the run-time face of the same rule -- and of
    the decision behind it (4.12), which keys registration eligibility on the
    module file name rather than on the presence of ``meta``, precisely so that
    "not a check" and "a check whose author forgot the metadata" cannot share a
    code path.

    Validates: Requirements 2.1, 4.12, 4.16
    """
    assert "meta" in vars(cls), (
        f"{check_id}: {cls.__module__}.{cls.__name__} declares no `meta` of its "
        f"own; it is answering with an inherited one from "
        f"{[k.__name__ for k in cls.__mro__[1:] if 'meta' in vars(k)]} "
        f"(Requirements 2.1, 4.16)"
    )
    declared = vars(cls)["meta"]
    # The attribute lookup and the class-body declaration must be the same
    # object, so every other assertion in this module -- all of which read
    # ``cls.meta`` -- is reading what the class body actually declared.
    assert cls.meta is declared, (
        f"{check_id}: cls.meta is not the CheckMeta declared in the class body"
    )
    # And the registry key is the identity the metadata claims. Property 1
    # covers the full four-way identity; this narrow half is here so that a
    # failure in *this* module cannot be about a mismatched key.
    assert declared.check_id == check_id, (
        f"registry key {check_id!r} disagrees with declared "
        f"meta.check_id {declared.check_id!r}"
    )


# ---------------------------------------------------------------------- #
# Half 2 -- the metadata is a deeply immutable, hashable CheckMeta (2.4).
# ---------------------------------------------------------------------- #

def _nested_values(meta: CheckMeta) -> list[tuple[str, Any]]:
    """Every value reachable inside *meta*, paired with a dotted field path.

    Walks the ``CheckMeta`` fields, then into ``remediation``'s three fields,
    then into each element of every tuple-valued field. Requirement 2.4 is
    about the *whole* value, not its top level: a ``tuple`` holding a ``list``
    is unhashable and shallowly frozen just as surely as a ``list`` field is,
    and ``remediation`` is the one field whose contents a top-level walk would
    never see.

    Args:
        meta: The metadata to walk.

    Returns:
        ``(path, value)`` pairs, e.g. ``("remediation.cli", "aws ...")`` and
        ``("sra_sections[0]", "...")``.
    """
    found: list[tuple[str, Any]] = []
    for field in dataclasses.fields(meta):
        value = getattr(meta, field.name)
        found.append((field.name, value))
        if isinstance(value, Remediation):
            for inner in dataclasses.fields(value):
                found.append(
                    (f"{field.name}.{inner.name}", getattr(value, inner.name))
                )
        elif isinstance(value, tuple):
            for index, element in enumerate(value):
                found.append((f"{field.name}[{index}]", element))
    return found


@pytest.mark.parametrize("check_id,cls", _CATALOG, ids=_catalog_ids())
def test_registered_meta_is_deeply_immutable_and_hashable(
    check_id: str, cls: type[SecurityCheck]
) -> None:
    """Property 4b: a real ``CheckMeta``, frozen through, and hashable.

    Four assertions, each catching a different way the same requirement fails:

      * the value is a ``CheckMeta`` -- not a ``dict``, a ``SimpleNamespace``,
        or a look-alike that happens to expose the right attribute names and
        would sail through every reader in the codebase;
      * assignment to any field of the ``CheckMeta``, and to any field of its
        ``Remediation``, raises;
      * ``hash(meta)`` succeeds, which is the single cheapest proof that
        nothing unhashable is nested anywhere inside it;
      * no ``list``, ``dict``, or ``set`` appears at any depth. Kept alongside
        the hash assertion rather than replaced by it, because the hash says
        only that *something* is wrong while this one names the field.

    Validates: Requirements 2.4
    """
    meta = cls.meta
    assert isinstance(meta, CheckMeta), (
        f"{check_id}: meta is {type(meta).__name__}, not a CheckMeta. Every "
        f"reader -- _select, the finding helpers, _synthetic_error, "
        f"--list-checks -- would still work against a look-alike, and none of "
        f"the validation rules would have run (Requirement 2.4)"
    )

    # ---- Assignment raises, on the CheckMeta and on the Remediation ---- #
    # dataclasses.FrozenInstanceError subclasses AttributeError, so accepting
    # either keeps this honest about *what* is being asserted -- that the
    # assignment does not take effect -- without pinning the exception class of
    # a slotted frozen dataclass.
    for field in dataclasses.fields(meta):
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            setattr(meta, field.name, getattr(meta, field.name))
    for field in dataclasses.fields(meta.remediation):
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            setattr(
                meta.remediation, field.name, getattr(meta.remediation, field.name)
            )

    # ---- Hashable, and stable across calls ---------------------------- #
    try:
        digest = hash(meta)
    except TypeError as exc:
        pytest.fail(
            f"{check_id}: hash(cls.meta) raised {exc}. A CheckMeta must be "
            f"hashable, which fails the moment any field -- at any depth -- "
            f"holds a mutable container (Requirement 2.4)"
        )
    assert hash(meta) == digest, f"{check_id}: hash(cls.meta) is not stable"

    # ---- Nothing mutable at any depth --------------------------------- #
    offenders = [
        (path, type(value).__name__)
        for path, value in _nested_values(meta)
        if isinstance(value, _FORBIDDEN_CONTAINERS)
    ]
    assert not offenders, (
        f"{check_id}: metadata holds mutable container(s) {offenders}. A frozen "
        f"dataclass holding a list is only shallowly frozen -- the field cannot "
        f"be reassigned, but its contents can be mutated for the rest of the "
        f"process, and every scan afterwards sees the change "
        f"(Requirement 2.4). Declare sequences as tuples"
    )


# ---------------------------------------------------------------------- #
# Scan instrumentation: a session that reaches no AWS, an account the test
# chooses, and a spy over file reads.
# ---------------------------------------------------------------------- #

class _StubClient:
    """A boto3 client stand-in whose every operation raises ``ClientError``.

    Chosen over a client that refuses to exist. Service ``client.py`` wrappers
    catch ``ClientError`` and return their ``{"Error": {...}}`` error_result, so
    check bodies run to completion and take a real branch. A session that
    refused to build a client at all would fail every check inside
    ``_setup_clients``, no ``execute()`` would ever run, and the file spy below
    would be watching a scan in which no check code executed.

    ``AccessDeniedException`` specifically: it is the code the checks are least
    likely to interpret as "the control is absent", so a stubbed scan does not
    quietly look like a real FAIL-everywhere scan.
    """

    def __init__(self, service_name: str, region: Optional[str]) -> None:
        self._service_name = service_name
        self._region = region

    def __getattr__(self, name: str) -> Any:
        """Return a callable that raises, whatever operation was asked for."""
        def _refuse(*args: Any, **kwargs: Any) -> Any:
            raise ClientError(
                {
                    "Error": {
                        "Code": "AccessDeniedException",
                        "Message": (
                            f"stubbed {self._service_name}.{name} in "
                            f"{self._region}: this test issues no AWS call"
                        ),
                    }
                },
                name,
            )

        return _refuse


class _StubSession:
    """A ``boto3.Session`` stand-in handing out :class:`_StubClient`.

    ``ScanContext`` stores whatever session it is given and touches it only
    inside ``get_client``, so this is the whole surface a scan needs. Nothing
    here can reach the network or read ambient credentials.
    """

    def client(self, service_name: str, region_name: Optional[str] = None,
               config: Any = None, **kwargs: Any) -> _StubClient:
        """Return a stub client for the requested service and region."""
        return _StubClient(service_name, region_name)


@contextlib.contextmanager
def _seeded_scan_context(account_id: str, account_name: str) -> Iterator[list[Any]]:
    """Patch ``main.ScanContext`` so every context it builds knows its account.

    ``ScanContext.get_account_info()`` checks ``_account_info`` first and
    returns it on a hit, so pre-seeding is what keeps a full scan away from STS
    and the Account API. It is also how the two scans in the test below are
    given *different* accounts, which is the variable Requirement 2.6 is about.

    The real class is still what gets constructed -- only the name in ``main``
    is rebound -- so the scan exercises a genuine ``ScanContext``.

    Args:
        account_id: Value ``get_account_info()`` should report.
        account_name: Value ``get_account_info()`` should report.

    Yields:
        The list of contexts constructed inside the block, so a caller can
        assert exactly one scan happened.
    """
    original = main.ScanContext
    built: list[Any] = []

    def factory(**kwargs: Any) -> Any:
        ctx = original(**kwargs)
        ctx._account_info = {
            "account_id": account_id,
            "account_name": account_name,
        }
        built.append(ctx)
        return ctx

    main.ScanContext = factory
    try:
        yield built
    finally:
        main.ScanContext = original


@contextlib.contextmanager
def _initialize_counter() -> Iterator[list[str]]:
    """Record every check that reached ``initialize(ctx)``.

    Non-vacuity instrumentation for both scan tests. Without it, a scan that
    selected nothing, or one in which every check died during construction,
    would satisfy every assertion below -- the metadata would not have moved
    and no file would have been opened, for the uninteresting reason that
    almost no check code ran.

    Yields:
        The list of check IDs, appended to in execution order.
    """
    original = SecurityCheck.initialize
    seen: list[str] = []

    def wrapper(self: SecurityCheck, ctx: Any) -> Any:
        seen.append(type(self).meta.check_id)
        return original(self, ctx)

    SecurityCheck.initialize = wrapper  # type: ignore[method-assign]
    try:
        yield seen
    finally:
        SecurityCheck.initialize = original  # type: ignore[method-assign]


@contextlib.contextmanager
def _file_read_spy() -> Iterator[list[str]]:
    """Record the path of every ``builtins.open`` and ``Path.read_text`` call.

    The two entry points the design names. Deliberately *not* an audit hook or
    a patch of the import machinery: module source is loaded through
    ``io.open_code`` and a raw ``FileIO``, not through ``builtins.open``, so
    importing the catalog does not register here and the spy sees only
    deliberate file reads -- which is exactly the thing Requirement 2.7
    forbids. ``test_no_file_is_read_to_obtain_metadata_during_a_scan``
    demonstrates the spy is live by reading a file under ``services/`` on
    purpose once the scan is over.

    Yields:
        The recorded paths, as strings, in call order.
    """
    recorded: list[str] = []
    real_open = builtins.open
    real_read_text = pathlib.Path.read_text

    def spy_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        # An int is a file descriptor and carries no path to attribute.
        if not isinstance(file, int):
            try:
                recorded.append(os.fspath(file))
            except TypeError:  # pragma: no cover - exotic file-like argument
                pass
        return real_open(file, *args, **kwargs)

    def spy_read_text(self: pathlib.Path, *args: Any, **kwargs: Any) -> str:
        recorded.append(os.fspath(self))
        return real_read_text(self, *args, **kwargs)

    builtins.open = spy_open  # type: ignore[assignment]
    pathlib.Path.read_text = spy_read_text  # type: ignore[method-assign]
    try:
        yield recorded
    finally:
        builtins.open = real_open  # type: ignore[assignment]
        pathlib.Path.read_text = real_read_text  # type: ignore[method-assign]


def _under_services(path: str) -> bool:
    """Whether *path* lies inside the ``sraverify/services`` tree."""
    try:
        resolved = Path(path).resolve()
    except OSError:  # pragma: no cover - unresolvable path
        return False
    return resolved == _SERVICES_ROOT or _SERVICES_ROOT in resolved.parents


def _assert_live_catalog_matches_snapshot() -> None:
    """Fail with a pointed message if a sibling module leaked an empty registry.

    Four sibling property modules empty ``_REGISTRY`` for the duration of a
    test and restore it in a ``finally``. If one ever fails to restore it, the
    scans below would select nothing and raise ``NoChecksSelectedError`` --
    a confusing failure in *this* module for a defect in another. Checking the
    live catalog against the collection-time snapshot first turns that into a
    message that names the actual cause, and makes this module's result
    independent of test-execution order.
    """
    live = dict(all_checks())
    expected = dict(_CATALOG)
    assert live == expected, (
        f"the live registry ({len(live)} checks) no longer matches the "
        f"collection-time snapshot ({len(expected)} checks). A sibling property "
        f"module that empties _REGISTRY inside a context manager has failed to "
        f"restore it; this module reads the real catalog and installs no such "
        f"fixture. Missing: {sorted(set(expected) - set(live))[:5]}"
    )


def _metadata_snapshot() -> dict[str, tuple[int, tuple[Any, ...]]]:
    """Per check ID, the identity of its ``meta`` and every field value.

    The identity half is what the assertion actually turns on; the values are
    carried so that a failure can say *which* field moved rather than only that
    the object did.

    Returns:
        ``check_id -> (id(meta), (path, value) pairs flattened)``.
    """
    snapshot: dict[str, tuple[int, tuple[Any, ...]]] = {}
    for check_id, cls in all_checks().items():
        meta = cls.meta
        snapshot[check_id] = (id(meta), tuple(_nested_values(meta)))
    return snapshot


def _scan(account_id: str, account_name: str, regions: list[str],
          audit_accounts: list[str], log_archive_accounts: list[str],
          ) -> tuple[list[Finding], list[str]]:
    """Run the whole catalog once, against stub clients, in a named account.

    Args:
        account_id: Seeded into the context, so every row is attributed to it.
        account_name: Seeded into the context.
        regions: Passed explicitly, so no lazy ``ec2:DescribeRegions`` runs.
        audit_accounts: Reaches checks through ``ctx``.
        log_archive_accounts: Reaches checks through ``ctx``.

    Returns:
        The findings, and the check IDs that reached ``initialize(ctx)``.
    """
    sra = main.SRAVerify(session=_StubSession(), regions=list(regions))
    with _seeded_scan_context(account_id, account_name) as contexts, \
            _initialize_counter() as initialized:
        findings = sra.run_checks(
            account_type="all",
            service=None,
            check_id=None,
            audit_accounts=list(audit_accounts),
            log_archive_accounts=list(log_archive_accounts),
            show_progress=False,
        )
    assert len(contexts) == 1, (
        f"expected exactly one ScanContext per run_checks call, got "
        f"{len(contexts)}"
    )
    return findings, initialized


#: The two invocations. Every variable Requirement 2.6 mentions differs between
#: them -- the account identity, the region list and its length, and the audit
#: and log-archive account lists -- so a metadata value derived from any of them
#: would move.
_SCAN_A = {
    "account_id": "111122223333",
    "account_name": "probe-account-a",
    "regions": ["us-east-1"],
    "audit_accounts": ["444455556666"],
    "log_archive_accounts": ["777788889999"],
}
_SCAN_B = {
    "account_id": "999988887777",
    "account_name": "probe-account-b",
    "regions": ["eu-west-1", "ap-southeast-2"],
    "audit_accounts": [],
    "log_archive_accounts": ["222233334444", "555566667777"],
}


# ---------------------------------------------------------------------- #
# Half 3 -- metadata does not move across two differing scans (2.6).
# ---------------------------------------------------------------------- #

def test_metadata_is_identical_across_two_scans_of_different_accounts() -> None:
    """Property 4c: ``cls.meta`` survives two differing scans unchanged.

    Requirement 2.6 says a ``CheckMeta`` carries only values written literally
    in its check module, so nothing derived from an AWS response and nothing
    derived from the invocation can enter it, and *two scans in one process
    necessarily observe identical metadata for a given check*. That "in one
    process" is the point: this is the requirement the long-running MCP server
    depends on, and it is unobservable from a single scan.

    **Object identity is asserted, not merely equality.** ``meta`` is a
    ``ClassVar`` bound once while the check module's class body executed, so
    the correct implementation cannot produce a second equal object -- there is
    nowhere for one to come from. Equality alone would be satisfied by a scan
    that rebuilt an identical ``CheckMeta`` each time, which is precisely the
    "metadata as imperative per-instance state" shape this change removed and
    which would reintroduce a per-scan code path where an invocation-derived
    value could enter. Identity rejects that; equality would not. Value
    equality is asserted too, immediately afterwards, because it is the form
    the requirement is written in and because it is what names the field that
    moved when the identity assertion is what fails first.

    Validates: Requirements 2.6
    """
    _assert_live_catalog_matches_snapshot()

    before = _metadata_snapshot()

    findings_a, initialized_a = _scan(**_SCAN_A)  # type: ignore[arg-type]
    after_first = _metadata_snapshot()

    findings_b, initialized_b = _scan(**_SCAN_B)  # type: ignore[arg-type]
    after_second = _metadata_snapshot()

    # ---- Both scans really ran ---------------------------------------- #
    # Otherwise every assertion below holds because nothing happened.
    for label, findings, initialized in (
        ("A", findings_a, initialized_a),
        ("B", findings_b, initialized_b),
    ):
        assert type(findings) is list
        assert initialized, (
            f"scan {label} initialized no check at all; the metadata "
            f"assertions below would hold vacuously"
        )
        assert len(initialized) == len(_CATALOG), (
            f"scan {label} initialized {len(initialized)} of {len(_CATALOG)} "
            f"checks; account_type='all' should reach every one"
        )
        assert findings, f"scan {label} produced no findings at all"
        assert all(isinstance(f, Finding) for f in findings)

    # ---- The two scans genuinely differed ----------------------------- #
    # The variables Requirement 2.6 is about have to actually vary, and the
    # findings are where that is observable.
    assert {f.account_id for f in findings_a} == {_SCAN_A["account_id"]}
    assert {f.account_id for f in findings_b} == {_SCAN_B["account_id"]}
    assert _SCAN_A["account_id"] != _SCAN_B["account_id"]
    assert _SCAN_A["regions"] != _SCAN_B["regions"]

    # ---- The metadata did not move ------------------------------------ #
    assert set(after_second) == set(before), (
        f"the catalog changed shape across the scans; added "
        f"{sorted(set(after_second) - set(before))}, removed "
        f"{sorted(set(before) - set(after_second))}"
    )

    for check_id in sorted(before):
        first_id, first_values = before[check_id]
        mid_id, mid_values = after_first[check_id]
        last_id, last_values = after_second[check_id]

        assert first_id == mid_id == last_id, (
            f"{check_id}: cls.meta is a different object after a scan "
            f"(before={first_id}, after scan A={mid_id}, after scan B="
            f"{last_id}). `meta` is a ClassVar bound once while the check "
            f"module's class body executed, so a rebound or rebuilt CheckMeta "
            f"means a scan-time code path is producing metadata -- which is "
            f"where a value derived from the account, the region list, or an "
            f"AWS response gets in (Requirement 2.6)"
        )

        moved = [
            (path, before_value, after_value)
            for (path, before_value), (_, after_value)
            in zip(first_values, last_values)
            if before_value != after_value
        ]
        assert not moved, (
            f"{check_id}: metadata values changed across two scans run under "
            f"different accounts and region lists: {moved} (Requirement 2.6)"
        )
        assert first_values == mid_values == last_values


# ---------------------------------------------------------------------- #
# Half 4 -- no file is read to obtain metadata (2.7).
# ---------------------------------------------------------------------- #

def test_no_file_is_read_to_obtain_metadata_during_a_scan() -> None:
    """Property 4d, scan half: a full scan opens no file under ``services/``.

    Requirement 2.7 says the scanner reads no file at run time to obtain check
    metadata. Metadata is a literal in a class body, so the correct
    implementation has nothing to read -- and that is the property: the absence
    of a YAML, JSON, or CSV catalog beside the code, and of the loader, the
    schema, the caching, and the "which file wins" ambiguity that come with
    one.

    The spy is proven live at the end of the same patched block by reading a
    file under ``services/`` deliberately. Without that control this test would
    keep passing if the patch ever silently stopped taking effect.

    Validates: Requirements 2.7
    """
    _assert_live_catalog_matches_snapshot()

    with _file_read_spy() as recorded:
        sra = main.SRAVerify(
            session=_StubSession(), regions=list(_SCAN_A["regions"])
        )
        with _seeded_scan_context(
            str(_SCAN_A["account_id"]), str(_SCAN_A["account_name"])
        ), _initialize_counter() as initialized:
            findings = sra.run_checks(
                account_type="all",
                service=None,
                check_id=None,
                show_progress=False,
            )
        during_scan = list(recorded)

        # Control: the spy must be capable of seeing a read under services/.
        control = _SERVICES_ROOT / "__init__.py"
        control.read_text(encoding="utf-8")
        with open(control, "rb") as handle:
            handle.read(1)
        after_control = recorded[len(during_scan):]

    assert initialized and findings, (
        "the scan initialized no check or produced no finding, so the spy "
        "watched nothing and this assertion would be vacuous"
    )

    offenders = sorted({path for path in during_scan if _under_services(path)})
    assert not offenders, (
        f"a scan opened {len(offenders)} file(s) under {_SERVICES_ROOT}: "
        f"{offenders}. Requirement 2.7 admits no run-time file read for check "
        f"metadata -- metadata is a literal in the check's class body, so "
        f"there is nothing to load"
    )

    assert [path for path in after_control if _under_services(path)], (
        f"the file spy recorded nothing for a deliberate read of {control}, so "
        f"the assertion above proved nothing. builtins.open or "
        f"pathlib.Path.read_text is no longer the path a file read takes"
    )


#: Runs in a fresh interpreter. ``sraverify.services`` is already in
#: ``sys.modules`` by the time this module is collected, so a second import in
#: this process is a no-op from ``sys.modules`` and would observe nothing --
#: the import half is only testable in a process that has not imported it yet.
#: Passed via ``-c`` as a single argv element, so no shell quoting is involved.
_CHILD_IMPORT_SPY = r'''
import builtins
import json
import os
import pathlib
import sys

recorded = []
real_open = builtins.open
real_read_text = pathlib.Path.read_text


def spy_open(file, *args, **kwargs):
    if not isinstance(file, int):
        try:
            recorded.append(os.fspath(file))
        except TypeError:
            pass
    return real_open(file, *args, **kwargs)


def spy_read_text(self, *args, **kwargs):
    recorded.append(os.fspath(self))
    return real_read_text(self, *args, **kwargs)


builtins.open = spy_open
pathlib.Path.read_text = spy_read_text

# The import under test: this is what walks 18 service packages and executes
# 158 check class bodies, each constructing and validating a CheckMeta.
import sraverify.services
from sraverify.core.registry import all_checks

registry_size = len(all_checks())
services_root = os.path.dirname(os.path.abspath(sraverify.services.__file__))
during_import = list(recorded)

# Control: prove the spy can see a read under services/ at all.
marker = os.path.join(services_root, "__init__.py")
pathlib.Path(marker).read_text(encoding="utf-8")
with open(marker, "rb") as handle:
    handle.read(1)
after_control = recorded[len(during_import):]

builtins.open = real_open
pathlib.Path.read_text = real_read_text


def under(path):
    try:
        absolute = os.path.abspath(path)
    except Exception:
        return False
    return absolute == services_root or absolute.startswith(services_root + os.sep)


payload = {
    "services_root": services_root,
    "registry_size": registry_size,
    "recorded_during_import": len(during_import),
    "offenders": sorted({p for p in during_import if under(p)}),
    "control_recorded": sorted({p for p in after_control if under(p)}),
}
sys.stdout.write("SRAVERIFY_SPY_JSON:" + json.dumps(payload) + "\n")
'''


def test_no_file_is_read_to_obtain_metadata_during_import() -> None:
    """Property 4d, import half: importing the catalog opens no ``services/`` file.

    Run in a **fresh interpreter**, which is the only honest way to test this:
    ``sraverify.services`` is in ``sys.modules`` before this module is even
    collected, so re-importing it here returns the cached module and executes
    no class body. A subprocess is the difference between asserting something
    and asserting nothing.

    The child reports the registry size it built, which is checked against this
    process's catalog: that is what confirms the child actually imported all 158
    check modules rather than failing early into an empty catalog. The child
    also proves its own spy live before reporting.

    Validates: Requirements 2.7
    """
    env = dict(os.environ)
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        f"{_PACKAGE_PARENT}{os.pathsep}{existing}" if existing
        else str(_PACKAGE_PARENT)
    )
    # Importing the catalog issues no AWS call, but a stray credential lookup
    # in an unrelated import should not be able to reach IMDS and stall the
    # child until its timeout.
    env["AWS_EC2_METADATA_DISABLED"] = "true"

    completed = subprocess.run(
        [sys.executable, "-c", _CHILD_IMPORT_SPY],
        capture_output=True,
        text=True,
        env=env,
        timeout=180,
        check=False,
    )
    assert completed.returncode == 0, (
        f"the fresh interpreter failed to import the catalog under the file "
        f"spy (exit {completed.returncode}).\n"
        f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
    )

    marker = "SRAVERIFY_SPY_JSON:"
    lines = [
        line for line in completed.stdout.splitlines() if line.startswith(marker)
    ]
    assert len(lines) == 1, (
        f"expected one {marker} line from the child, got {len(lines)}.\n"
        f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
    )
    payload = json.loads(lines[0][len(marker):])

    assert payload["registry_size"] == len(_CATALOG), (
        f"the fresh interpreter registered {payload['registry_size']} checks "
        f"but this process holds {len(_CATALOG)}; the child did not import the "
        f"same catalog, so its result says nothing about ours"
    )

    assert not payload["offenders"], (
        f"importing sraverify.services opened {len(payload['offenders'])} "
        f"file(s) under {payload['services_root']}: {payload['offenders']}. "
        f"Requirement 2.7 admits no file read for check metadata; a CheckMeta "
        f"is a literal in the check's own class body"
    )

    assert payload["control_recorded"], (
        f"the child's spy recorded nothing for a deliberate read under "
        f"{payload['services_root']}, so its result proved nothing "
        f"({payload['recorded_during_import']} paths were recorded during the "
        f"import itself)"
    )
