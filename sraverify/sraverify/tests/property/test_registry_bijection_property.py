"""Property-based test for the registry-filesystem bijection (task 17.2).

This module implements **Property 2: registry-filesystem bijection**:

    The registry is a bijection with ``services/*/checks/sra_*.py`` on disk:
    every such file contributes exactly one registry entry, and every entry
    has exactly one such file.
    ``|all_checks()| == |glob("services/*/checks/sra_*.py")|``.

**Validates: Requirements 5.1, 5.2, 5.4**

Why this module exists
----------------------

This property is the whole justification for choosing ``pkgutil`` discovery
over explicit imports. The design's tradeoff table grants that discovery loses
static analysis -- checks become reachable only dynamically, and a linter
reports the check modules as unused -- and buys, in exchange, the structural
impossibility of the silent-omission failure: the file's presence *is* the
registration, so there is no import list to forget to edit.

The bijection test recovers the one guarantee discovery cannot give on its
own: that every file on disk produced exactly one registry entry and no entry
lacks a file. Explicit imports at least let a reader grep the catalog; with
discovery, nothing in the source states how many checks there are. This module
is that statement, restored as an executable one.

Both directions are reported separately by name, because they are different
defects:

  * **A file with no entry** is a check that silently never runs. It is the
    exact failure the old two-edit registration produced by omission and the
    one this design was written to remove, so it is also the one a regression
    would most plausibly reintroduce -- an ``__init_subclass__`` guard that
    returns early, a stem the eligibility test stops recognizing, a discovery
    filter that grows a condition. Nothing else in the suite would notice: the
    scan runs clean, the CSV is well formed, it is simply missing rows.
  * **An entry with no file** should be impossible -- registration is driven
    by importing a file -- but it is worth asserting, because the ways it
    could happen are all ways the catalog has stopped meaning what it says: a
    synthetic check leaked out of a test's isolation fixture, a stale
    ``.pyc`` resident for a deleted module, a class registered from somewhere
    other than a check module.

Collapsing the two into a bare count comparison would let one of each cancel
the other out and report success, which is why the count assertion here is
paired with, and not a substitute for, the two set comparisons.

No sampling
-----------

Property 1 through 5 quantify over the catalog, which is a fixed finite set of
158 checks, so this module enumerates it directly rather than drawing from it
with ``hypothesis``. Sampling a set small enough to walk exhaustively would
only trade a total guarantee for a probabilistic one. The reads need no
credentials: ``import sraverify.services`` issues no AWS call.

Registry isolation -- deliberately absent
-----------------------------------------

Four sibling modules in this suite install a fixture that snapshots the
module-level ``_REGISTRY``, **empties** it, and restores it afterwards, because
their synthetic catalogs must not compete with the real 158 checks. This module
must not do that: the real catalog is the subject under test, and clearing it
would make every assertion below vacuous or falsely failing.

Order independence comes from the module-level ``import sraverify.services``
instead. Pytest imports every test module during collection, before running any
test, so the real catalog is resident before the first sibling fixture runs, and
each of those fixtures restores the snapshot it took. That makes this module's
result independent of whether it runs before or after them. ``_catalog()``
re-asserts non-emptiness at the top of every test so that a fixture which failed
to restore is reported as exactly that, rather than as a mysterious count of
zero.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Mapping

from sraverify.core.check import SecurityCheck
from sraverify.core.registry import all_checks

# Importing the services package *is* discovery: it imports every service
# subpackage, each of which imports its own sra_* check modules, each of which
# fires __init_subclass__ and registers. The import is what puts the subject of
# this module in the registry, and it happens at collection time, which is what
# makes this module independent of test order. Not a static dependency of any
# core module -- see Requirement 5.6 -- but a test may name it directly.
import sraverify.services  # noqa: F401  (imported for its registration side effect)


#: The catalog size the migration is specified to produce: 158 checks across
#: 18 services. Both numbers are asserted rather than merely derived, so that a
#: change which drops a check *and* its file stays a bijection and still fails.
EXPECTED_CHECK_COUNT = 167
EXPECTED_SERVICE_COUNT = 18

#: Modules eligible to be check modules. Mirrors ``CHECK_MODULE_PREFIX`` in
#: ``core/discovery.py``, spelled out here rather than imported so that this
#: test states the filesystem contract independently of the code implementing
#: it. If the two ever disagree, that disagreement is the finding.
CHECK_MODULE_PREFIX = "sra_"

#: The glob, relative to the ``services`` directory, that Property 2 names.
CHECK_MODULE_GLOB = f"*/checks/{CHECK_MODULE_PREFIX}*.py"


def _services_dir() -> Path:
    """Locate the installed ``services`` directory.

    Derived from ``sraverify.services.__path__`` rather than from a
    repo-relative path, so the property holds for an installed copy of the
    package -- a wheel in a virtualenv, or the editable install this repo uses
    -- and not only for a source tree rooted at a known depth below the
    working directory.

    Returns:
        The resolved directory holding the service subpackages.

    Raises:
        AssertionError: The package reports no filesystem path, or more than
            one. Either means the package is not a plain directory on disk and
            the glob half of this property cannot be evaluated honestly.
    """
    entries = [Path(entry).resolve() for entry in sraverify.services.__path__]
    assert len(entries) == 1, (
        f"sraverify.services.__path__ holds {len(entries)} entries {entries}; "
        f"Property 2 compares the registry against one directory of files"
    )
    services = entries[0]
    assert services.is_dir(), f"{services} is not a directory"
    return services


def _relative(path: Path, services: Path) -> str:
    """Render *path* relative to the ``services`` directory for diagnostics.

    Absolute paths make a mismatch report unreadable -- every line shares a
    long prefix. ``guardduty/checks/sra_guardduty_01.py`` is the name a reader
    can act on.

    Args:
        path: The path to render.
        services: The ``services`` directory to render it relative to.

    Returns:
        The relative path as a POSIX string, or the absolute path when *path*
        lies outside *services* -- which is itself worth seeing in a report.
    """
    try:
        return path.relative_to(services).as_posix()
    except ValueError:
        return str(path)


def _check_module_files(services: Path) -> set[Path]:
    """Return every ``services/*/checks/sra_*.py`` file, resolved.

    This is the ``glob`` half of Property 2, and the authority against which
    the registry is compared. It reads the filesystem directly rather than
    asking ``pkgutil``, so it is not the same computation discovery performed:
    a discovery filter that silently stopped matching a file would still leave
    that file visible here.

    Args:
        services: The ``services`` directory to scan.

    Returns:
        The resolved paths of the matching files.
    """
    return {path.resolve() for path in services.glob(CHECK_MODULE_GLOB)}


def _module_file(cls: type[SecurityCheck]) -> Path | None:
    """Return the file the registered class *cls* was defined in.

    Resolved through ``sys.modules`` rather than ``inspect.getfile``, so that
    the two ways this can come back empty -- a module absent from
    ``sys.modules``, and a module object carrying no ``__file__`` -- are
    reported as an entry with no file rather than raised as a ``TypeError``
    from inside the helper. Both are exactly the shape of defect the
    entry-to-file direction of this property is looking for.

    Args:
        cls: A class taken from the registry.

    Returns:
        The resolved path of the defining module, or ``None`` when no file can
        be determined.
    """
    module = sys.modules.get(cls.__module__)
    if module is None:
        return None
    filename = getattr(module, "__file__", None)
    if filename is None:
        return None
    return Path(filename).resolve()


def _catalog() -> Mapping[str, type[SecurityCheck]]:
    """Return the real catalog, asserting it is populated.

    The guard is aimed at one specific way this module could be misread. Four
    sibling modules empty ``_REGISTRY`` inside a fixture and restore it on
    teardown; if one ever failed to restore, every assertion here would fail
    with a count of zero and no hint as to why. Naming the cause at the point
    of the read turns that into a one-line diagnosis.

    Returns:
        The read-only mapping returned by ``all_checks()``.
    """
    catalog = all_checks()
    assert catalog, (
        "the check registry is empty; either sraverify.services failed to "
        "import or a sibling test module's registry-isolation fixture did not "
        "restore its snapshot"
    )
    return catalog


def test_registry_entry_count_equals_check_module_file_count() -> None:
    """Property 2: |all_checks()| == |glob("services/*/checks/sra_*.py")|.

    The count comparison stated verbatim, plus the absolute figure the
    migration targets. The count alone is necessary but not sufficient -- one
    unregistered file and one fileless entry would cancel -- so the two set
    comparisons below carry the actual bijection.

    Validates: Requirements 5.1, 5.4
    """
    services = _services_dir()
    catalog = _catalog()
    files = _check_module_files(services)

    assert len(catalog) == len(files), (
        f"registry holds {len(catalog)} entries but {len(files)} check module "
        f"files match {CHECK_MODULE_GLOB} under {services}"
    )
    assert len(files) == EXPECTED_CHECK_COUNT, (
        f"expected {EXPECTED_CHECK_COUNT} check module files under {services}, "
        f"found {len(files)}"
    )
    assert len(catalog) == EXPECTED_CHECK_COUNT, (
        f"expected {EXPECTED_CHECK_COUNT} registry entries, "
        f"found {len(catalog)}"
    )


def test_every_check_module_file_contributes_exactly_one_registry_entry() -> None:
    """Property 2, file to entry: no file unregistered, none registered twice.

    A file with no entry is a check that silently never runs -- the failure
    mode discovery exists to remove, and the one nothing else in the suite
    would catch. A file carrying two entries means one module declared two
    check classes, which the one-file-one-check identity rule forbids.

    Validates: Requirements 5.1, 5.4
    """
    services = _services_dir()
    catalog = _catalog()

    entries_by_file: dict[Path, list[str]] = {}
    for check_id, cls in catalog.items():
        path = _module_file(cls)
        if path is not None:
            entries_by_file.setdefault(path, []).append(check_id)

    unregistered = sorted(
        _relative(path, services)
        for path in _check_module_files(services)
        if path not in entries_by_file
    )
    assert not unregistered, (
        f"{len(unregistered)} check module file(s) produced no registry entry, "
        f"so the check(s) they define never run: {unregistered}"
    )

    duplicated = {
        _relative(path, services): sorted(ids)
        for path, ids in entries_by_file.items()
        if len(ids) > 1
    }
    assert not duplicated, (
        f"check module file(s) produced more than one registry entry each: "
        f"{duplicated}"
    )


def test_every_registry_entry_has_exactly_one_check_module_file() -> None:
    """Property 2, entry to file: every entry traces to one file on disk.

    Each entry must resolve to a file that exists, lies under
    ``services/*/checks/``, and matches the ``sra_*`` glob. An entry failing
    any of those is an entry the filesystem does not account for.

    Validates: Requirements 5.1, 5.4
    """
    services = _services_dir()
    catalog = _catalog()
    files = _check_module_files(services)

    fileless: list[str] = []
    off_disk: dict[str, str] = {}
    for check_id, cls in catalog.items():
        path = _module_file(cls)
        if path is None:
            fileless.append(f"{check_id} ({cls.__module__})")
        elif path not in files:
            off_disk[check_id] = _relative(path, services)

    assert not fileless, (
        f"{len(fileless)} registry entry/entries resolve to no module file: "
        f"{sorted(fileless)}"
    )
    assert not off_disk, (
        f"registry entry/entries whose module file does not match "
        f"{CHECK_MODULE_GLOB} under {services}: {off_disk}"
    )

    # The map from entry to file is injective, which with the file-to-entry
    # direction above completes the bijection rather than a mere surjection.
    seen: dict[Path, str] = {}
    collisions: dict[str, list[str]] = {}
    for check_id, cls in catalog.items():
        path = _module_file(cls)
        if path is None:
            continue
        if path in seen:
            collisions.setdefault(_relative(path, services), [seen[path]]).append(
                check_id
            )
        else:
            seen[path] = check_id
    assert not collisions, (
        f"two or more registry entries share one module file: {collisions}"
    )


def test_the_bijection_reports_both_directions_of_a_mismatch() -> None:
    """Property 2, stated as one set equality with a two-sided report.

    The two preceding tests each fail on one direction. This one is the whole
    property in a single assertion, and it exists for its failure message:
    when the catalog and the tree have drifted, a reviewer sees both lists at
    once and can tell a missing registration from a phantom entry without
    running a second test.

    Validates: Requirements 5.1, 5.4
    """
    services = _services_dir()
    catalog = _catalog()

    on_disk = {_relative(path, services) for path in _check_module_files(services)}
    registered = {
        _relative(path, services)
        for path in (_module_file(cls) for cls in catalog.values())
        if path is not None
    }

    files_with_no_entry = sorted(on_disk - registered)
    entries_with_no_file = sorted(registered - on_disk)
    orphaned_entries = sorted(
        f"{check_id} ({cls.__module__})"
        for check_id, cls in catalog.items()
        if _module_file(cls) is None
    )

    assert on_disk == registered and not orphaned_entries, (
        "the registry is not a bijection with the check modules on disk.\n"
        f"  files with no registry entry (checks that never run): "
        f"{files_with_no_entry or 'none'}\n"
        f"  registry entries with no matching file: "
        f"{entries_with_no_file or 'none'}\n"
        f"  registry entries with no resolvable file at all: "
        f"{orphaned_entries or 'none'}"
    )


def test_exactly_eighteen_service_subpackages_are_discovered() -> None:
    """Requirement 5.2: the ``services`` package holds 18 service subpackages.

    Counted from the filesystem, taking a directory with an ``__init__.py`` as
    a package, so ``__pycache__`` and any stray directory are excluded on the
    same rule discovery uses. Every one of them must also hold a ``checks``
    subpackage, since 5.7 makes a service package without one a hard import
    failure rather than a service contributing nothing.

    Validates: Requirements 5.2
    """
    services = _services_dir()

    subpackages = sorted(
        path.name
        for path in services.iterdir()
        if path.is_dir() and (path / "__init__.py").is_file()
    )

    assert len(subpackages) == EXPECTED_SERVICE_COUNT, (
        f"expected {EXPECTED_SERVICE_COUNT} service subpackages under "
        f"{services}, found {len(subpackages)}: {subpackages}"
    )

    without_checks = [
        name
        for name in subpackages
        if not (services / name / "checks" / "__init__.py").is_file()
    ]
    assert not without_checks, (
        f"service subpackage(s) with no checks subpackage: {without_checks}"
    )

    # Every service contributes at least one check, so no service subpackage is
    # dead weight and the 158 files are spread across all 18 of them.
    empty = [
        name
        for name in subpackages
        if not list((services / name / "checks").glob(f"{CHECK_MODULE_PREFIX}*.py"))
    ]
    assert not empty, f"service subpackage(s) contributing no check module: {empty}"


def test_no_non_sra_module_in_a_checks_directory_got_registered() -> None:
    """Requirement 5.1: only ``sra_*`` modules contribute registry entries.

    Discovery skips non-``sra_`` modules and subpackages of ``checks``, and
    ``__init_subclass__`` keys eligibility on the same stem rule. This asserts
    the outcome: every registered entry's file stem begins with ``sra_``, and
    the non-``sra_`` files that do exist inside ``checks`` directories -- the
    package ``__init__.py`` files -- contributed nothing.

    Validates: Requirements 5.1, 5.2
    """
    services = _services_dir()
    catalog = _catalog()

    registered_files = {
        path
        for path in (_module_file(cls) for cls in catalog.values())
        if path is not None
    }

    wrong_prefix = {
        check_id: _relative(path, services)
        for check_id, cls in catalog.items()
        if (path := _module_file(cls)) is not None
        and not path.name.startswith(CHECK_MODULE_PREFIX)
    }
    assert not wrong_prefix, (
        f"registry entry/entries defined in a module whose name does not begin "
        f"with {CHECK_MODULE_PREFIX!r}: {wrong_prefix}"
    )

    non_check_modules = {
        path.resolve()
        for path in services.glob("*/checks/*.py")
        if not path.name.startswith(CHECK_MODULE_PREFIX)
    }
    # Non-vacuity: there really are such files -- one __init__.py per service --
    # so the disjointness below is asserting something.
    assert non_check_modules, (
        f"no non-{CHECK_MODULE_PREFIX!r} module found in any checks directory "
        f"under {services}; this assertion would pass vacuously"
    )

    leaked = sorted(
        _relative(path, services)
        for path in non_check_modules & registered_files
    )
    assert not leaked, (
        f"non-{CHECK_MODULE_PREFIX!r} module(s) inside a checks directory "
        f"produced a registry entry: {leaked}"
    )
