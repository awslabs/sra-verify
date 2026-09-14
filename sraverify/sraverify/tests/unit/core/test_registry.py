"""Unit tests for ``sraverify.core.registry`` and ``sraverify.core.discovery``.

Three concerns, in the order the design puts weight on them:

  * **Property 3: a duplicate check ID raises.** ``register`` is idempotent for
    the *same* class object -- a module imported twice under the same name has
    to stay harmless -- but a *different* class claiming an ID that is already
    present is a catalog defect and must raise rather than silently overwrite.
    Overwriting is the failure mode that makes a check disappear from the run
    while every file on disk still looks correct.
  * **The read path is read-only and ordered.** ``all_checks()`` hands back a
    ``MappingProxyType`` over a sorted copy, so no caller can mutate the
    catalog and ``--list-checks`` output is reproducible.
  * **Discovery imports the right modules in the right order.** Folded in here
    rather than given a module of its own: sorted ``sra_*`` import order, and an
    empty list when nothing matches, exercised over a throwaway package built
    under ``tmp_path``.

Every test that touches the registry runs inside ``isolated_registry``, which
snapshots the module-level ``_REGISTRY``, empties it for the duration of the
test, and restores it afterwards. Without the snapshot these tests would leak
synthetic entries into the real catalog for every later test module in the same
pytest session; without the emptying their expectations would depend on whether
an earlier module already imported the 158 real checks.

Requirements 4.7, 4.8, 4.9, 5.1, 5.3.
"""
from __future__ import annotations

import importlib
import sys
import textwrap

import pytest

from sraverify.core import registry
from sraverify.core.discovery import import_check_modules
from sraverify.core.errors import DuplicateCheckIdError, SRAVerifyError


# --------------------------------------------------------------------------
# Isolation
# --------------------------------------------------------------------------

@pytest.fixture
def isolated_registry():
    """Snapshot ``_REGISTRY``, empty it for the test, and restore it afterwards.

    ``_REGISTRY`` is module-level state shared by the whole process. The
    snapshot is a shallow copy of the dict, and restoration mutates the
    original dict in place rather than rebinding the name, so a module that
    captured a reference to it still sees the restored contents.

    Emptying it for the duration of the test is what makes these tests
    independent of whether some earlier module in the session imported
    ``sraverify.services`` and left all 158 real checks resident. Each test's
    own registrations are then the whole truth about the catalog.
    """
    saved = dict(registry._REGISTRY)
    registry._REGISTRY.clear()
    try:
        yield registry._REGISTRY
    finally:
        registry._REGISTRY.clear()
        registry._REGISTRY.update(saved)


def _check_class(name: str) -> type:
    """Return a fresh throwaway class to stand in for a check class.

    ``register`` stores whatever it is handed and reads nothing off it, so a
    bare class is a sufficient stand-in and avoids dragging the real
    ``SecurityCheck`` metaclass hook into a registry test.
    """
    return type(name, (), {})


# --------------------------------------------------------------------------
# Property 3: duplicate check ID raises (Requirements 4.7, 4.8)
# --------------------------------------------------------------------------

def test_register_adds_the_class_under_its_check_id(isolated_registry):
    cls = _check_class("SRA_TEST_01")

    registry.register("SRA-TEST-01", cls)

    assert registry.all_checks()["SRA-TEST-01"] is cls


def test_a_different_class_under_an_existing_id_raises(isolated_registry):
    first = _check_class("SRA_TEST_01")
    second = _check_class("SRA_TEST_01_IMPOSTOR")
    registry.register("SRA-TEST-01", first)

    with pytest.raises(DuplicateCheckIdError):
        registry.register("SRA-TEST-01", second)


def test_duplicate_error_carries_the_id_and_both_classes(isolated_registry):
    first = _check_class("SRA_TEST_01")
    second = _check_class("SRA_TEST_01_IMPOSTOR")
    registry.register("SRA-TEST-01", first)

    with pytest.raises(DuplicateCheckIdError) as excinfo:
        registry.register("SRA-TEST-01", second)

    # DuplicateCheckIdError declares no __init__, so the three values reach the
    # exception only through .args. str(e) renders that tuple's repr, which is
    # why the substring assertions below hold without a hand-formatted message.
    assert excinfo.value.args == ("SRA-TEST-01", first, second)

    rendered = str(excinfo.value)
    assert "SRA-TEST-01" in rendered
    assert "SRA_TEST_01" in rendered
    assert "SRA_TEST_01_IMPOSTOR" in rendered


def test_duplicate_error_is_an_sraverify_error(isolated_registry):
    # main.py's except clauses lean on the common base.
    registry.register("SRA-TEST-01", _check_class("SRA_TEST_01"))

    with pytest.raises(SRAVerifyError):
        registry.register("SRA-TEST-01", _check_class("SRA_TEST_01_OTHER"))


def test_a_rejected_duplicate_leaves_the_incumbent_in_place(isolated_registry):
    first = _check_class("SRA_TEST_01")
    second = _check_class("SRA_TEST_01_IMPOSTOR")
    registry.register("SRA-TEST-01", first)

    with pytest.raises(DuplicateCheckIdError):
        registry.register("SRA-TEST-01", second)

    # The point of raising rather than overwriting: the original class is still
    # the one that will run.
    assert registry.all_checks()["SRA-TEST-01"] is first


def test_re_registering_the_same_class_object_is_harmless(isolated_registry):
    cls = _check_class("SRA_TEST_01")

    registry.register("SRA-TEST-01", cls)
    registry.register("SRA-TEST-01", cls)
    registry.register("SRA-TEST-01", cls)

    catalog = registry.all_checks()
    assert catalog["SRA-TEST-01"] is cls
    assert list(catalog).count("SRA-TEST-01") == 1


def test_the_same_class_may_hold_two_distinct_ids(isolated_registry):
    # Not a shape any real check has, but the duplicate rule is keyed on
    # (id, class) and must not degrade into "one id per class".
    cls = _check_class("SRA_TEST_01")

    registry.register("SRA-TEST-01", cls)
    registry.register("SRA-TEST-02", cls)

    catalog = registry.all_checks()
    assert catalog["SRA-TEST-01"] is cls
    assert catalog["SRA-TEST-02"] is cls


def test_distinct_ids_for_distinct_classes_coexist(isolated_registry):
    a = _check_class("SRA_TEST_01")
    b = _check_class("SRA_TEST_02")

    registry.register("SRA-TEST-01", a)
    registry.register("SRA-TEST-02", b)

    assert registry.all_checks()["SRA-TEST-01"] is a
    assert registry.all_checks()["SRA-TEST-02"] is b


def test_two_subclasses_of_one_base_still_conflict_on_a_shared_id(isolated_registry):
    base = _check_class("SRA_TEST_BASE")
    first = type("SRA_TEST_01", (base,), {})
    second = type("SRA_TEST_01", (base,), {})
    registry.register("SRA-TEST-01", first)

    # Identical class *names* and a shared base are not identity. The check is
    # `is not`, so this must still raise.
    with pytest.raises(DuplicateCheckIdError):
        registry.register("SRA-TEST-01", second)


# --------------------------------------------------------------------------
# The read path: read-only and ordered (Requirement 4.9)
# --------------------------------------------------------------------------

def test_all_checks_returns_a_mapping_proxy(isolated_registry):
    from types import MappingProxyType

    assert isinstance(registry.all_checks(), MappingProxyType)


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda m: m.__setitem__("SRA-TEST-99", object), id="setitem"),
        pytest.param(lambda m: m.__delitem__("SRA-TEST-01"), id="delitem"),
        pytest.param(lambda m: m.clear(), id="clear"),
        pytest.param(lambda m: m.pop("SRA-TEST-01"), id="pop"),
        pytest.param(lambda m: m.popitem(), id="popitem"),
        pytest.param(lambda m: m.update({"SRA-TEST-99": object}), id="update"),
        pytest.param(lambda m: m.setdefault("SRA-TEST-99", object), id="setdefault"),
    ],
)
def test_the_returned_mapping_rejects_mutation(isolated_registry, mutate):
    registry.register("SRA-TEST-01", _check_class("SRA_TEST_01"))
    catalog = registry.all_checks()

    with pytest.raises((TypeError, AttributeError)):
        mutate(catalog)


def test_mutating_the_underlying_registry_is_not_visible_through_a_handed_out_view(
    isolated_registry,
):
    registry.register("SRA-TEST-01", _check_class("SRA_TEST_01"))
    catalog = registry.all_checks()

    registry.register("SRA-TEST-02", _check_class("SRA_TEST_02"))

    # The proxy wraps a *copy*, so the later registration is invisible here.
    assert "SRA-TEST-02" not in catalog
    assert "SRA-TEST-02" in registry.all_checks()


def test_catalog_is_ordered_by_ascending_check_id(isolated_registry):
    isolated_registry.clear()
    for check_id in ["SRA-ZULU-02", "SRA-ALPHA-01", "SRA-ZULU-01", "SRA-MIKE-10"]:
        registry.register(check_id, _check_class(check_id.replace("-", "_")))

    assert list(registry.all_checks()) == [
        "SRA-ALPHA-01",
        "SRA-MIKE-10",
        "SRA-ZULU-01",
        "SRA-ZULU-02",
    ]


def test_ordering_is_lexicographic_so_two_digit_ids_sort_correctly(isolated_registry):
    isolated_registry.clear()
    for n in [10, 2, 1, 9, 20]:
        check_id = f"SRA-TEST-{n:02d}"
        registry.register(check_id, _check_class(check_id.replace("-", "_")))

    # Zero-padding is what makes lexicographic order agree with numeric order.
    assert list(registry.all_checks()) == [
        "SRA-TEST-01",
        "SRA-TEST-02",
        "SRA-TEST-09",
        "SRA-TEST-10",
        "SRA-TEST-20",
    ]


def test_ordering_does_not_depend_on_registration_order(isolated_registry):
    ids = ["SRA-TEST-03", "SRA-TEST-01", "SRA-TEST-02"]

    isolated_registry.clear()
    for check_id in ids:
        registry.register(check_id, _check_class(check_id.replace("-", "_")))
    forward = list(registry.all_checks())

    isolated_registry.clear()
    for check_id in reversed(ids):
        registry.register(check_id, _check_class(check_id.replace("-", "_")))
    backward = list(registry.all_checks())

    assert forward == backward == ["SRA-TEST-01", "SRA-TEST-02", "SRA-TEST-03"]


def test_an_empty_registry_yields_an_empty_catalog(isolated_registry):
    isolated_registry.clear()

    assert dict(registry.all_checks()) == {}


# --------------------------------------------------------------------------
# Discovery, folded in (Requirements 5.1, 5.3)
# --------------------------------------------------------------------------

_PKG_COUNTER = iter(range(1, 10_000))


@pytest.fixture
def make_checks_package(tmp_path):
    """Build a throwaway ``<pkg>/checks/`` package and make it importable.

    Yields a factory taking the module file names to create under ``checks``
    and returning the dotted name of the ``checks`` package. Each call gets a
    unique top-level package name, so two invocations in one test cannot
    collide in ``sys.modules``.

    ``sys.path`` and every module the factory introduced are removed on
    teardown, so nothing leaks into a later test module.
    """
    created: list[str] = []
    path_entry = str(tmp_path)
    sys.path.insert(0, path_entry)

    def factory(module_names, *, subpackages=()):
        pkg_name = f"_sraverify_disco_pkg_{next(_PKG_COUNTER)}"
        created.append(pkg_name)

        pkg_dir = tmp_path / pkg_name
        checks_dir = pkg_dir / "checks"
        checks_dir.mkdir(parents=True)
        (pkg_dir / "__init__.py").write_text('"""Throwaway service package."""\n')
        (checks_dir / "__init__.py").write_text('"""Throwaway checks package."""\n')

        for name in module_names:
            (checks_dir / f"{name}.py").write_text(
                textwrap.dedent(
                    f'''\
                    """Throwaway check module."""
                    import {pkg_name}.checks as _checks

                    # Append on import so the test can read back the real
                    # import order rather than trusting the return value alone.
                    if not hasattr(_checks, "IMPORTED"):
                        _checks.IMPORTED = []
                    _checks.IMPORTED.append("{name}")
                    '''
                )
            )

        for sub in subpackages:
            sub_dir = checks_dir / sub
            sub_dir.mkdir()
            (sub_dir / "__init__.py").write_text(
                '"""Throwaway subpackage that must not be imported."""\n'
                "raise AssertionError('a checks subpackage must not be imported')\n"
            )

        importlib.invalidate_caches()
        return f"{pkg_name}.checks"

    try:
        yield factory
    finally:
        if path_entry in sys.path:
            sys.path.remove(path_entry)
        for pkg_name in created:
            for mod in [m for m in sys.modules if m == pkg_name or m.startswith(f"{pkg_name}.")]:
                del sys.modules[mod]
        importlib.invalidate_caches()


def test_import_check_modules_returns_sorted_sra_module_names(make_checks_package):
    checks_pkg = make_checks_package(["sra_test_10", "sra_test_01", "sra_test_02"])

    imported = import_check_modules(checks_pkg)

    assert imported == ["sra_test_01", "sra_test_02", "sra_test_10"]


def test_import_check_modules_imports_in_the_order_it_reports(make_checks_package):
    checks_pkg = make_checks_package(["sra_test_09", "sra_test_01", "sra_test_20"])

    imported = import_check_modules(checks_pkg)

    # Read the real import order back out of the package the modules appended to.
    actual = sys.modules[checks_pkg].IMPORTED
    assert actual == imported == ["sra_test_01", "sra_test_09", "sra_test_20"]


def test_import_check_modules_returns_an_empty_list_when_nothing_matches(
    make_checks_package,
):
    checks_pkg = make_checks_package(["helpers", "base", "_private", "test_sra_01"])

    assert import_check_modules(checks_pkg) == []


def test_import_check_modules_returns_an_empty_list_for_an_empty_package(
    make_checks_package,
):
    checks_pkg = make_checks_package([])

    assert import_check_modules(checks_pkg) == []


def test_import_check_modules_skips_non_sra_modules(make_checks_package):
    checks_pkg = make_checks_package(
        ["sra_test_01", "helpers", "sra_test_02", "conftest"]
    )

    imported = import_check_modules(checks_pkg)

    assert imported == ["sra_test_01", "sra_test_02"]
    assert f"{checks_pkg}.helpers" not in sys.modules
    assert f"{checks_pkg}.conftest" not in sys.modules


def test_import_check_modules_skips_subpackages(make_checks_package):
    # The subpackage __init__ raises on import, so a skip failure is loud.
    checks_pkg = make_checks_package(
        ["sra_test_01"], subpackages=["sra_nested", "helpers_pkg"]
    )

    assert import_check_modules(checks_pkg) == ["sra_test_01"]


def test_import_check_modules_actually_imports_the_modules(make_checks_package):
    checks_pkg = make_checks_package(["sra_test_01", "sra_test_02"])

    import_check_modules(checks_pkg)

    assert f"{checks_pkg}.sra_test_01" in sys.modules
    assert f"{checks_pkg}.sra_test_02" in sys.modules


def test_a_second_call_imports_no_module_twice(make_checks_package):
    checks_pkg = make_checks_package(["sra_test_01", "sra_test_02"])

    first = import_check_modules(checks_pkg)
    second = import_check_modules(checks_pkg)

    # The return value is the matching module names either way; what must not
    # double is the module-body execution, tracked by IMPORTED.
    assert first == second == ["sra_test_01", "sra_test_02"]
    assert sys.modules[checks_pkg].IMPORTED == ["sra_test_01", "sra_test_02"]


def test_a_missing_checks_package_propagates_module_not_found():
    with pytest.raises(ModuleNotFoundError):
        import_check_modules("_sraverify_no_such_package_.checks")
