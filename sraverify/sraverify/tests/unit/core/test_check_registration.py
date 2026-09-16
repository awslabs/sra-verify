"""Unit tests for ``SecurityCheck.__init_subclass__`` -- registration and identity.

Every test here builds a **real** throwaway service package on disk under
``tmp_path`` and imports it. That is not ceremony: the hook reads
``sys.modules[cls.__module__].__file__`` and derives the expected check ID from
the file stem, so a synthetic class declared inline in this module would be
skipped by the ``sra_`` stem rule and would exercise nothing. A file on disk,
filed under a service package, imported by name, is the only faithful fixture.

The branches covered, in the order the hook applies them:

  * **Eligibility, silent (4.13, 4.2).** Three ways a subclass is left
    unregistered with no error raised: its module is absent from
    ``sys.modules``, its module carries no ``__file__``, or its file stem does
    not begin with ``sra_``. The third is what keeps the service base classes
    in ``base.py`` out of the catalog. In all three fixtures the class is
    otherwise perfectly registrable, so the skip is attributable to exactly one
    cause.
  * **Identity 1 -- the file stem is the authority (4.4).**
  * **Identity 2 -- the metadata ``check_id`` (4.5).**
  * **Identity 3 -- the class name (4.6).**
  * **Identity 4 -- the containing service package (4.14).**
  * **Metadata presence, read from the class body and never inherited (4.16).**
  * **Shape rules (6.12).** No check inherits another check; no class attribute
    shadows a metadata property, including one smuggled in by an intermediate
    base class.

Two ordering facts are asserted directly rather than left implicit, because
both surprise a reader who assumes the rules are independent:

  * The metadata-presence rule runs **before** the class-name rule, so a second
    subclass declared in a check module fails on the missing ``meta`` (4.16),
    not on its name (4.6). Reaching the class-name rule requires the subclass
    to declare its own ``meta``.
  * Requirement 4.15 is per **class**, not per module. A module that declares a
    valid check and then a second class that raises leaves the first check
    registered even though the module import failed. The guarantee is that no
    *failing* class contributes a partial entry, not that a failed import is
    transactional across the file.

Every test runs inside ``isolated_registry``, which snapshots the module-level
``_REGISTRY``, empties it for the duration of the test, and restores it
afterwards. Importing a synthetic check registers it for real, so without the
snapshot these tests would leak synthetic IDs into the catalog for every later
test module in the same pytest session -- and without the emptying they would
collide with the 158 real checks any earlier module left resident, since the
synthetic modules here deliberately reuse real check IDs.

Requirements 4.2, 4.4, 4.5, 4.6, 4.13, 4.14, 4.16, 6.12.
"""

from __future__ import annotations

import importlib
import sys
import textwrap
import types

import pytest

from sraverify.core import registry
from sraverify.core.check import SecurityCheck
from sraverify.core.errors import CheckIdentityError, SRAVerifyError


# --------------------------------------------------------------------------
# Isolation
# --------------------------------------------------------------------------

@pytest.fixture
def isolated_registry():
    """Snapshot ``_REGISTRY``, empty it for the test, and restore it afterwards.

    Same shape as ``test_registry.py``'s fixture, and for the same reason:
    ``_REGISTRY`` is module-level process state. Restoration mutates the
    original dict in place rather than rebinding the name, so a module holding
    a reference to it still sees the restored contents.

    The **clear** matters as much as the snapshot. Once every service is
    migrated, ``import sraverify.services`` leaves all 158 real checks resident
    in ``_REGISTRY`` for the whole pytest session, and any earlier test module
    that imports it puts them there. A synthetic check reusing a real ID -- and
    these tests deliberately reuse ``SRA-GUARDDUTY-01`` -- would then raise
    ``DuplicateCheckIdError`` before reaching the identity rule under test, and
    the ``not in all_checks()`` assertions would find the real entry. Emptying
    the registry makes each test's own registrations the whole truth, and makes
    the outcome independent of which modules ran before it.
    """
    saved = dict(registry._REGISTRY)
    registry._REGISTRY.clear()
    try:
        yield registry._REGISTRY
    finally:
        registry._REGISTRY.clear()
        registry._REGISTRY.update(saved)


# --------------------------------------------------------------------------
# Synthetic check-module sources
# --------------------------------------------------------------------------

_PRELUDE = '''\
"""Synthetic module written by test_check_registration."""
from sraverify.core.check import SecurityCheck
from sraverify.core.enums import AccountType, Severity
from sraverify.core.metadata import CheckMeta, Remediation
'''


def _meta_src(
    check_id: str,
    *,
    service: str = "GuardDuty",
    resource_type: str = "AWS::GuardDuty::Detector",
) -> str:
    """Return the source of a **valid** ``CheckMeta`` literal, indented one level.

    Every value is legal on purpose. ``CheckMeta.__post_init__`` runs while the
    class body executes, which is strictly before ``__init_subclass__``, so a
    metadata *value* defect would raise ``MetadataError`` and the identity rule
    under test would never be reached. Only ``check_id``, ``service``, and
    ``resource_type`` vary, because those are the three an identity test needs
    to move.
    """
    body = textwrap.dedent(
        f'''\
        meta = CheckMeta(
            check_id="{check_id}",
            title="A synthetic control is configured",
            description="Synthetic description for a registration test.",
            check_logic="Synthetic logic.",
            severity=Severity.HIGH,
            account_type=AccountType.APPLICATION,
            service="{service}",
            resource_type="{resource_type}",
            remediation=Remediation(text="Do the synthetic thing."),
        )
        '''
    )
    return textwrap.indent(body, "    ")


def _check_src(
    class_name: str,
    *,
    check_id: str | None,
    bases: str = "SecurityCheck",
    service: str = "GuardDuty",
    resource_type: str = "AWS::GuardDuty::Detector",
    class_attrs: str = "",
    extra: str = "",
) -> str:
    """Return the full source of a synthetic check module.

    Args:
        class_name: The class to declare.
        check_id: The ``meta.check_id`` to declare, or ``None`` to declare no
            ``meta`` at all -- the 4.16 fixture.
        bases: Base-class expression, so a test can inherit a service base
            class or another check.
        service: ``meta.service``.
        resource_type: ``meta.resource_type``.
        class_attrs: Extra source for the class body, dedented and indented one
            level. Used for the shadowing fixtures.
        extra: Extra module-level source appended after the prelude, e.g. an
            import of another check module.
    """
    parts: list[str] = []
    if check_id is not None:
        parts.append(_meta_src(check_id, service=service, resource_type=resource_type))
    if class_attrs:
        parts.append(textwrap.indent(textwrap.dedent(class_attrs), "    "))
    if not parts:
        parts.append("    pass\n")

    return (
        _PRELUDE
        + extra
        + f"\n\nclass {class_name}({bases}):\n"
        + '    """Synthetic check."""\n\n'
        + "\n".join(parts)
    )


# --------------------------------------------------------------------------
# The tmp_path service package
# --------------------------------------------------------------------------

_PKG_COUNTER = iter(range(1, 10_000))


@pytest.fixture
def synthetic_service(tmp_path, isolated_registry):
    """Build a throwaway ``<top>/<service>/checks/`` tree and make it importable.

    Yields a factory taking a mapping of path-relative-to-the-service-package
    to module source, and returning the dotted name of the service package. A
    test then imports one module by name and asserts on what happens:

        pkg = synthetic_service({"checks/sra_guardduty_01.py": src})
        importlib.import_module(f"{pkg}.checks.sra_guardduty_01")

    The tree mirrors the real layout, because the hook reads the service name
    out of ``cls.__module__`` -- ``<top>.<service>.checks.<stem>`` -- and the
    ``checks`` component is load-bearing.

    Each call gets a unique top-level package name, so two invocations in one
    test cannot collide in ``sys.modules``. ``sys.path`` and every module the
    factory introduced are removed on teardown. Depends on
    ``isolated_registry``, so importing a synthetic check cannot leak into the
    real catalog: fixture finalizers run in reverse order, so ``sys.modules`` is
    purged first and the registry is restored after.
    """
    created: list[str] = []
    path_entry = str(tmp_path)
    sys.path.insert(0, path_entry)

    def factory(files, *, service: str = "guardduty") -> str:
        top = f"_sraverify_synth_{next(_PKG_COUNTER)}"
        created.append(top)

        service_dir = tmp_path / top / service
        (service_dir / "checks").mkdir(parents=True)
        (tmp_path / top / "__init__.py").write_text(
            '"""Throwaway stand-in for the services package."""\n'
        )
        # Deliberately *not* a discovery call: these tests import one module at
        # a time by name, so each import failure is attributable to one class.
        (service_dir / "__init__.py").write_text(
            '"""Throwaway service package."""\n'
        )
        (service_dir / "checks" / "__init__.py").write_text(
            '"""Throwaway checks package."""\n'
        )

        for relative_path, source in files.items():
            target = service_dir / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source)

        importlib.invalidate_caches()
        return f"{top}.{service}"

    try:
        yield factory
    finally:
        if path_entry in sys.path:
            sys.path.remove(path_entry)
        for top in created:
            for name in [
                m for m in sys.modules if m == top or m.startswith(f"{top}.")
            ]:
                del sys.modules[name]
        importlib.invalidate_caches()


# --------------------------------------------------------------------------
# The happy path, so a later failure is attributable to the rule under test
# --------------------------------------------------------------------------

def test_a_well_formed_check_module_registers_itself(synthetic_service):
    pkg = synthetic_service(
        {
            "checks/sra_guardduty_01.py": _check_src(
                "SRA_GUARDDUTY_01", check_id="SRA-GUARDDUTY-01"
            )
        }
    )

    module = importlib.import_module(f"{pkg}.checks.sra_guardduty_01")

    # Importing the file is the whole of registering it: no decorator, no dict.
    assert registry.all_checks()["SRA-GUARDDUTY-01"] is module.SRA_GUARDDUTY_01


def test_a_two_digit_check_number_registers(synthetic_service):
    pkg = synthetic_service(
        {
            "checks/sra_guardduty_25.py": _check_src(
                "SRA_GUARDDUTY_25", check_id="SRA-GUARDDUTY-25"
            )
        }
    )

    importlib.import_module(f"{pkg}.checks.sra_guardduty_25")

    assert "SRA-GUARDDUTY-25" in registry.all_checks()


# --------------------------------------------------------------------------
# Eligibility: the three silent skips (Requirements 4.2, 4.13)
# --------------------------------------------------------------------------

def test_a_service_base_class_in_base_py_is_skipped_silently(synthetic_service):
    # The real shape: GuardDutyCheck lives in base.py, declares no meta of its
    # own, and must stay out of the catalog without raising. Eligibility is
    # keyed on the file name, never on the presence of `meta` (4.12), which is
    # what lets this coexist with the 4.16 test below.
    pkg = synthetic_service(
        {"base.py": _check_src("GuardDutyCheck", check_id=None)}
    )

    module = importlib.import_module(f"{pkg}.base")

    assert issubclass(module.GuardDutyCheck, SecurityCheck)
    assert module.GuardDutyCheck not in set(registry.all_checks().values())


def test_a_base_class_declaring_meta_in_base_py_is_still_skipped(synthetic_service):
    # A base class that happens to carry a metadata literal is still not a
    # check, because the file stem decides. Nothing registers under that ID.
    pkg = synthetic_service(
        {"base.py": _check_src("GuardDutyCheck", check_id="SRA-GUARDDUTY-01")}
    )

    importlib.import_module(f"{pkg}.base")

    assert "SRA-GUARDDUTY-01" not in registry.all_checks()


def test_an_intermediate_subclass_outside_a_check_module_is_skipped(
    synthetic_service,
):
    pkg = synthetic_service(
        {"checks/helpers.py": _check_src("RegionLoopingCheck", check_id=None)}
    )

    module = importlib.import_module(f"{pkg}.checks.helpers")

    # Inside the checks package, but the stem does not begin with sra_.
    assert module.RegionLoopingCheck not in set(registry.all_checks().values())


def test_a_check_may_inherit_a_base_class_declared_in_base_py(synthetic_service):
    # The corollary of the base.py skip: the skipped class stays usable as a
    # base, and only the check itself lands in the catalog. Without this, the
    # "no check inherits another check" rule below would be indistinguishable
    # from "no check inherits anything".
    pkg = synthetic_service(
        {
            "base.py": _check_src("GuardDutyCheck", check_id=None),
            "checks/sra_guardduty_01.py": _check_src(
                "SRA_GUARDDUTY_01",
                check_id="SRA-GUARDDUTY-01",
                bases="GuardDutyCheck",
                extra="from ..base import GuardDutyCheck\n",
            ),
        }
    )

    module = importlib.import_module(f"{pkg}.checks.sra_guardduty_01")

    catalog = registry.all_checks()
    assert catalog["SRA-GUARDDUTY-01"] is module.SRA_GUARDDUTY_01
    assert module.SRA_GUARDDUTY_01.__mro__[1] is module.GuardDutyCheck
    assert module.GuardDutyCheck not in set(catalog.values())


def test_a_subclass_whose_module_is_absent_from_sys_modules_is_skipped(
    isolated_registry,
):
    # exec with a __name__ nobody has imported: sys.modules.get returns None.
    # The class name, the module name, and the file stem the module name implies
    # are all otherwise valid, so absence from sys.modules is the only possible
    # grounds for the skip.
    module_name = "_sraverify_absent_pkg.guardduty.checks.sra_guardduty_01"
    assert module_name not in sys.modules

    namespace = {"__name__": module_name, "SecurityCheck": SecurityCheck}
    exec("class SRA_GUARDDUTY_01(SecurityCheck):\n    pass\n", namespace)

    assert namespace["SRA_GUARDDUTY_01"].__module__ == module_name
    assert "SRA-GUARDDUTY-01" not in registry.all_checks()


def test_a_subclass_whose_module_carries_no_file_is_skipped(isolated_registry):
    # A module object built by hand has no __file__. Same fixture as above with
    # the module present in sys.modules, so the two conditions 4.13 admits are
    # covered separately rather than as one compound case.
    module_name = "_sraverify_nofile_pkg.guardduty.checks.sra_guardduty_01"
    module = types.ModuleType(module_name)
    assert getattr(module, "__file__", None) is None
    sys.modules[module_name] = module
    try:
        namespace = {"__name__": module_name, "SecurityCheck": SecurityCheck}
        exec("class SRA_GUARDDUTY_01(SecurityCheck):\n    pass\n", namespace)
    finally:
        del sys.modules[module_name]

    assert "SRA-GUARDDUTY-01" not in registry.all_checks()


def test_neither_silent_skip_raises_even_with_a_malformed_class_name(
    isolated_registry,
):
    # Belt and braces: the skip returns before any rule is applied, so a class
    # that would fail three rules at once still raises nothing.
    module_name = "_sraverify_absent_pkg_2.nowhere.sra_9bad_00"
    assert module_name not in sys.modules

    namespace = {"__name__": module_name, "SecurityCheck": SecurityCheck}
    exec("class NotACheckAtAll(SecurityCheck):\n    pass\n", namespace)

    assert namespace["NotACheckAtAll"] not in set(registry.all_checks().values())


# --------------------------------------------------------------------------
# Identity 1: the file stem is the authority (Requirement 4.4)
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "stem",
    [
        pytest.param("sra_guardduty_00", id="number-zero"),
        pytest.param("sra_guardduty_1", id="single-digit"),
        pytest.param("sra_guardduty_100", id="three-digits"),
        pytest.param("sra_guardduty_01x", id="trailing-junk"),
        pytest.param("sra_1guardduty_01", id="service-starts-with-a-digit"),
        pytest.param("sra_12_01", id="numeric-service"),
        pytest.param("sra_GuardDuty_01", id="upper-case-service"),
        pytest.param("sra_guard-duty_01", id="hyphen-in-service"),
        pytest.param("sra__01", id="empty-service"),
        pytest.param("sra_guardduty", id="no-number"),
        pytest.param("sra_", id="prefix-only"),
    ],
)
def test_a_malformed_module_stem_raises(synthetic_service, stem):
    # The metadata and the class name are valid throughout, so nothing but the
    # stem rule can be responsible. `sra_12_01` and `sra_guardduty_00` are the
    # two the obvious `sra_([a-z0-9]+)_(\d{2})` would have admitted, and both
    # would have registered looking correct.
    pkg = synthetic_service(
        {
            f"checks/{stem}.py": _check_src(
                "SRA_GUARDDUTY_01", check_id="SRA-GUARDDUTY-01"
            )
        }
    )

    with pytest.raises(CheckIdentityError) as excinfo:
        importlib.import_module(f"{pkg}.checks.{stem}")

    rendered = str(excinfo.value)
    assert "malformed" in rendered
    assert stem in rendered
    # 4.4 requires the module file be named, so the author can find the file.
    assert f"{stem}.py" in rendered


def test_a_malformed_stem_leaves_the_registry_untouched(synthetic_service):
    before = dict(registry.all_checks())
    pkg = synthetic_service(
        {
            "checks/sra_guardduty_00.py": _check_src(
                "SRA_GUARDDUTY_01", check_id="SRA-GUARDDUTY-01"
            )
        }
    )

    with pytest.raises(CheckIdentityError):
        importlib.import_module(f"{pkg}.checks.sra_guardduty_00")

    assert dict(registry.all_checks()) == before


def test_an_identity_failure_is_an_sraverify_error(synthetic_service):
    # main.py's except clauses lean on the common base.
    pkg = synthetic_service(
        {
            "checks/sra_guardduty_00.py": _check_src(
                "SRA_GUARDDUTY_01", check_id="SRA-GUARDDUTY-01"
            )
        }
    )

    with pytest.raises(SRAVerifyError):
        importlib.import_module(f"{pkg}.checks.sra_guardduty_00")


# --------------------------------------------------------------------------
# Identity 2: the metadata check_id (Requirement 4.5)
# --------------------------------------------------------------------------

def test_metadata_check_id_disagreeing_with_the_stem_raises(synthetic_service):
    # The realistic mistake: sra_guardduty_01.py copied to sra_guardduty_02.py
    # with the file renamed and the metadata left behind. Nothing but this
    # comparison catches it, and both classes would otherwise register.
    pkg = synthetic_service(
        {
            "checks/sra_guardduty_02.py": _check_src(
                "SRA_GUARDDUTY_02", check_id="SRA-GUARDDUTY-01"
            )
        }
    )

    with pytest.raises(CheckIdentityError) as excinfo:
        importlib.import_module(f"{pkg}.checks.sra_guardduty_02")

    rendered = str(excinfo.value)
    # 4.5: both values and the module file.
    assert "SRA-GUARDDUTY-01" in rendered
    assert "SRA-GUARDDUTY-02" in rendered
    assert "sra_guardduty_02.py" in rendered


def test_a_check_id_for_a_different_service_raises(synthetic_service):
    pkg = synthetic_service(
        {
            "checks/sra_guardduty_01.py": _check_src(
                "SRA_GUARDDUTY_01", check_id="SRA-SHIELD-01"
            )
        }
    )

    with pytest.raises(CheckIdentityError) as excinfo:
        importlib.import_module(f"{pkg}.checks.sra_guardduty_01")

    assert "SRA-SHIELD-01" in str(excinfo.value)


def test_a_disagreeing_check_id_registers_neither_id(synthetic_service):
    pkg = synthetic_service(
        {
            "checks/sra_guardduty_02.py": _check_src(
                "SRA_GUARDDUTY_02", check_id="SRA-GUARDDUTY-01"
            )
        }
    )

    with pytest.raises(CheckIdentityError):
        importlib.import_module(f"{pkg}.checks.sra_guardduty_02")

    catalog = registry.all_checks()
    assert "SRA-GUARDDUTY-01" not in catalog
    assert "SRA-GUARDDUTY-02" not in catalog


# --------------------------------------------------------------------------
# Identity 3: the class name (Requirement 4.6)
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "class_name",
    [
        pytest.param("SRA_GUARDDUTY_02", id="wrong-number"),
        pytest.param("SRA_SHIELD_01", id="wrong-service"),
        pytest.param("SRA_GuardDuty_01", id="wrong-case"),
        pytest.param("SRA_GUARDDUTY_1", id="unpadded-number"),
        pytest.param("SRAGUARDDUTY01", id="no-separators"),
        pytest.param("GuardDutyDetectorEnabled", id="descriptive-name"),
        pytest.param("SRA_GUARDDUTY_01_v2", id="suffixed"),
    ],
)
def test_a_class_name_disagreeing_with_the_stem_raises(synthetic_service, class_name):
    pkg = synthetic_service(
        {
            "checks/sra_guardduty_01.py": _check_src(
                class_name, check_id="SRA-GUARDDUTY-01"
            )
        }
    )

    with pytest.raises(CheckIdentityError) as excinfo:
        importlib.import_module(f"{pkg}.checks.sra_guardduty_01")

    rendered = str(excinfo.value)
    # 4.6: both values and the module file.
    assert class_name in rendered
    assert "SRA_GUARDDUTY_01" in rendered
    assert "sra_guardduty_01.py" in rendered


def test_a_second_subclass_in_a_check_module_fails_on_its_missing_meta(
    synthetic_service,
):
    # Ordering, asserted rather than assumed: the class-name rule applies to
    # EVERY subclass created in a sra_* module, but the metadata-presence rule
    # runs first, so a second subclass that simply inherits the first's meta
    # fails on 4.16 -- `vars(cls)` has no meta -- and never reaches 4.6.
    source = _check_src("SRA_GUARDDUTY_01", check_id="SRA-GUARDDUTY-01") + (
        "\n\nclass GuardDutyHelper(SRA_GUARDDUTY_01):\n"
        '    """A second subclass in a check module."""\n\n'
        "    pass\n"
    )
    pkg = synthetic_service({"checks/sra_guardduty_01.py": source})

    with pytest.raises(CheckIdentityError) as excinfo:
        importlib.import_module(f"{pkg}.checks.sra_guardduty_01")

    rendered = str(excinfo.value)
    assert "declares no meta of its own" in rendered
    assert "GuardDutyHelper" in rendered


def test_a_second_subclass_declaring_its_own_meta_fails_on_its_name(
    synthetic_service,
):
    # Give the second subclass its own valid meta and it clears 4.16 and 4.5,
    # then fails on 4.6 -- which is the rule that stops it registering under a
    # check ID it does not own.
    source = _check_src("SRA_GUARDDUTY_01", check_id="SRA-GUARDDUTY-01") + (
        "\n\nclass GuardDutyHelper(SecurityCheck):\n"
        '    """A second subclass with metadata of its own."""\n\n'
        + _meta_src("SRA-GUARDDUTY-01")
    )
    pkg = synthetic_service({"checks/sra_guardduty_01.py": source})

    with pytest.raises(CheckIdentityError) as excinfo:
        importlib.import_module(f"{pkg}.checks.sra_guardduty_01")

    rendered = str(excinfo.value)
    assert "GuardDutyHelper" in rendered
    assert "SRA_GUARDDUTY_01" in rendered


def test_the_first_valid_check_survives_a_later_class_failing_in_the_same_module(
    synthetic_service,
):
    # Requirement 4.15 is per CLASS, not per module. The first class registered
    # before the second one raised, and it stays registered even though the
    # module import failed. The guarantee is that no *failing* class leaves a
    # partial entry -- not that a failed import is transactional across a file.
    source = _check_src("SRA_GUARDDUTY_01", check_id="SRA-GUARDDUTY-01") + (
        "\n\nclass GuardDutyHelper(SecurityCheck):\n"
        '    """A second subclass with metadata of its own."""\n\n'
        + _meta_src("SRA-GUARDDUTY-01")
    )
    pkg = synthetic_service({"checks/sra_guardduty_01.py": source})

    with pytest.raises(CheckIdentityError):
        importlib.import_module(f"{pkg}.checks.sra_guardduty_01")

    catalog = registry.all_checks()
    assert "SRA-GUARDDUTY-01" in catalog
    assert catalog["SRA-GUARDDUTY-01"].__name__ == "SRA_GUARDDUTY_01"


# --------------------------------------------------------------------------
# Identity 4: the containing service package (Requirement 4.14)
# --------------------------------------------------------------------------

def test_a_check_filed_under_the_wrong_service_package_raises(synthetic_service):
    # Fully self-consistent under the three rules above -- stem, metadata ID,
    # and class name all say shield -- and still wrong: filed under guardduty
    # it would inherit GuardDutyCheck, run against GuardDuty's namespace and
    # client, and report Service=Shield on every row.
    pkg = synthetic_service(
        {
            "checks/sra_shield_01.py": _check_src(
                "SRA_SHIELD_01",
                check_id="SRA-SHIELD-01",
                service="Shield",
                resource_type="AWS::Shield::Protection",
            )
        },
        service="guardduty",
    )

    with pytest.raises(CheckIdentityError) as excinfo:
        importlib.import_module(f"{pkg}.checks.sra_shield_01")

    rendered = str(excinfo.value)
    # 4.14: both values and the module file.
    assert "shield" in rendered
    assert "guardduty" in rendered
    assert "sra_shield_01.py" in rendered


def test_the_wrong_service_package_registers_nothing(synthetic_service):
    pkg = synthetic_service(
        {
            "checks/sra_shield_01.py": _check_src(
                "SRA_SHIELD_01",
                check_id="SRA-SHIELD-01",
                service="Shield",
                resource_type="AWS::Shield::Protection",
            )
        },
        service="guardduty",
    )

    with pytest.raises(CheckIdentityError):
        importlib.import_module(f"{pkg}.checks.sra_shield_01")

    assert "SRA-SHIELD-01" not in registry.all_checks()


def test_a_check_module_outside_a_checks_package_raises(synthetic_service):
    # Same rule, other half: the service name is read from cls.__module__ on
    # the assumption that the module sits in <service>/checks/. A check module
    # dropped straight into the service package has no such position, so the
    # service can't be determined and the hook refuses rather than guessing.
    pkg = synthetic_service(
        {
            "sra_guardduty_01.py": _check_src(
                "SRA_GUARDDUTY_01", check_id="SRA-GUARDDUTY-01"
            )
        }
    )

    with pytest.raises(CheckIdentityError) as excinfo:
        importlib.import_module(f"{pkg}.sra_guardduty_01")

    assert "not in a service checks package" in str(excinfo.value)
    assert "SRA-GUARDDUTY-01" not in registry.all_checks()


def test_a_correctly_filed_check_passes_the_service_package_rule(synthetic_service):
    # The rule compares the file-name service segment against the package, not
    # against meta.service, so a display name that differs in case and spacing
    # from the package name is fine.
    pkg = synthetic_service(
        {
            "checks/sra_accessanalyzer_01.py": _check_src(
                "SRA_ACCESSANALYZER_01",
                check_id="SRA-ACCESSANALYZER-01",
                service="IAM Access Analyzer",
                resource_type="AWS::AccessAnalyzer::Analyzer",
            )
        },
        service="accessanalyzer",
    )

    importlib.import_module(f"{pkg}.checks.sra_accessanalyzer_01")

    assert "SRA-ACCESSANALYZER-01" in registry.all_checks()


# --------------------------------------------------------------------------
# Metadata presence, read from the class body (Requirement 4.16)
# --------------------------------------------------------------------------

def test_a_check_declaring_no_meta_raises(synthetic_service):
    pkg = synthetic_service(
        {"checks/sra_guardduty_01.py": _check_src("SRA_GUARDDUTY_01", check_id=None)}
    )

    with pytest.raises(CheckIdentityError) as excinfo:
        importlib.import_module(f"{pkg}.checks.sra_guardduty_01")

    rendered = str(excinfo.value)
    # 4.16: the class and the module file.
    assert "SRA_GUARDDUTY_01" in rendered
    assert "sra_guardduty_01.py" in rendered
    assert "meta" in rendered


def test_an_inherited_meta_does_not_satisfy_the_metadata_rule(synthetic_service):
    # vars(cls), not getattr(cls, "meta"). A check inheriting a base class that
    # carries a metadata literal would otherwise register under an ID it does
    # not own -- and, worse, under the ID the base class declared.
    pkg = synthetic_service(
        {
            "base.py": _check_src("GuardDutyCheck", check_id="SRA-GUARDDUTY-01"),
            "checks/sra_guardduty_01.py": _check_src(
                "SRA_GUARDDUTY_01",
                check_id=None,
                bases="GuardDutyCheck",
                extra="from ..base import GuardDutyCheck\n",
            ),
        }
    )

    with pytest.raises(CheckIdentityError) as excinfo:
        importlib.import_module(f"{pkg}.checks.sra_guardduty_01")

    assert "declares no meta of its own" in str(excinfo.value)
    assert "SRA-GUARDDUTY-01" not in registry.all_checks()


def test_a_missing_meta_registers_nothing(synthetic_service):
    before = dict(registry.all_checks())
    pkg = synthetic_service(
        {"checks/sra_guardduty_01.py": _check_src("SRA_GUARDDUTY_01", check_id=None)}
    )

    with pytest.raises(CheckIdentityError):
        importlib.import_module(f"{pkg}.checks.sra_guardduty_01")

    assert dict(registry.all_checks()) == before


# --------------------------------------------------------------------------
# Shape rule: no check inherits another check (Requirement 6.12)
# --------------------------------------------------------------------------

def test_a_check_inheriting_a_registered_check_raises(synthetic_service):
    # Two classes answering to one metadata lineage means a Finding is no
    # longer attributable to exactly one check ID. The subclass declares its
    # own valid meta, which is what carries it past 4.16, 4.5, and 4.6 to here.
    pkg = synthetic_service(
        {
            "checks/sra_guardduty_01.py": _check_src(
                "SRA_GUARDDUTY_01", check_id="SRA-GUARDDUTY-01"
            ),
            "checks/sra_guardduty_02.py": _check_src(
                "SRA_GUARDDUTY_02",
                check_id="SRA-GUARDDUTY-02",
                bases="SRA_GUARDDUTY_01",
                extra="from .sra_guardduty_01 import SRA_GUARDDUTY_01\n",
            ),
        }
    )
    importlib.import_module(f"{pkg}.checks.sra_guardduty_01")

    with pytest.raises(CheckIdentityError) as excinfo:
        importlib.import_module(f"{pkg}.checks.sra_guardduty_02")

    rendered = str(excinfo.value)
    assert "inherits from another check" in rendered
    assert "SRA_GUARDDUTY_01" in rendered
    assert "SRA_GUARDDUTY_02" in rendered
    # The offending subclass contributes no entry; the base keeps its own.
    catalog = registry.all_checks()
    assert "SRA-GUARDDUTY-02" not in catalog
    assert "SRA-GUARDDUTY-01" in catalog


def test_the_inheritance_rule_walks_the_whole_mro(synthetic_service):
    # A registered check two levels up is still a registered check among the
    # bases. The intermediate sits in base.py so it is itself skipped, which
    # is exactly how this would sneak in.
    pkg = synthetic_service(
        {
            "checks/sra_guardduty_01.py": _check_src(
                "SRA_GUARDDUTY_01", check_id="SRA-GUARDDUTY-01"
            ),
            "base.py": (
                _PRELUDE
                + "from .checks.sra_guardduty_01 import SRA_GUARDDUTY_01\n"
                + "\n\nclass DerivedBase(SRA_GUARDDUTY_01):\n"
                + '    """An intermediate base outside a check module."""\n\n'
                + "    pass\n"
            ),
            "checks/sra_guardduty_03.py": _check_src(
                "SRA_GUARDDUTY_03",
                check_id="SRA-GUARDDUTY-03",
                bases="DerivedBase",
                extra="from ..base import DerivedBase\n",
            ),
        }
    )
    importlib.import_module(f"{pkg}.checks.sra_guardduty_01")

    with pytest.raises(CheckIdentityError) as excinfo:
        importlib.import_module(f"{pkg}.checks.sra_guardduty_03")

    assert "inherits from another check" in str(excinfo.value)
    assert "SRA-GUARDDUTY-03" not in registry.all_checks()


# --------------------------------------------------------------------------
# Shape rule: no shadowed metadata property (Requirement 6.12)
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "attribute, literal",
    [
        pytest.param("check_id", '"SRA-GUARDDUTY-01"', id="check_id"),
        pytest.param("service", '"GuardDuty"', id="service"),
        pytest.param("severity", "Severity.HIGH", id="severity"),
        pytest.param("account_type", "AccountType.APPLICATION", id="account_type"),
    ],
)
def test_a_class_attribute_shadowing_a_metadata_property_raises(
    synthetic_service, attribute, literal
):
    # Each of the four is a read-only property delegating to meta. A class
    # attribute of the same name shadows the property and silently wins, so
    # identity would no longer come only from meta -- and the values agree with
    # the metadata here, which is what makes the defect invisible in review.
    pkg = synthetic_service(
        {
            "checks/sra_guardduty_01.py": _check_src(
                "SRA_GUARDDUTY_01",
                check_id="SRA-GUARDDUTY-01",
                class_attrs=f"{attribute} = {literal}\n",
            )
        }
    )

    with pytest.raises(CheckIdentityError) as excinfo:
        importlib.import_module(f"{pkg}.checks.sra_guardduty_01")

    rendered = str(excinfo.value)
    assert f"SRA_GUARDDUTY_01.{attribute}" in rendered
    assert "sra_guardduty_01.py" in rendered
    assert "SRA-GUARDDUTY-01" not in registry.all_checks()


def test_a_shadow_on_an_intermediate_base_class_raises(synthetic_service):
    # The rule walks cls and every base below SecurityCheck, so a service base
    # class in base.py -- itself skipped by the eligibility rule, and therefore
    # never checked in its own right -- cannot smuggle a shadow in either. This
    # is the shape the pre-change `account_type="account"` in
    # services/config/base.py would have taken.
    pkg = synthetic_service(
        {
            "base.py": _check_src(
                "GuardDutyCheck",
                check_id=None,
                class_attrs=(
                    'NAMESPACE = "guardduty"\n'
                    "account_type = AccountType.APPLICATION\n"
                ),
            ),
            "checks/sra_guardduty_01.py": _check_src(
                "SRA_GUARDDUTY_01",
                check_id="SRA-GUARDDUTY-01",
                bases="GuardDutyCheck",
                extra="from ..base import GuardDutyCheck\n",
            ),
        }
    )

    with pytest.raises(CheckIdentityError) as excinfo:
        importlib.import_module(f"{pkg}.checks.sra_guardduty_01")

    rendered = str(excinfo.value)
    assert "GuardDutyCheck.account_type" in rendered
    assert "SRA-GUARDDUTY-01" not in registry.all_checks()


def test_an_unrelated_class_attribute_is_fine(synthetic_service):
    # Only the four metadata names are forbidden. A service base class's
    # NAMESPACE, and a check's own private constants, must keep working.
    pkg = synthetic_service(
        {
            "checks/sra_guardduty_01.py": _check_src(
                "SRA_GUARDDUTY_01",
                check_id="SRA-GUARDDUTY-01",
                class_attrs=(
                    'NAMESPACE = "guardduty"\n'
                    '_EXPECTED_FEATURES = ("S3_DATA_EVENTS",)\n'
                ),
            )
        }
    )

    importlib.import_module(f"{pkg}.checks.sra_guardduty_01")

    assert "SRA-GUARDDUTY-01" in registry.all_checks()

# --------------------------------------------------------------------------
# Shape rule: the discriminator table belongs to the service (Requirement 4.4)
#
# NOT_CONFIGURED_ERRORS declares which (operation, code) pairs mean "the
# control is not configured". Its whole purpose is that two checks reading the
# same error result from the same operation cannot classify it differently, so a
# check that declares its own has re-created the per-check classification the
# client error contract removes -- invisibly, because shadowing a ClassVar is
# legal Python and the check keeps working.
# --------------------------------------------------------------------------


def test_a_check_declaring_the_discriminator_table_raises(synthetic_service):
    # The table is legal on a service base class and forbidden on a check. The
    # value declared here is well-formed, which is the point: the defect is
    # *where* it is declared, not what it says, so nothing else can catch it.
    pkg = synthetic_service(
        {
            "checks/sra_guardduty_01.py": _check_src(
                "SRA_GUARDDUTY_01",
                check_id="SRA-GUARDDUTY-01",
                class_attrs=(
                    "NOT_CONFIGURED_ERRORS = {\n"
                    '    "DescribeOrganizationConfiguration": {\n'
                    '        "BadRequestException": NotConfigured(evidence="e"),\n'
                    "    }\n"
                    "}\n"
                ),
                extra="from sraverify.core.aws_errors import NotConfigured\n",
            )
        }
    )

    with pytest.raises(CheckIdentityError) as excinfo:
        importlib.import_module(f"{pkg}.checks.sra_guardduty_01")

    rendered = str(excinfo.value)
    assert "NOT_CONFIGURED_ERRORS" in rendered
    assert "SRA_GUARDDUTY_01" in rendered
    assert "service base class" in rendered
    assert "SRA-GUARDDUTY-01" not in registry.all_checks()


def test_an_empty_discriminator_table_on_a_check_still_raises(synthetic_service):
    # An empty table changes no behaviour, and is still refused. The rule is
    # about ownership of the declaration, not about its contents: admitting the
    # empty case would leave "declare it empty, then fill it in later" open as a
    # way past the rule, and the second edit would not re-trigger it.
    pkg = synthetic_service(
        {
            "checks/sra_guardduty_01.py": _check_src(
                "SRA_GUARDDUTY_01",
                check_id="SRA-GUARDDUTY-01",
                class_attrs="NOT_CONFIGURED_ERRORS = {}\n",
            )
        }
    )

    with pytest.raises(CheckIdentityError):
        importlib.import_module(f"{pkg}.checks.sra_guardduty_01")

    assert "SRA-GUARDDUTY-01" not in registry.all_checks()


def test_a_service_base_class_may_declare_the_discriminator_table(synthetic_service):
    # The positive case, and the one that must keep working: every migrated
    # service declares its table on base.py, which the eligibility rule skips in
    # its own right. The check inherits it and registers cleanly.
    pkg = synthetic_service(
        {
            "base.py": _check_src(
                "GuardDutyCheck",
                check_id=None,
                class_attrs=(
                    'NAMESPACE = "guardduty"\n'
                    "NOT_CONFIGURED_ERRORS = {\n"
                    '    "DescribeOrganizationConfiguration": {\n'
                    '        "BadRequestException": NotConfigured(evidence="e"),\n'
                    "    }\n"
                    "}\n"
                ),
                extra="from sraverify.core.aws_errors import NotConfigured\n",
            ),
            "checks/sra_guardduty_01.py": _check_src(
                "SRA_GUARDDUTY_01",
                check_id="SRA-GUARDDUTY-01",
                bases="GuardDutyCheck",
                extra="from ..base import GuardDutyCheck\n",
            ),
        }
    )

    module = importlib.import_module(f"{pkg}.checks.sra_guardduty_01")

    assert "SRA-GUARDDUTY-01" in registry.all_checks()
    # Inherited, not declared: the rule reads vars(cls), so inheritance is fine.
    cls = module.SRA_GUARDDUTY_01
    assert "NOT_CONFIGURED_ERRORS" not in vars(cls)
    assert "DescribeOrganizationConfiguration" in cls.NOT_CONFIGURED_ERRORS


def test_the_table_rule_is_checked_before_registration(synthetic_service):
    # Same "register LAST" guarantee the other shape rules have: a module that
    # fails this rule leaves the registry byte-identical, so a failed import
    # contributes no partial catalog entry.
    before = dict(registry.all_checks())

    pkg = synthetic_service(
        {
            "checks/sra_guardduty_02.py": _check_src(
                "SRA_GUARDDUTY_02",
                check_id="SRA-GUARDDUTY-02",
                class_attrs="NOT_CONFIGURED_ERRORS = {}\n",
            )
        }
    )

    with pytest.raises(CheckIdentityError):
        importlib.import_module(f"{pkg}.checks.sra_guardduty_02")

    assert dict(registry.all_checks()) == before


def test_the_default_table_is_empty_and_shared(synthetic_service):
    # SecurityCheck's default classifies nothing, so an unmigrated service's
    # checks resolve every error to ERROR. That is the safe default, and it is
    # what makes the migration incremental: a service with no table yet cannot
    # emit a fabricated FAIL.
    pkg = synthetic_service(
        {
            "checks/sra_guardduty_01.py": _check_src(
                "SRA_GUARDDUTY_01", check_id="SRA-GUARDDUTY-01"
            )
        }
    )

    module = importlib.import_module(f"{pkg}.checks.sra_guardduty_01")

    assert module.SRA_GUARDDUTY_01.NOT_CONFIGURED_ERRORS == {}
