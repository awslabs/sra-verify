"""Catalog-wide identity pass over the real 158 checks (task 17.1).

This module implements **Property 1: four-way check identity**:

    ∀ ``(check_id, cls)`` ∈ ``all_checks()``:
    ``cls.meta.check_id == check_id == cls.__name__.replace("_", "-")`` and
    ``Path(module_of(cls).__file__).stem == check_id.lower().replace("-", "_")``.

**Validates: Requirements 4.1, 4.3, 4.5, 4.6, 4.14, 13.5**

Enumerated, not sampled
-----------------------

The design's testing strategy takes properties 1-5 and 13 as a single pass over
the real catalog rather than as ``hypothesis``-generated cases, and the reason is
that the quantifier here ranges over a *fixed finite set*. There are exactly 158
registered checks, they are known at collection time, they need no credentials to
enumerate, and enumerating all of them is both cheaper and strictly stronger than
drawing samples from them. A generated variant would have to synthesise check
classes, and a synthetic class is precisely the thing this property is not about:
the claim is about the catalog that ships.

Why four expressions of one identity
------------------------------------

A check's identity is written down in four independent places, and the registry
is only trustworthy if they agree:

  * the **module file stem** -- ``sra_guardduty_01`` -- which
    ``__init_subclass__`` treats as the authority and from which the expected
    check ID is derived (4.3);
  * the **metadata** ``check_id`` (4.5). Still load-bearing even with metadata
    declared inline, because nothing stops an author writing
    ``check_id="SRA-GUARDDUTY-02"`` inside ``sra_guardduty_01.py``;
  * the **class name** ``SRA_GUARDDUTY_01`` (4.6);
  * the **registry key**, which is what ``--check`` matches against and what
    lands in the ``CheckId`` CSV column.

Plus a fifth, which is a *filing* rule rather than a naming one: the service
package the module physically sits under must match the service segment of its
own file name (4.14). ``services/guardduty/checks/sra_shield_01.py`` satisfies
all four rules above and is still wrong -- it would inherit ``GuardDutyCheck``,
run against GuardDuty's namespace, accessors and client, and report
``Service=Shield`` on every row it emits.

Is this not just re-testing ``__init_subclass__``?
--------------------------------------------------

No, and the distinction matters. ``tests/unit/core/test_check_registration.py``
tests the *hook*, against synthetic modules written into ``tmp_path``: it proves
that a violation raises. This module tests the *catalog*, and proves a different
thing -- that the hook actually ran over all 158 real checks and that none of
them slipped past it. Those come apart in ways that are not hypothetical:

  * an ``__init_subclass__`` that returned early for some reachable reason (a
    module with no ``__file__``, a re-import through a second module name) would
    leave a check registered without ever having been cross-checked, and the
    hook's own unit tests would all still pass;
  * a check reaching the registry through some path other than the hook would be
    invisible to those tests and visible here;
  * ``--check SRA-X-NN`` resolves against the registry key, while the finding
    rows carry ``meta.check_id``. If those two ever diverged, selecting a check
    by ID would run it and then attribute its rows to a different ID.

The derivations below are therefore written out locally from ``str`` operations
rather than imported from ``core/check.py``. Importing ``CHECK_MODULE_RE`` and
reusing the production derivation would make the test agree with the
implementation by construction, which is the one thing a cross-check must not do.
``CHECK_ID_RE`` *is* imported, because criterion 13.5 is a claim about that exact
published pattern -- that the ``SRA-<SERVICE>-NN`` format with a two-digit
zero-padded number survived this change -- and restating the regex here would
weaken it to a claim about a copy.

Parametrized, so a failure names the check
------------------------------------------

One loop over 158 checks inside a single test reports the first violation as one
opaque assertion and stops. Parametrizing over ``sorted(all_checks().items())``
gives 158 named cases, so the failure output reads
``test_check_identity_is_four_way_consistent[SRA-SHIELD-07]`` and every *other*
offender is reported in the same run rather than hidden behind the first.

The count assertion is not ceremony
-----------------------------------

``test_catalog_is_populated`` guards against the failure mode that would make
everything above vacuous. Discovery is by ``pkgutil`` walk, and a walk that
matched nothing -- a renamed package, a lost ``checks`` subpackage, an import
that quietly no-oped -- registers zero checks and raises nothing. A parametrized
test over an empty catalog does not fail; it collects zero cases and the suite
reports success. So the catalog's size is asserted separately, and asserted
against the file count on disk as well as against the literal 158, so the number
cannot be kept green by editing it alone.

Reads the real registry -- no isolation fixture
-----------------------------------------------

Deliberately no ``isolated_registry`` here. Four sibling modules under
``tests/unit/core/`` snapshot ``_REGISTRY`` and **clear** it, because they need a
synthetic catalog; this module needs the opposite, and a fixture that cleared the
registry would empty the very catalog under test and reduce the pass to zero
cases. Those siblings restore what they snapshot, so nothing here depends on test
order -- and ``_CATALOG`` is captured once at import time, before any test in the
session has run, which makes that independence structural rather than a matter of
trusting each sibling's teardown.
"""
from __future__ import annotations

from pathlib import Path
import sys
from types import ModuleType

import pytest

# Imported for its registration side effect: the walk over 18 service packages
# and 158 check modules is what populates the registry this module reads. Drop
# it and every parametrized case below silently disappears.
import sraverify.services  # noqa: F401
from sraverify.core.check import SecurityCheck
from sraverify.core.metadata import CHECK_ID_RE
from sraverify.core.registry import all_checks

#: The catalog, snapshotted at import time -- i.e. at collection, before any
#: test in the session has had a chance to touch ``_REGISTRY``. Parametrization
#: reads this, so a sibling module's registry fixture cannot shrink the pass.
_CATALOG: dict[str, type[SecurityCheck]] = dict(all_checks())

#: The catalog size this change ships with. Cross-checked against the file count
#: on disk in ``test_catalog_is_populated``, so bumping this literal alone does
#: not make a lost check pass.
EXPECTED_CHECK_COUNT = 167

#: ``sraverify/services``, located from this test module rather than from a
#: hard-coded path: ``tests/property/`` -> ``tests/`` -> the package root.
_SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"

#: Every check module file on disk, which is what the registry must mirror.
_CHECK_MODULE_GLOB = "*/checks/sra_*.py"


def module_of(cls: type[SecurityCheck]) -> ModuleType:
    """Return the module object that defined *cls*.

    Read from the loaded-module table rather than by re-importing, so this asks
    "which module is this class actually from" instead of "which module would
    that name import to now".

    Args:
        cls: A registered check class.

    Returns:
        The module named by ``cls.__module__``.

    Raises:
        AssertionError: ``cls.__module__`` is absent from ``sys.modules`` or the
            module carries no file location. Either would mean the class was
            created dynamically, which ``__init_subclass__`` leaves
            unregistered (4.13), so reaching this from a registered class is
            itself the defect.
    """
    module = sys.modules.get(cls.__module__)
    assert module is not None, (
        f"{cls.__name__} is registered but its module {cls.__module__!r} is "
        f"not in sys.modules"
    )
    assert getattr(module, "__file__", None) is not None, (
        f"{cls.__name__} is registered but its module {cls.__module__!r} "
        f"carries no __file__"
    )
    return module


def split_stem(stem: str) -> tuple[str, str]:
    """Split a check module file stem into its service segment and number.

    Derived here with plain string operations rather than through
    ``core/check.py``'s ``CHECK_MODULE_RE``, so this module cross-checks the
    production derivation instead of restating it.

    Args:
        stem: A check module file stem, e.g. ``"sra_guardduty_01"``.

    Returns:
        ``(service_segment, number)``, e.g. ``("guardduty", "01")``.

    Raises:
        AssertionError: The stem is not three underscore-delimited parts
            beginning with ``sra``. The service segment admits no underscore of
            its own, which is what makes the split unambiguous.
    """
    parts = stem.split("_")
    assert len(parts) == 3, (
        f"check module stem {stem!r} is not three underscore-delimited parts; "
        f"the service segment may not contain an underscore"
    )
    assert parts[0] == "sra", f"check module stem {stem!r} does not begin with 'sra'"
    return parts[1], parts[2]


@pytest.mark.parametrize(
    ("check_id", "cls"),
    sorted(_CATALOG.items()),
    ids=[check_id for check_id in sorted(_CATALOG)],
)
def test_check_identity_is_four_way_consistent(
    check_id: str, cls: type[SecurityCheck]
) -> None:
    """Property 1: all four expressions of one check's identity agree.

    Validates: Requirements 4.1, 4.3, 4.5, 4.6, 4.14, 13.5
    """
    module = module_of(cls)
    module_path = Path(module.__file__)
    stem = module_path.stem

    # ---- 13.5: the published check ID format survived this change ---- #
    # Anchored with fullmatch: CHECK_ID_RE carries no anchors of its own, so
    # a bare search would accept "XSRA-GUARDDUTY-01Y".
    assert CHECK_ID_RE.fullmatch(check_id), (
        f"registry key {check_id!r} does not match the published check ID "
        f"pattern {CHECK_ID_RE.pattern!r} ({module_path})"
    )

    # ---- 4.5: metadata check_id == registry key ---------------------- #
    # If these diverged, `--check SRA-X-NN` would resolve through the key and
    # then attribute every emitted row to a different CheckId.
    assert cls.meta.check_id == check_id, (
        f"metadata check_id {cls.meta.check_id!r} disagrees with the registry "
        f"key {check_id!r} ({module_path})"
    )

    # ---- 4.6: class name == check ID with '-' as '_' ----------------- #
    assert check_id == cls.__name__.replace("_", "-"), (
        f"class name {cls.__name__!r} does not render to the check ID "
        f"{check_id!r} ({module_path})"
    )
    # The same identity read the other way. Not redundant: it pins the
    # substitution as a bijection, so a class name carrying a hyphen-free
    # oddity cannot satisfy one direction while failing the other.
    assert cls.__name__ == check_id.replace("-", "_"), (
        f"check ID {check_id!r} does not render to the class name "
        f"{cls.__name__!r} ({module_path})"
    )

    # ---- 4.3: file stem == check ID, lower-cased, '-' as '_' --------- #
    # The file stem is the authority the other three are derived from, and 4.3
    # requires that derivation to be reversible.
    assert stem == check_id.lower().replace("-", "_"), (
        f"module file stem {stem!r} disagrees with the check ID {check_id!r} "
        f"({module_path})"
    )

    service_segment, number = split_stem(stem)

    # The forward derivation, spelled out: upper-case the service segment and
    # join SRA, it, and the two-digit number with hyphens (4.3).
    assert check_id == f"SRA-{service_segment.upper()}-{number}", (
        f"check ID {check_id!r} is not what the file stem {stem!r} derives to "
        f"({module_path})"
    )
    # 13.5's two-digit zero-padded clause, read off the number itself.
    assert len(number) == 2 and number.isdigit() and number != "00", (
        f"check number {number!r} is not a two-digit zero-padded number in "
        f"01-99 ({module_path})"
    )

    # ---- 4.14: filed under the service its own name claims ---------- #
    # cls.__module__ is "sraverify.services.<svc>.checks.sra_<svc>_NN".
    parts = cls.__module__.split(".")
    assert len(parts) >= 3 and parts[-2] == "checks", (
        f"{cls.__name__} does not sit in a service checks package: "
        f"{cls.__module__!r} ({module_path})"
    )
    assert parts[-3] == service_segment, (
        f"{cls.__name__} is filed under the {parts[-3]!r} service package but "
        f"its file name says {service_segment!r} ({module_path})"
    )
    # And the same claim against the directory the file physically lives in,
    # since the dotted name and the path can disagree.
    assert module_path.parent.name == "checks", (
        f"{module_path} is not inside a 'checks' directory"
    )
    assert module_path.parent.parent.name == service_segment, (
        f"{module_path} sits under the {module_path.parent.parent.name!r} "
        f"service directory but its file name says {service_segment!r}"
    )


def test_catalog_is_populated() -> None:
    """The catalog is non-empty and holds every check module on disk.

    Without this, the parametrized pass above is vacuous: ``pkgutil`` discovery
    that matched nothing registers nothing and raises nothing, and a
    parametrization over an empty mapping collects zero cases and reports
    success.

    Validates: Requirements 4.1, 4.3, 4.5, 4.6, 4.14, 13.5
    """
    assert _CATALOG, (
        "the check registry is empty, so every identity case above collected "
        "zero parameters and asserted nothing"
    )

    on_disk = sorted(path.stem for path in _SERVICES_DIR.glob(_CHECK_MODULE_GLOB))
    assert on_disk, f"no check module files found under {_SERVICES_DIR}"

    # Asserted against the files as well as against the literal, so the literal
    # cannot be edited to keep a lost check green.
    assert len(_CATALOG) == len(on_disk) == EXPECTED_CHECK_COUNT, (
        f"catalog holds {len(_CATALOG)} checks and {len(on_disk)} check module "
        f"files are on disk; expected {EXPECTED_CHECK_COUNT} of each"
    )

    # The live registry, read now rather than at import, still agrees. This is
    # what notices a sibling module that cleared the catalog without restoring
    # it -- which would not otherwise surface here, since the pass above reads
    # the import-time snapshot.
    assert dict(all_checks()) == _CATALOG, (
        "the live registry no longer matches the catalog captured at import "
        "time; something mutated it during the session"
    )
