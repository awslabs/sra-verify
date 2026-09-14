"""Catalog-wide pass asserting every registered check is executable (task 17.5).

This module implements **Property 13: every registered check is executable**:

    ∀ registered ``cls``: ``cls`` defines ``execute`` and instantiating ``cls``
    succeeds -- i.e. no ``abstractmethod`` remains unimplemented.

**Validates: Requirements 6.1, 6.2**

Why this is an enumeration and not a sample
-------------------------------------------

The quantifier runs over a fixed finite set -- the real catalog, all 158 checks
migrated -- so the module enumerates it with ``pytest.mark.parametrize`` rather
than sampling it with ``hypothesis``. Two consequences, both wanted: the pass is
exhaustive, and a failure names the offending check ID in the test ID, so triage
starts at the right file instead of at a shrunk counterexample.

Every assertion here is a read over the registry plus an ``__init__`` that the
design pins as cheap. No credentials, no AWS call, no scan. ``execute()`` is
never *called* -- see the note on requirement 6.9 below.

What the property actually catches
----------------------------------

Requirement 6.2's purpose, stated in requirement 6's user story: a misspelled
``execute`` used to register cleanly and fail only when that check happened to
run. ``def exceute(self)`` left the abstract method unimplemented, but nothing
noticed until the orchestrator reached that check -- and then it produced one
synthetic ERROR row indistinguishable from a throttled API call. Making
``SecurityCheck`` an ``ABC`` moves that failure to construction. This module is
what confirms the move landed across the whole catalog rather than in principle.

``"execute" in vars(cls)`` is deliberately stricter than ``hasattr``. It demands
the method be declared in the check's *own* class body. Inheritance would be a
real defect and not a stylistic one: a service base class does not implement
``execute`` -- only leaf checks do, because the evaluation logic is the whole of
what distinguishes one check from the next -- so an inherited ``execute`` would
mean either a base class had grown one (and every check under it would silently
share one implementation) or a check had inherited from another check, which
requirement 6.12 forbids outright. ``test_no_intermediate_base_declares_execute``
asserts the base-class half directly.

The mechanism is verified, not assumed
--------------------------------------

``test_abstract_method_mechanism_is_in_place`` asserts that ``SecurityCheck`` is
genuinely an ``ABC`` and that ``SecurityCheck.execute.__isabstractmethod__`` is
``True``. Without it this module could pass vacuously: were the ``@abstractmethod``
decorator or the ``ABC`` base dropped, every ``cls()`` below would still succeed
and every ``__abstractmethods__`` would still be empty -- the property's
assertions would all hold while the guarantee they stand for had evaporated. It
is cheap and it closes the loop.

Requirement 6.9, and why it is asserted at the property boundary
----------------------------------------------------------------

Requirement 6.9 says a context-delegating property read before
``initialize(ctx)`` raises ``RuntimeError`` naming the property and the check ID,
rather than an opaque ``AttributeError`` on ``None``.
``test_uninitialized_context_read_is_attributable`` asserts exactly that, over
all seven properties and every registered check.

It does **not** assert it by calling ``execute()`` on an uninitialized instance,
which was the more direct-looking route. Two reasons, both measured against the
real catalog rather than assumed:

  * All 158 ``execute()`` bodies are generator functions, so the call itself runs
    no body at all. The assertion would need a ``next()`` to mean anything.
  * With that ``next()``, 136 of 158 raise the clear ``RuntimeError`` -- and 22
    raise ``AttributeError: 'NoneType' object has no attribute '_has'``. Those 22
    (shield 01-10 and 12-14, organizations 01-07, firewallmanager 01, waf 01)
    reach a service base accessor that touches ``self._ctx._has(...)`` directly
    instead of reading a context property first, so ``_require_ctx`` never runs.

Asserting the ``RuntimeError`` through ``execute()`` would therefore be a test
that fails on 22 checks for a reason outside this task's scope: the fix belongs
in those service base classes, which task 17.5 does not touch, and the design's
non-goals do not include routing base-class cache reads through ``_require_ctx``.
Scoping the assertion to the seven properties keeps it exhaustive and true rather
than flaky or selectively skipped. The narrower claim is also the one requirement
6.9 actually makes -- it is written about the properties, not about ``execute()``.

Worth recording as a follow-up, not a defect this module hides: the 22 checks'
opaque ``AttributeError`` is unreachable in a real scan, because the orchestrator
calls ``initialize(ctx)`` inside the same guarded block as ``execute()`` and
never advances a generator from an uninitialized check.

Registry snapshot and order independence
----------------------------------------

``_CATALOG`` is captured at *import* time. pytest imports every test module
during collection, before any fixture runs, so the snapshot is taken while the
registry is whole. Four sibling modules -- ``test_registry.py``,
``test_select.py``, ``test_check_registration.py``, and
``test_no_accumulator_property.py``'s neighbours -- empty the shared
module-level ``_REGISTRY`` inside a fixture and restore it afterwards. Even a
fixture that failed to restore could not affect this module, because
``all_checks()`` returns a proxy over a *copy* and ``sorted(...)`` materialises
it into a list of ``(id, class)`` pairs that holds the class objects directly.
Nothing here re-reads the registry at test time, and this module installs no
fixture of its own.

``import sraverify.services`` is present for its side effect and is not
removable: it is what triggers ``pkgutil`` discovery over the 18 service
packages, and therefore what populates the registry this module reads.
"""

from __future__ import annotations

import collections.abc
import inspect
from abc import ABCMeta
from typing import Any, get_args, get_origin

import pytest

import sraverify.services  # noqa: F401  -- side effect: populates the registry
from sraverify.core.check import SecurityCheck
from sraverify.core.finding import Finding
from sraverify.core.registry import all_checks

# ---------------------------------------------------------------------- #
# The catalog snapshot, taken at collection time.
# ---------------------------------------------------------------------- #

#: ``(check_id, check_class)`` pairs for the whole catalog, sorted by check ID.
_CATALOG: list[tuple[str, type[SecurityCheck]]] = sorted(all_checks().items())

#: Test IDs, so a failure reads ``[SRA-GUARDDUTY-01]`` rather than ``[cls17]``.
_CATALOG_IDS: list[str] = [check_id for check_id, _ in _CATALOG]

#: Applied to every per-check test below.
_over_catalog = pytest.mark.parametrize(
    ("check_id", "cls"), _CATALOG, ids=_CATALOG_IDS
)

#: The seven read-only properties that delegate to the ``ScanContext`` (6.9).
#: ``account_info`` is included even though ``account_id`` and ``account_name``
#: read through the same context call, because each is a separate property with
#: its own ``_require_ctx`` argument and the message names that argument.
_CONTEXT_PROPERTIES: tuple[str, ...] = (
    "session",
    "regions",
    "account_info",
    "account_id",
    "account_name",
    "audit_accounts",
    "log_archive_accounts",
)


def _return_annotation(func: Any) -> Any:
    """Return *func*'s resolved return annotation.

    ``inspect.get_annotations(..., eval_str=True)`` is used rather than reading
    ``__annotations__`` directly so the assertion holds whether the defining
    module carries ``from __future__ import annotations`` or not. Under the
    string form the raw dict would hold ``"Iterable[Finding]"``, and an identity
    check against the real generic alias would fail for a reason that has
    nothing to do with the check.

    Args:
        func: The function whose annotations to resolve.

    Returns:
        The resolved ``return`` annotation.

    Raises:
        AssertionError: The function carries no return annotation.
    """
    resolved = inspect.get_annotations(func, eval_str=True)
    assert "return" in resolved, (
        f"{func.__qualname__} carries no return annotation; requirement 6.1 "
        f"fixes it at Iterable[Finding]"
    )
    return resolved["return"]


# ---------------------------------------------------------------------- #
# Non-vacuity, and the mechanism the property depends on.
# ---------------------------------------------------------------------- #


def test_catalog_is_not_empty() -> None:
    """The snapshot is non-empty, so the parametrised passes are not vacuous.

    Deliberately a floor and not an exact count: task 17.2's registry-filesystem
    bijection owns the precise cardinality, and duplicating it here would give
    two places to update when a check is added and one of them would be missed.

    Validates: Requirements 6.1, 6.2
    """
    assert _CATALOG, (
        "the check registry was empty at collection time; every per-check "
        "assertion in this module would pass vacuously"
    )
    assert len(_CATALOG) == len(set(_CATALOG_IDS)), (
        "duplicate check IDs in the snapshot, which a MappingProxyType over a "
        "dict should make impossible"
    )


def test_abstract_method_mechanism_is_in_place() -> None:
    """``SecurityCheck`` is an ABC whose single abstract method is ``execute``.

    Verifies the mechanism the rest of this module depends on instead of
    assuming it. Drop the ``ABC`` base or the ``@abstractmethod`` decorator and
    every other assertion here still passes while the guarantee is gone.

    Validates: Requirements 6.1, 6.2
    """
    assert isinstance(SecurityCheck, ABCMeta), (
        "SecurityCheck is not built by ABCMeta, so abstract-method enforcement "
        "is not active and an unimplemented execute() would construct happily"
    )
    assert inspect.isabstract(SecurityCheck), (
        "SecurityCheck reports as concrete; it has no unimplemented abstract "
        "method, so a check with no execute() would not fail at construction"
    )
    assert getattr(SecurityCheck.execute, "__isabstractmethod__", False) is True, (
        "SecurityCheck.execute is not marked abstract; a misspelled execute in "
        "a check would register cleanly and fail only when that check ran"
    )
    assert SecurityCheck.__abstractmethods__ == frozenset({"execute"}), (
        f"execute is not the single abstract method of the contract; "
        f"__abstractmethods__ is {set(SecurityCheck.__abstractmethods__)!r}"
    )

    # The enforcement is observable, not just declared.
    with pytest.raises(TypeError) as excinfo:
        SecurityCheck()  # type: ignore[abstract]
    message = str(excinfo.value)
    assert "execute" in message, (
        f"the TypeError from constructing SecurityCheck does not name the "
        f"unimplemented method: {message!r}"
    )


def test_execute_is_declared_abstract_with_no_parameters_beyond_self() -> None:
    """The abstract declaration itself takes only the instance (6.1).

    A base declaration that admitted a parameter would let a check declare
    ``execute(self, region)``, satisfy the ABC, and then be called with no
    argument by the orchestrator -- a ``TypeError`` per check at scan time.

    Validates: Requirements 6.1
    """
    parameters = list(inspect.signature(SecurityCheck.execute).parameters)
    assert parameters == ["self"], (
        f"SecurityCheck.execute declares parameters {parameters!r}; requirement "
        f"6.1 fixes it at the instance alone"
    )


# ---------------------------------------------------------------------- #
# Property 13, per registered check.
# ---------------------------------------------------------------------- #


@_over_catalog
def test_registered_check_declares_execute_in_its_own_body(
    check_id: str, cls: type[SecurityCheck]
) -> None:
    """Property 13, first half: ``execute`` is declared by the check itself.

    ``vars(cls)`` rather than ``hasattr``: an inherited ``execute`` would mean a
    service base class had grown one, or a check had inherited from another
    check. Both are defects, and both would satisfy a ``hasattr`` test.

    Validates: Requirements 6.1, 6.2
    """
    assert "execute" in vars(cls), (
        f"{check_id} ({cls.__module__}) does not declare execute in its own "
        f"class body; it is inheriting one, which means either a service base "
        f"class implements execute or this check inherits from another check"
    )

    func = vars(cls)["execute"]
    assert callable(func), (
        f"{check_id}.execute is not callable: {type(func).__name__}"
    )
    assert not getattr(func, "__isabstractmethod__", False), (
        f"{check_id}.execute is itself marked abstract, so the class cannot be "
        f"instantiated"
    )
    assert list(inspect.signature(func).parameters) == ["self"], (
        f"{check_id}.execute takes parameters beyond the instance: "
        f"{list(inspect.signature(func).parameters)!r}"
    )


@_over_catalog
def test_no_intermediate_base_declares_execute(
    check_id: str, cls: type[SecurityCheck]
) -> None:
    """No class between the check and ``SecurityCheck`` implements ``execute``.

    The other half of the ``vars(cls)`` assertion above, stated from the base
    class's side. A service base class that grew an ``execute`` would make every
    check under it instantiable whether or not it had implemented the method,
    which is precisely the failure requirement 6.2 exists to prevent.

    Validates: Requirements 6.1, 6.2
    """
    mro = cls.__mro__
    assert SecurityCheck in mro, (
        f"{check_id} does not derive from SecurityCheck; how it registered is "
        f"itself the question"
    )

    intermediates = mro[1 : mro.index(SecurityCheck)]
    offenders = [base.__name__ for base in intermediates if "execute" in vars(base)]
    assert not offenders, (
        f"{check_id} inherits from {offenders!r}, which declare execute; only "
        f"leaf check classes may implement it"
    )


@_over_catalog
def test_registered_check_instantiates(
    check_id: str, cls: type[SecurityCheck]
) -> None:
    """Property 13, second half: ``cls()`` succeeds with nothing left abstract.

    The ``TypeError`` this rules out is requirement 6.2's whole subject. It also
    pins the post-construction state requirement 6.5 fixes -- a null context and
    an empty client mapping -- because a subclass ``__init__`` that did more than
    that would be doing per-scan work at construction, and selection constructs
    nothing while ``run_checks`` constructs every selected check.

    Validates: Requirements 6.1, 6.2
    """
    remaining = getattr(cls, "__abstractmethods__", frozenset())
    assert remaining == frozenset(), (
        f"{check_id} leaves abstract methods unimplemented: {set(remaining)!r}"
    )

    try:
        instance = cls()
    except TypeError as exc:  # pragma: no cover -- the failure this rules out
        pytest.fail(
            f"{check_id} ({cls.__module__}) could not be constructed: {exc}. An "
            f"abstract method is unimplemented, or __init__ requires an "
            f"argument the orchestrator does not supply."
        )

    assert isinstance(instance, SecurityCheck)
    assert isinstance(instance, cls)
    assert instance._ctx is None, (
        f"{check_id} attached a ScanContext at construction; initialize(ctx) is "
        f"the only initialization path"
    )
    assert instance._clients == {}, (
        f"{check_id} populated its client mapping at construction: "
        f"{instance._clients!r}"
    )

    # Construction did not consume the class-level metadata or shadow it.
    assert instance.check_id == check_id, (
        f"{check_id} reports check_id {instance.check_id!r} on an instance"
    )


@_over_catalog
def test_execute_is_annotated_to_return_an_iterable_of_findings(
    check_id: str, cls: type[SecurityCheck]
) -> None:
    """``execute`` is annotated as returning an iterable of ``Finding``.

    Requirement 6.1 fixes the return type at ``Iterable[Finding]``, a type a
    generator function satisfies. The annotation is not enforced at run time, so
    this is the assertion that keeps the 158 declarations honest -- and it is the
    one that would notice a body migrated to yield something other than a
    ``Finding``, since the element type is checked and not just the container.

    Validates: Requirements 6.1
    """
    annotation = _return_annotation(vars(cls)["execute"])

    origin = get_origin(annotation)
    assert origin is not None, (
        f"{check_id}.execute is annotated {annotation!r}, which is not a "
        f"parameterised iterable; requirement 6.1 fixes it at Iterable[Finding]"
    )
    assert isinstance(origin, type) and issubclass(
        origin, collections.abc.Iterable
    ), (
        f"{check_id}.execute returns {annotation!r}, whose origin {origin!r} is "
        f"not an iterable type; run_checks does list(check.execute())"
    )

    args = get_args(annotation)
    assert Finding in args, (
        f"{check_id}.execute is annotated {annotation!r}; the element type must "
        f"be Finding, since Finding is the only thing write_csv_output renders"
    )


@_over_catalog
def test_uninitialized_context_read_is_attributable(
    check_id: str, cls: type[SecurityCheck]
) -> None:
    """Reading a context property before ``initialize(ctx)`` names the check.

    Scoped to the seven properties rather than driven through ``execute()``: see
    the module docstring. The claim is requirement 6.9's own, and it holds for
    every registered check, which is what makes it worth asserting exhaustively.

    Validates: Requirements 6.9
    """
    instance = cls()

    for name in _CONTEXT_PROPERTIES:
        with pytest.raises(RuntimeError) as excinfo:
            getattr(instance, name)
        message = str(excinfo.value)
        assert check_id in message, (
            f"the RuntimeError from reading {check_id}.{name} uninitialized "
            f"does not name the check: {message!r}"
        )
        assert name in message, (
            f"the RuntimeError from reading {check_id}.{name} uninitialized "
            f"does not name the property: {message!r}"
        )
