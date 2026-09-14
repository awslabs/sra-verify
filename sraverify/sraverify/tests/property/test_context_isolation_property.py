"""Property-based test for per-scan context isolation (task 11.8).

This module implements **Property 18: returned findings hold no
``ScanContext``**:

    After ``run_checks`` returns, no ``ScanContext`` is reachable from the
    returned findings. Asserted with ``gc.get_referrers`` over the returned
    list, or by holding a ``weakref`` to the context and confirming it is dead
    after a ``gc.collect()``.

**Validates: Requirements 1.11, 10.7, 10.11**

Both halves of the design's argument are asserted here, because each one is a
different way for the same defect to survive:

  * **The inner half** -- ``findings = list(check.execute())`` inside the
    per-check guarded block (10.6). ``execute()`` is a generator in the
    migrated catalog, and a generator captures its frame; that frame holds
    ``self``, and ``self`` holds ``self._ctx``. An unconsumed or
    partially-consumed generator therefore keeps the whole ``ScanContext``, and
    every boto3 client it has cached, reachable past ``finally: del ctx``.
  * **The outer half** -- ``run_checks`` returns a concrete ``list`` (10.7).
    Were it a generator, or ``itertools.chain(...)``, or a ``map``, the
    ``finally: del ctx`` would not run until the *caller* finished consuming
    the result, and the frame holding ``ctx`` would stay alive until then. The
    inner ``list()`` would still be doing its job perfectly and the leak would
    simply move up one layer -- which is why ``type(findings) is list`` is an
    assertion in its own right rather than a type-annotation formality.

Neither half is hypothetical, and for the MCP server -- where ``run_checks`` is
called repeatedly in one long-lived process -- either one leaks a scan's worth
of clients per invocation while every test that checks *output* still passes.

Why the synthetic checks include a generator
-------------------------------------------

A check whose ``execute()`` does ``return [...]`` cannot exercise this property
at all: a list holds no frame, so there is nothing for the inner ``list()`` to
protect against. The drawn plan therefore always contains at least one
generator-bodied check, which is the migrated convention. Two further
generator shapes are drawn alongside it, because they are the cases where a
frame is *most* likely to be retained by something other than the loop: a
generator that raises on its first ``next()``, and one that raises after
yielding a row. Both leave an exception, a traceback, and a suspended frame in
play at the moment the per-check guard fires.

``test_a_live_generator_pins_the_context`` is the non-vacuity control. It
reproduces the leak deliberately -- holding a started generator across a
``gc.collect()`` -- and asserts the context is *still alive*. Without it, this
module would keep passing if ``ScanContext`` ever became unreachable-by-
construction for some unrelated reason, and the property would be asserting
nothing.

No AWS, and no reliance on credentials
--------------------------------------

Two structural guarantees rather than two conventions:

  * the session handed to ``SRAVerify`` is a ``_RefusingSession`` whose
    ``client()`` raises, so any code path that tried to reach AWS fails loudly
    instead of hanging on a network timeout;
  * ``ctx._account_info`` is pre-seeded by the recording factory, so
    ``ctx.get_account_info()`` returns from its cache and never reaches STS.
    ``run_checks`` calls it once before the loop, and every ``passed()`` /
    ``failed()`` call goes through it too.

Registry and import isolation
-----------------------------

``core/registry.py`` keeps a module-level ``_REGISTRY``.
``_isolated_registry`` snapshots it, empties it, registers the synthetic checks
for the duration, and restores the snapshot afterwards -- mutating the original
dict in place rather than rebinding the name, so a module that captured a
reference to it still sees the restored contents. Emptying it is not
housekeeping: with the real catalog present, ``account_type='all'`` would
select 158 real checks and the scan would go to AWS.

``import sraverify.main`` also imports ``sraverify.services`` for its
registration side effect, and during Phase 2 that raises
``CheckIdentityError`` on the not-yet-migrated checks. ``_import_main`` tries
the honest import first and falls back to stubbing ``sraverify.services`` in
``sys.modules`` only if it fails, so this module runs both before Phase 3 (via
the stub) and after it (via the real import). Either way the registry is
emptied inside the test, so which path was taken does not change what runs.

Log-handler isolation
---------------------

Every scan in this module runs inside ``_production_log_handling``, and that is
load-bearing rather than tidy. ``run_checks`` logs its per-check failures with
``exc_info=True``, and a ``LogRecord`` built that way holds the traceback, which
holds the frames, one of which holds the check, which holds the ``ScanContext``.
pytest's logging plugin retains every record for the duration of the test, so
without the guard the ``weakref`` assertions here measure the harness's
retention instead of the orchestrator's lifetime. See that helper's docstring
for why the fix belongs in the observer and why it does not weaken anything.
"""
from __future__ import annotations

import contextlib
import gc
import logging
import sys
import types
import weakref
from typing import Any, Iterable, Iterator, Optional

import pytest
from hypothesis import HealthCheck, example, given, settings
from hypothesis import strategies as st

from sraverify.core import registry
from sraverify.core.check import SecurityCheck
from sraverify.core.enums import AccountType, Severity, Status
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.core.scan_context import ScanContext


# ---------------------------------------------------------------------- #
# Importing main.py, in both phases.
# ---------------------------------------------------------------------- #

def _import_main() -> types.ModuleType:
    """Import ``sraverify.main``, stubbing ``sraverify.services`` if it must.

    ``main.py`` carries ``import sraverify.services`` purely for the
    registration side effect, and until every check body is migrated that
    import raises ``CheckIdentityError``. The honest import is attempted first
    so that once the catalog is migrated this helper becomes a plain import and
    the real registration happens; the stub is a Phase 2 crutch and is applied
    only when the real thing fails.

    Returns:
        The imported ``sraverify.main`` module.
    """
    try:
        import sraverify.main as main_module
    except Exception:
        # A failed import removes 'sraverify.main' from sys.modules, so the
        # retry below re-executes the module body in full.
        sys.modules.setdefault(
            "sraverify.services", types.ModuleType("sraverify.services")
        )
        import sraverify.main as main_module
    return main_module


main = _import_main()


# ---------------------------------------------------------------------- #
# Probe fixtures: a session that refuses, and a pre-seeded identity.
# ---------------------------------------------------------------------- #

#: Pre-seeded into ``ctx._account_info`` so ``get_account_info()`` returns from
#: cache. Twelve digits, matching the shape of a real account ID, so a failure
#: message reads like the real thing.
_PROBE_ACCOUNT_ID = "111122223333"
_PROBE_ACCOUNT_NAME = "probe-account"

#: Passed explicitly as ``SRAVerify(regions=...)`` so ``check.regions`` returns
#: this list rather than lazily resolving enabled regions via
#: ``ec2:DescribeRegions``. Two regions, so a per-region check yields more than
#: one row and the loop is genuinely exercised.
_PROBE_REGIONS = ("us-east-1", "us-west-2")


class _RefusingSession:
    """A stand-in for ``boto3.Session`` that refuses to build a client.

    ``ScanContext`` stores whatever session it is handed and only touches it
    inside ``get_client``. Handing it this object turns "this test must not
    reach AWS" from a convention into a structural guarantee: a code path that
    tried would raise here rather than hang on a connect timeout or, worse,
    succeed against whatever credentials happen to be in the environment.
    """

    def client(self, *args: Any, **kwargs: Any) -> Any:
        """Refuse, naming the call that was attempted."""
        raise AssertionError(
            f"a context-isolation probe must issue no AWS call, but a client "
            f"was requested: args={args!r} kwargs={kwargs!r}"
        )


# ---------------------------------------------------------------------- #
# Synthetic check bodies, one per shape.
#
# Each is installed as ``execute`` on a throwaway subclass below. The shapes
# that matter are the generator ones: a list-returning body holds no frame, so
# it cannot exercise the inner ``list()`` at all.
# ---------------------------------------------------------------------- #

def _execute_generator(self: SecurityCheck) -> Iterator[Finding]:
    """Yield one PASS per region, as a generator. The migrated convention."""
    for region in self.regions:
        yield self.passed(
            region=region,
            resource_id=f"probe/{region}",
            actual_value="probe resource observed",
        )


def _execute_generator_empty(self: SecurityCheck) -> Iterator[Finding]:
    """Yield nothing, as a generator. A legal zero-row check."""
    yield from ()


def _execute_list(self: SecurityCheck) -> Iterable[Finding]:
    """Return a plain list of FAIL findings, which ``Iterable`` also admits."""
    return [
        self.failed(
            region=region,
            resource_id=None,
            actual_value="probe resource not configured",
        )
        for region in self.regions
    ]


def _execute_raise_before_yield(self: SecurityCheck) -> Iterator[Finding]:
    """Raise on the first ``next()``, with a suspended-then-dead frame."""
    raise RuntimeError("probe failure before the first yield")
    yield  # pragma: no cover - unreachable, but makes this a generator


def _execute_raise_after_yield(self: SecurityCheck) -> Iterator[Finding]:
    """Yield a row, then raise. The partial row is discarded with the generator."""
    yield self.passed(
        region=self.regions[0],
        resource_id="probe/partial",
        actual_value="probe row yielded before the failure",
    )
    raise RuntimeError("probe failure after the first yield")


def _setup_clients_ok(self: SecurityCheck) -> None:
    """Register no wrappers. Nothing here reaches ``ctx.get_client``."""
    self._clients.clear()


def _setup_clients_broken(self: SecurityCheck) -> None:
    """Raise out of ``initialize(ctx)``, after the context has been attached.

    The interesting half of this shape is that ``self._ctx`` is already set
    when the exception is raised, so the traceback carries a frame holding a
    check that holds the context.
    """
    raise RuntimeError("probe failure inside _setup_clients")


#: shape name -> (execute body, _setup_clients body, expected rows and status).
#: ``rows`` is ``"per_region"``, an integer, or ``"error"`` for the shapes that
#: contribute exactly one synthetic ERROR row.
_SHAPES: dict[str, tuple[Any, Any, str]] = {
    "generator": (_execute_generator, _setup_clients_ok, "per_region_pass"),
    "generator_empty": (_execute_generator_empty, _setup_clients_ok, "none"),
    "list": (_execute_list, _setup_clients_ok, "per_region_fail"),
    "raise_before_yield": (
        _execute_raise_before_yield, _setup_clients_ok, "one_error",
    ),
    "raise_after_yield": (
        _execute_raise_after_yield, _setup_clients_ok, "one_error",
    ),
    "broken_setup": (_execute_generator, _setup_clients_broken, "one_error"),
}

#: The shapes whose ``execute()`` is a generator, and which therefore exercise
#: the inner ``list()``. The drawn plan always contains at least one of these,
#: which is what keeps the property non-vacuous.
_GENERATOR_SHAPES = (
    "generator",
    "generator_empty",
    "raise_before_yield",
    "raise_after_yield",
    "broken_setup",
)


def _make_probe_check(
    shape: str, index: int, account_type: AccountType
) -> type[SecurityCheck]:
    """Build one throwaway registrable check class of the given shape.

    Declared through ``type()`` inside this module, whose file stem does not
    begin with ``sra_``, so ``__init_subclass__`` returns silently: no identity
    cross-check runs and the class does not self-register. Registration is done
    explicitly by ``_isolated_registry`` instead, which is what keeps the
    synthetic catalog scoped to one test.

    The ``meta`` is a real, fully validated ``CheckMeta`` -- ``_select`` reads
    ``meta.account_type`` and ``meta.service``, ``passed()`` and ``failed()``
    read six fields off it, and ``_synthetic_error`` reads eight -- so a
    stand-in object would only move the failure.

    Args:
        shape: A key of ``_SHAPES``.
        index: 1-based position in the plan, giving the check its ``NN``.
        account_type: The ``AccountType`` member for this check's metadata.

    Returns:
        A concrete ``SecurityCheck`` subclass, unregistered.
    """
    execute, setup_clients, _ = _SHAPES[shape]
    check_id = f"SRA-PROBE-{index:02d}"
    meta = CheckMeta(
        check_id=check_id,
        title=f"Probe control {index} is configured",
        description=(
            "Synthetic check used by the context-isolation property test. It "
            "reaches no AWS API and exists only to produce findings and to "
            "hold a reference to the per-scan context while it does so."
        ),
        check_logic=f"Probe shape {shape}; yields rows from a fixed region list",
        severity=Severity.MEDIUM,
        account_type=account_type,
        service="Probe",
        resource_type="AWS::Probe::Resource",
        remediation=Remediation(text="Nothing to remediate; this is a probe."),
    )
    return type(
        check_id.replace("-", "_"),
        (SecurityCheck,),
        {
            "__doc__": f"Throwaway {shape} probe check.",
            "__module__": __name__,
            "meta": meta,
            "execute": execute,
            "_setup_clients": setup_clients,
        },
    )


def _expected_rows(shape: str) -> int:
    """Rows a check of this shape contributes to one scan.

    Kept beside ``_SHAPES`` so the row-count assertion in the property cannot
    silently drift from the bodies above. ``raise_after_yield`` expects one row,
    not two: the row yielded before the failure goes with the discarded
    generator (10.8).
    """
    _, _, rows = _SHAPES[shape]
    if rows == "none":
        return 0
    if rows == "one_error":
        return 1
    return len(_PROBE_REGIONS)


def _expected_status(shape: str) -> Optional[Status]:
    """The single status every row of this shape carries, or ``None`` for no rows."""
    _, _, rows = _SHAPES[shape]
    return {
        "none": None,
        "one_error": Status.ERROR,
        "per_region_pass": Status.PASS,
        "per_region_fail": Status.FAIL,
    }[rows]


# ---------------------------------------------------------------------- #
# Isolation helpers.
#
# Written as context managers rather than pytest fixtures on purpose: a
# function-scoped fixture used with @given trips hypothesis's
# function_scoped_fixture health check, because the fixture is set up once
# while the test body runs many times. These enter and exit per example.
# ---------------------------------------------------------------------- #

@contextlib.contextmanager
def _isolated_registry(classes: Iterable[type[SecurityCheck]]) -> Iterator[None]:
    """Replace the catalog with *classes* for the duration of the block.

    Empties ``_REGISTRY`` first, which is load-bearing rather than tidy: with
    the real 158-check catalog present, ``account_type='all'`` would select all
    of it and the scan would go to AWS. Restoration mutates the original dict
    in place rather than rebinding the name, so a module holding a reference to
    it sees the restored contents.

    Args:
        classes: The synthetic check classes to register, each under its own
            ``meta.check_id``.
    """
    saved = dict(registry._REGISTRY)
    registry._REGISTRY.clear()
    try:
        for cls in classes:
            registry.register(cls.meta.check_id, cls)
        yield
    finally:
        registry._REGISTRY.clear()
        registry._REGISTRY.update(saved)


class _FormatAndDiscardHandler(logging.Handler):
    """Format each record and drop it, holding no reference afterwards.

    This is the shipped handler's memory behavior, reduced to the one property
    this module depends on. ``core/logging.py`` attaches a
    ``StreamHandler(sys.stderr)``, which formats the record and writes it; the
    record then goes out of scope. ``format()`` is called here rather than
    skipped so the same ``Formatter.formatException`` path runs -- that is where
    a handler *could* start retaining state -- while the rendered text is
    discarded instead of written, keeping the probe's deliberate tracebacks out
    of the test output.
    """

    def emit(self, record: logging.LogRecord) -> None:
        """Render *record* and discard it."""
        self.format(record)


@contextlib.contextmanager
def _production_log_handling() -> Iterator[None]:
    """Give the ``sraverify`` logger production's handler setup for the block.

    Why this exists, in full, because it looks like a test disabling the thing
    it is testing and it is the opposite.
    ----------------------------------------------------------------------

    ``run_checks``'s per-check guard logs with ``exc_info=True`` (10.2 requires
    the traceback). A ``LogRecord`` built that way holds ``record.exc_info``,
    whose third element is the traceback; the traceback holds every frame in
    it; and for the ``broken_setup`` shape one of those frames is
    ``SecurityCheck.initialize``, whose ``self`` is the check, whose ``_ctx``
    is the ``ScanContext``. **Any** handler that retains the record therefore
    keeps the context alive past ``finally: del ctx`` and past a forced
    ``gc.collect()``.

    In production nothing retains it: the stderr handler formats the record,
    writes it, and drops it. Requirement 10.11 holds in the shipped code path.

    Under pytest it is a different story. The logging plugin installs two
    ``LogCaptureHandler`` instances -- and installs them on the ``sraverify``
    logger directly, not only on the root logger, so ``propagate = False`` does
    not keep them out -- and each one appends every record to a ``records``
    list that outlives the test body. Without this context manager the property
    below measures *pytest's* retention rather than the orchestrator's
    lifetime, and fails for the counterexample
    ``[('generator', APPLICATION), ('broken_setup', APPLICATION)]`` while the
    production code is correct. Deleting ``.hypothesis/`` and re-running shows
    the same defect is latent from the workspace root too; the cache was
    steering generation away from it, not preventing it.

    So the fix belongs here, in the observer, and it is deliberately the
    narrowest honest one: for the duration of the scan the ``sraverify`` logger
    gets exactly what it has in production -- one handler that formats and
    drops, and ``propagate = False`` so the root logger's handlers (which
    pytest also populates) never see the record either. The previous handler
    list and propagate flag are restored on the way out, so ``caplog`` works
    normally everywhere else in the suite.

    The swap mutates ``logger.handlers`` in place rather than rebinding the
    name, for the same reason ``_isolated_registry`` does: pytest's
    ``catching_logs`` removes its handlers on the way out, and it must find the
    list it added them to.

    What this does **not** do, which is the point:

      * it does not touch ``main.run_checks``, which still logs with
        ``exc_info=True``;
      * it does not soften, skip, or xfail the assertion, and in particular it
        does not exclude the raising shapes from the drawn plan -- those are
        the shapes the property exists for;
      * it does not exempt any referrer from ``_referrer_summary``.

    A genuine production leak -- the orchestrator keeping ``ctx`` by any means
    other than a log record the harness chose to keep -- still fails the
    assertion, which is verified by mutating ``run_checks`` to leak on purpose.

    Two alternatives were rejected. Reaching into
    ``_pytest.logging.LogCaptureHandler.records`` to empty it before collecting
    would work today but pins the test to a pytest internal that is not part of
    its public API. Excluding the traceback-held frame from the referrer set
    would blind the assertion to the one referrer shape a real leak is most
    likely to take, since a real leak also shows up as a frame.
    """
    sraverify_logger = logging.getLogger("sraverify")
    saved_handlers = sraverify_logger.handlers[:]
    saved_propagate = sraverify_logger.propagate

    handler = _FormatAndDiscardHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    )
    sraverify_logger.handlers.clear()
    sraverify_logger.handlers.append(handler)
    sraverify_logger.propagate = False
    try:
        yield
    finally:
        sraverify_logger.handlers.clear()
        sraverify_logger.handlers.extend(saved_handlers)
        sraverify_logger.propagate = saved_propagate
        handler.close()


@contextlib.contextmanager
def _recording_scan_context() -> Iterator[list[weakref.ref]]:
    """Patch ``main.ScanContext`` with a factory that records a weak reference.

    A weak reference is the only handle the test keeps, which is the whole
    point: a strong one would keep the context alive and the property would
    pass unconditionally. The factory also pre-seeds ``_account_info`` so
    ``get_account_info()`` returns from its cache instead of reaching STS.

    Patching the name in ``main`` rather than subclassing ``ScanContext``
    leaves the object the orchestrator builds a genuine ``ScanContext``, so the
    ``isinstance`` walk in the property is testing the real class.

    Yields:
        The list the factory appends to, one ``weakref.ref`` per context
        constructed inside the block. Also asserts, by being a list, that
        exactly one context is built per ``run_checks`` call (10.9).
    """
    created: list[weakref.ref] = []
    original = main.ScanContext

    def factory(**kwargs: Any) -> ScanContext:
        ctx = original(**kwargs)
        # Short-circuit the STS + Account API lookup. get_account_info()
        # checks this field first, under the lock, and returns it on a hit.
        ctx._account_info = {
            "account_id": _PROBE_ACCOUNT_ID,
            "account_name": _PROBE_ACCOUNT_NAME,
        }
        created.append(weakref.ref(ctx))
        # ``ctx`` goes out of scope when this frame does, so the only handle
        # that outlives the call is the weak one.
        return ctx

    main.ScanContext = factory
    try:
        yield created
    finally:
        main.ScanContext = original


def _data_reachable(root: Any, limit: int = 100_000) -> dict[int, Any]:
    """Objects reachable from *root* through data references only.

    Complements the ``weakref`` assertion by answering the design's other
    formulation -- "no ``ScanContext`` is reachable from the returned findings"
    -- without depending on collection timing at all.

    Traversal stops at types, modules, and callables. That boundary is what
    makes the walk meaningful: a class reaches its ``__dict__``, whose methods
    reach ``__globals__``, from which essentially every object in the process
    is reachable, and the walk would report a "leak" for any module-level
    object anywhere. A ``Finding`` is a slotted frozen dataclass holding
    strings, enum members, and ``None``, so the honest walk over it is small.

    Args:
        root: Where to start, typically the list ``run_checks`` returned.
        limit: Safety cap on objects visited, so a pathological graph fails the
            assertion below rather than hanging the suite.

    Returns:
        Mapping of ``id()`` to object for everything visited, ``root``
        included.
    """
    seen: dict[int, Any] = {}
    stack: list[Any] = [root]
    while stack:
        obj = stack.pop()
        if id(obj) in seen:
            continue
        seen[id(obj)] = obj
        if len(seen) > limit:  # pragma: no cover - safety valve
            raise AssertionError(
                f"reachability walk exceeded {limit} objects; the traversal "
                f"boundary is wrong or a finding holds a container it should not"
            )
        if isinstance(obj, (type, types.ModuleType)) or callable(obj):
            continue
        stack.extend(gc.get_referents(obj))
    return seen


def _referrer_summary(obj: Any) -> str:
    """One line naming what still refers to *obj*, for a failure message.

    Only ever called on the failure path. A live context is the defect this
    property exists to catch, so the message has to say enough to start the
    diagnosis rather than merely reporting that a weak reference was not dead.
    """
    referrers = gc.get_referrers(obj)
    described = []
    for referrer in referrers:
        if isinstance(referrer, types.FrameType):
            described.append(
                f"frame {referrer.f_code.co_name} "
                f"({referrer.f_code.co_filename}:{referrer.f_lineno})"
            )
        else:
            described.append(type(referrer).__name__)
    return ", ".join(described) or "nothing (a reference cycle, then)"


# ---------------------------------------------------------------------- #
# Strategies.
# ---------------------------------------------------------------------- #

def plans() -> st.SearchStrategy[list[tuple[str, AccountType]]]:
    """Draw a scan plan: a list of (shape, account_type) pairs.

    At least one generator-bodied check is always present, inserted at a drawn
    position so it is exercised first, last, and in the middle across a run.
    Without that guarantee an example could consist solely of list-returning
    checks, and the property would hold for a reason that has nothing to do
    with the code it is testing.

    The plan is capped at six checks: ``CheckMeta`` allows ``NN`` up to 99, but
    the property is about lifetime rather than volume, and a long plan only
    slows the run.

    Returns:
        A strategy producing lists of one to six ``(shape, account_type)``
        pairs.
    """
    account_types = st.sampled_from(list(AccountType))
    any_shape = st.tuples(st.sampled_from(sorted(_SHAPES)), account_types)
    generator_shape = st.tuples(st.sampled_from(_GENERATOR_SHAPES), account_types)

    @st.composite
    def _plan(draw: st.DrawFn) -> list[tuple[str, AccountType]]:
        rest = draw(st.lists(any_shape, max_size=5))
        guaranteed = draw(generator_shape)
        position = draw(st.integers(min_value=0, max_value=len(rest)))
        return rest[:position] + [guaranteed] + rest[position:]

    return _plan()


# ---------------------------------------------------------------------- #
# The property.
# ---------------------------------------------------------------------- #

@given(
    plan=plans(),
    narrow_to_one=st.booleans(),
    show_progress=st.booleans(),
)
@example(
    # Pinned, not incidental. This is the exact input that exposed the
    # log-record retention described on ``_production_log_handling``: a healthy
    # generator followed by a check that raises out of ``initialize``, so the
    # traceback the guard logs carries a frame whose ``self._ctx`` is the
    # context. Hypothesis found it, and then a warm ``.hypothesis/`` cache hid
    # it again on the next invocation -- which is precisely why it is written
    # down here. An explicit example runs in the explicit phase on every
    # invocation, before generation, so no cache state can steer past it.
    #
    # ``narrow_to_one=False`` matters: narrowing selects a single
    # generator-bodied check and the raising one never runs.
    plan=[
        ("generator", AccountType.APPLICATION),
        ("broken_setup", AccountType.APPLICATION),
    ],
    narrow_to_one=False,
    show_progress=False,
)
@settings(
    deadline=None,
    # gc.collect() over a whole process is not fast and its cost varies with
    # whatever the rest of the suite has allocated, which is exactly the kind
    # of variance a per-example deadline mistakes for a defect.
    suppress_health_check=[HealthCheck.too_slow],
)
def test_returned_findings_hold_no_scan_context(
    plan: list[tuple[str, AccountType]],
    narrow_to_one: bool,
    show_progress: bool,
) -> None:
    """Property 18: after ``run_checks`` returns, the context is unreachable.

    Validates: Requirements 1.11, 10.7, 10.11
    """
    classes = [
        _make_probe_check(shape, index, account_type)
        for index, (shape, account_type) in enumerate(plan, start=1)
    ]
    shape_by_id = {
        cls.meta.check_id: shape for cls, (shape, _) in zip(classes, plan)
    }

    # Narrowing to a single check exercises the ``--check`` path, and the check
    # chosen is always a generator-bodied one so the single-check scan stays as
    # meaningful as the full one.
    if narrow_to_one:
        selected_ids = [
            cls.meta.check_id
            for cls in classes
            if shape_by_id[cls.meta.check_id] in _GENERATOR_SHAPES
        ][:1]
    else:
        selected_ids = [cls.meta.check_id for cls in classes]
    check_id = selected_ids[0] if narrow_to_one else None

    sra = main.SRAVerify(
        session=_RefusingSession(),
        regions=list(_PROBE_REGIONS),
    )

    with (
        _isolated_registry(classes),
        _production_log_handling(),
        _recording_scan_context() as created,
    ):
        findings = sra.run_checks(
            account_type="all",
            service=None,
            check_id=check_id,
            show_progress=show_progress,
        )

    # ---- Exactly one context, and the test holds only a weak handle --- #
    assert len(created) == 1, (
        f"expected one ScanContext per run_checks call, got {len(created)} "
        f"(Requirement 10.9)"
    )
    context_ref = created[0]

    # ---- Requirement 10.7: a concrete list, not a lazy object --------- #
    # ``type() is list`` rather than ``isinstance``: a lazy list *subclass*
    # would satisfy isinstance and could still defer work to the caller.
    assert type(findings) is list, (
        f"run_checks returned {type(findings).__name__}, not a list. A lazy "
        f"return value defers `finally: del ctx` until the caller consumes "
        f"the result, which moves the leak up one layer rather than removing "
        f"it (Requirement 10.7)"
    )
    # A list is not its own iterator; a generator, map, filter, or zip is.
    assert iter(findings) is not findings
    # Re-iterating yields the same rows, so nothing was consumed by reading it.
    assert list(findings) == findings
    assert all(isinstance(finding, Finding) for finding in findings), (
        "every element of the returned list must be a Finding"
    )

    # ---- The scan really ran, and produced the rows it should --------- #
    # Not decoration: if selection matched nothing, or every check silently
    # contributed no row, the reachability assertions below would hold
    # vacuously over an empty list.
    expected_total = sum(_expected_rows(shape_by_id[cid]) for cid in selected_ids)
    assert len(findings) == expected_total, (
        f"expected {expected_total} rows from {len(selected_ids)} checks, got "
        f"{len(findings)}: "
        f"{[(f.check_id, f.status.value) for f in findings]}"
    )
    for cid in selected_ids:
        shape = shape_by_id[cid]
        rows = [f for f in findings if f.check_id == cid]
        assert len(rows) == _expected_rows(shape)
        status = _expected_status(shape)
        if status is not None:
            assert all(f.status is status for f in rows), (
                f"{cid} ({shape}) produced "
                f"{sorted({f.status.value for f in rows})}, expected "
                f"{status.value}"
            )

    # ---- Identity travelled by value, not by reference ---------------- #
    # Requirement 1.11's purpose: this is *why* a finding can outlive the
    # context that produced it.
    for finding in findings:
        assert finding.account_id == _PROBE_ACCOUNT_ID
        assert finding.account_name == _PROBE_ACCOUNT_NAME

    # ---- Nothing reachable from the findings refers to the context ---- #
    reached = _data_reachable(findings)
    leaked = [
        obj for obj in reached.values()
        if isinstance(obj, (ScanContext, SecurityCheck))
    ]
    assert not leaked, (
        f"the returned findings reach {[type(o).__name__ for o in leaked]}; a "
        f"Finding must hold strings, enum members, and None only "
        f"(Requirement 1.11)"
    )

    # ---- Requirement 10.11: the weak reference is dead ---------------- #
    gc.collect()
    context = context_ref()
    if context is not None:
        summary = _referrer_summary(context)
        # Do not soften this. A context still alive here means a scan's worth
        # of boto3 clients survives every run_checks call, which in the
        # long-running MCP server is an unbounded leak.
        del context
        pytest.fail(
            f"the ScanContext survived run_checks and one forced collection; "
            f"still referred to by: {summary}. Requirement 10.11 requires the "
            f"weak reference to be dead, so neither the returned list nor "
            f"anything reachable from it keeps the context alive"
        )


# ---------------------------------------------------------------------- #
# Non-vacuity control, and the repeat-call case the MCP server hits.
# ---------------------------------------------------------------------- #

def test_a_live_generator_pins_the_context() -> None:
    """The leak, reproduced on purpose, so the property above has teeth.

    This is the defect ``findings = list(check.execute())`` exists to prevent:
    a started generator holds its frame, the frame holds ``self``, and ``self``
    holds ``self._ctx``. If this test ever stops holding -- if a started
    generator no longer pins the context -- then the property above is
    asserting nothing and the ``list()`` call in ``run_checks`` has become
    decorative.

    Validates: Requirements 1.11, 10.7, 10.11
    """
    cls = _make_probe_check("generator", 1, AccountType.APPLICATION)
    # The ``del generator; gc.collect(); assert context_ref() is None`` half
    # below is a weakref liveness assertion on the same object graph as the
    # property, so it carries the same exposure to a retained ``LogRecord``.
    # Nothing on this path logs with ``exc_info`` today, which is why the guard
    # is applied for symmetry rather than to fix a live failure.
    with _production_log_handling():
        ctx = ScanContext(session=_RefusingSession(), regions=list(_PROBE_REGIONS))
        ctx._account_info = {
            "account_id": _PROBE_ACCOUNT_ID,
            "account_name": _PROBE_ACCOUNT_NAME,
        }
        context_ref = weakref.ref(ctx)

        check = cls()
        check.initialize(ctx)
        generator = check.execute()
        first = next(generator)  # Start it, so the frame is live and suspended.
        assert isinstance(first, Finding)

        del ctx, check, first
        gc.collect()

        assert context_ref() is not None, (
            "a started generator no longer keeps its check -- and therefore "
            "the ScanContext -- alive. The inner list() in run_checks is then "
            "protecting against nothing, and Property 18 is vacuous"
        )

        # And the instrumentation itself is sound: once the generator goes, so
        # does the context. Without this half, the assertion above could be
        # passing because of some *other* strong reference this test holds.
        del generator
        gc.collect()
        assert context_ref() is None, (
            f"dropping the generator did not release the context; still "
            f"referred to by: {_referrer_summary(context_ref())}"
        )


def test_a_scan_with_no_findings_still_returns_a_list_and_leaks_nothing() -> None:
    """The zero-row scan, where an empty lazy object is easiest to hide.

    ``[]`` and an exhausted generator both read as "no findings" at every call
    site that only iterates the result, so this is the shape in which a lazy
    return value is least likely to be noticed.

    Validates: Requirements 10.7, 10.11
    """
    classes = [_make_probe_check("generator_empty", 1, AccountType.APPLICATION)]
    sra = main.SRAVerify(
        session=_RefusingSession(), regions=list(_PROBE_REGIONS)
    )

    # ``_production_log_handling`` for the same reason as the property above.
    # This shape raises nothing today, so no ``exc_info`` record is built and
    # the guard is currently a no-op here -- but the assertion below is the same
    # weakref liveness assertion, and it would break the same way the moment
    # anything on this path logged a traceback.
    with (
        _isolated_registry(classes),
        _production_log_handling(),
        _recording_scan_context() as created,
    ):
        findings = sra.run_checks(account_type="all")

    assert type(findings) is list
    assert findings == []

    gc.collect()
    context = created[0]()
    if context is not None:
        summary = _referrer_summary(context)
        del context
        pytest.fail(f"context survived a zero-finding scan; held by {summary}")


def test_successive_scans_release_each_context_before_the_next_returns() -> None:
    """The MCP server's actual shape: many scans in one long-lived process.

    Requirement 10.11 is stated per call, and one call in isolation cannot
    distinguish "released" from "released eventually". Running three scans and
    asserting every earlier context is dead is what makes the per-call
    guarantee add up to a bounded process: a leak of one context per call is
    invisible in a single-scan test and fatal in a server.

    Validates: Requirements 10.7, 10.11
    """
    sra = main.SRAVerify(
        session=_RefusingSession(), regions=list(_PROBE_REGIONS)
    )
    refs: list[weakref.ref] = []

    for _ in range(3):
        classes = [_make_probe_check("generator", 1, AccountType.APPLICATION)]
        with (
            _isolated_registry(classes),
            _production_log_handling(),
            _recording_scan_context() as created,
        ):
            findings = sra.run_checks(account_type="all")

        assert type(findings) is list
        assert len(findings) == len(_PROBE_REGIONS)
        refs.extend(created)

    gc.collect()
    alive = [index for index, ref in enumerate(refs) if ref() is not None]
    assert not alive, (
        f"{len(alive)} of {len(refs)} scan contexts survived (scans "
        f"{alive}); in the MCP server that is a scan's worth of boto3 clients "
        f"retained per call"
    )
