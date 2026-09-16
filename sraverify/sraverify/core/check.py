"""
The check contract.

This module hosts ``SecurityCheck``, the abstract base every concrete service
check inherits from.

Identity and description are a validated frozen :class:`CheckMeta` declared in
the subclass's own class body and assigned to the ``meta`` class variable.
Nothing about a check's identity is imperative instance state any more, so
``check_id``, ``service``, ``severity``, and ``account_type`` are read-only
properties that delegate to ``meta``.

Per-scan state (the boto3 ``Session``, the region list, audit/log-archive
account lists, and account info) lives on a :class:`ScanContext` rather than on
the check instance. ``SecurityCheck`` exposes that state through read-only
properties that delegate to ``self._ctx``, each routed through
:meth:`SecurityCheck._require_ctx` so a read before ``initialize(ctx)`` names
the property and the check rather than surfacing an ``AttributeError`` on
``None``.

Registration is automatic. ``__init_subclass__`` fires for every subclass at
import time, cross-checks four independent expressions of the check's identity
-- the module file stem, the metadata ``check_id``, the class name, and the
containing service package -- and only then adds the class to the registry, so
a class whose file, name, and metadata disagree fails at import rather than
registering cleanly.

``initialize(ctx)`` is the single initialization path.

``execute()`` is the only abstract method and the only source of findings: it
yields :class:`Finding` objects. The former ``create_finding`` / ``findings`` /
``get_findings`` accumulator trio is gone, and re-creating any of those three
names on an instance raises rather than silently discarding rows.

Findings are built by three status-specific helpers -- ``passed()``,
``failed()``, and ``error()`` -- over one private ``_finding`` builder. Every
parameter of all three is keyword-only, which is what stops a positional swap
of ``actual_value`` and ``remediation`` across three near-identical signatures
from producing a well-formed row with the right values in the wrong columns.
Their signatures also encode the remediation rules: ``passed()`` has no
``remediation`` parameter at all, ``failed()`` falls back to the metadata
default, and ``error()`` demands one.
"""

from __future__ import annotations

import re
import sys
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, ClassVar, Final, Optional

import boto3

from sraverify.core.aws_errors import (
    NO_CLIENT_CODE,
    TRANSPORT_ERROR_CODES,
    NotConfiguredTable,
)
from sraverify.core.aws_errors import is_not_configured as _is_not_configured
from sraverify.core.enums import AccountType, Severity, Status
from sraverify.core.errors import CheckIdentityError
from sraverify.core.finding import Finding
from sraverify.core.logging import logger
from sraverify.core.metadata import CheckMeta
from sraverify.core.registry import all_checks, register
from sraverify.core.scan_context import ScanContext

#: The one legal shape of a check module's file stem: ``sra_<service>_<NN>``,
#: where the service segment begins with a lower-case ASCII letter and ``NN``
#: lies in ``01``-``99``. Deliberately tighter than the obvious
#: ``sra_([a-z0-9]+)_(\d{2})``, which would admit ``sra_12_01`` (a numeric
#: "service" in the catalog) and ``sra_guardduty_00`` (a check numbered zero),
#: both of which would register cleanly and look correct.
#:
#: ``re.ASCII`` so that a non-ASCII digit cannot satisfy the numeric segment,
#: and always applied with ``fullmatch`` so the whole stem must match.
#:
#: The ``01``-``99`` range caps one service at 99 checks. That ceiling is real
#: and named rather than discovered: the largest service today is GuardDuty at
#: 25, and approaching the limit would be a schema change to the ``CheckId``
#: column, not a regex tweak.
CHECK_MODULE_RE: Final = re.compile(r"sra_([a-z][a-z0-9]*)_(0[1-9]|[1-9][0-9])", re.ASCII)

#: Check-module file stems begin with this. The discriminator for registration
#: eligibility is the file name, never the presence of ``meta`` (4.12).
_CHECK_MODULE_PREFIX: Final = "sra_"

#: Metadata fields exposed as read-only properties on ``SecurityCheck``. A
#: class attribute of any of these names would shadow the property and silently
#: win, so identity and account type would no longer come only from ``meta``.
_SHADOWED_META_NAMES: Final = ("check_id", "service", "severity", "account_type")

#: Attribute names removed by this change. Re-creating any of them would
#: silently restore the accumulator defect: `self.findings = []` followed by
#: `self.findings.append(...)` discards every appended row, because nothing
#: reads that attribute any more.
_REMOVED_ATTRS: Final = frozenset({"findings", "create_finding", "get_findings"})

#: The public helper that produces each ``Status``, so that the ``RuntimeError``
#: from a pre-``initialize`` call names the method the author actually wrote.
#: Deriving the name from ``status.value.lower()`` would report ``pass()``,
#: which is not a method that exists -- ``pass`` is a reserved keyword, which is
#: exactly why the helper is spelled ``passed()``.
_HELPER_NAMES: Final = {
    Status.PASS: "passed",
    Status.FAIL: "failed",
    Status.ERROR: "error",
}

#: The error codes that mean "the caller is not permitted", across the services
#: this scanner consults. AWS spells the same condition four ways depending on
#: the service, so ``_remediation_for`` matches against the set rather than one
#: literal.
_ACCESS_DENIED_CODES: Final = frozenset(
    {
        "AccessDeniedException",
        "AccessDenied",
        "UnauthorizedOperation",
        "UnauthorizedException",
    }
)

#: The one class attribute a *service base* class may declare that a *check*
#: may not. The discriminator table belongs to the service, because its whole
#: purpose is that two checks reading the same error result from the same operation
#: cannot classify it differently; a check that declared its own would have
#: re-created exactly the per-check classification this contract removes.
_SERVICE_ONLY_NAMES: Final = ("NOT_CONFIGURED_ERRORS",)


class SecurityCheck(ABC):
    """Base class for all security checks.

    Metadata is a validated frozen ``CheckMeta`` declared in the subclass's
    own class body and assigned to ``meta``. Per-scan state is owned by an
    attached ``ScanContext`` and reached through read-only delegating
    properties.
    """

    meta: ClassVar[CheckMeta]

    #: Per-service declaration of which ``(operation, code)`` pairs mean "the
    #: control is not configured". Declared on the **service base class**, never
    #: on a check -- ``__init_subclass__`` enforces that. Read by
    #: :meth:`is_not_configured`.
    #:
    #: Empty here on purpose. A service with no declared semantics classifies
    #: every error as non-semantic, so every failure yields ERROR. That is the
    #: safe default: an unrecognized code produces an honest "could not
    #: determine" rather than a fabricated finding.
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {}

    def __init__(self) -> None:
        """Construct the check.

        Takes no argument beyond the instance and does no work beyond
        initializing two empty containers. Metadata is a ``ClassVar`` set at
        import, so there is nothing to assign here, and nothing on this path
        touches AWS: ``run_checks``, ``get_available_checks``, and every CLI
        filter read metadata off the class without constructing anything, but
        construction still has to stay cheap for the checks that are selected.

        Because this accepts nothing, a leftover
        ``super().__init__(account_type=...)`` in an unmigrated check raises
        ``TypeError`` naming the argument.
        """
        self._ctx: Optional[ScanContext] = None

        # Per-scan service-level client wrappers (e.g., ``GuardDutyClient``
        # instances keyed by region). Service base classes populate this in
        # their ``_setup_clients`` override; the underlying boto3 clients
        # are obtained from ``ctx.get_client(...)`` so they pick up the
        # bounded ``Client_Config``.
        self._clients: dict[str, Any] = {}

    # ------------------------------------------------------------------ #
    # Registration and identity enforcement.
    # ------------------------------------------------------------------ #

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Cross-check a new subclass's identity and register it.

        Fires once per subclass, at class-creation time, which is import time.
        There is no decorator to apply and no dictionary to maintain: a check
        module's presence on disk is the whole of its registration, so the
        failure mode where a check is written, looks correct, and silently
        never runs cannot occur.

        By the time this runs, ``cls.meta`` -- where one is declared -- is
        *already* a validated ``CheckMeta``: the class body finished evaluating
        before the class object existed, so ``CheckMeta.__post_init__`` has
        run. This hook therefore validates *identity* and never values, and a
        bad metadata value is always reported as a ``MetadataError`` rather
        than as an identity error, regardless of which would have been noticed
        first.

        Four independent expressions of a check's identity are cross-checked,
        in this order: the module file stem (the authority, from which the
        expected check ID is derived), the metadata ``check_id``, the class
        name, and the service package the module is filed under. Two shape
        rules follow: no check inherits another check, and no class attribute
        shadows a metadata property.

        Registration is the last step, so any failure above leaves the
        registry byte-identical to its prior state and a failed import
        contributes no partial catalog entry (4.15).

        Nothing on this path issues an AWS API call (4.10) and nothing reads a
        file: ``module.__file__`` is read as a string attribute, never opened
        or stat'ed. That is what makes ``--list-checks`` a credential-free,
        I/O-free catalog validation pass.

        Args:
            **kwargs: Class-creation keywords, forwarded to ``super()``.

        Raises:
            CheckIdentityError: The subclass was created from a module whose
                file stem begins with ``sra_`` and it breaks any identity or
                shape rule, including declaring no ``meta`` of its own.
            DuplicateCheckIdError: A different class already holds this
                check ID. Raised by :func:`register`.
        """
        super().__init_subclass__(**kwargs)

        # ---- Eligibility --------------------------------------------- #
        # A dynamically created class -- exec, type(), a REPL session, a
        # doctest -- has no module record or no __file__. It is not a check.
        # Returning silently rather than raising (4.13) is what keeps
        # SecurityCheck usable in a test that declares a throwaway subclass in
        # memory. These two are the *only* conditions that leave a subclass
        # unregistered without an error, other than the file-stem rule below.
        module = sys.modules.get(cls.__module__)
        if module is None or getattr(module, "__file__", None) is None:
            return

        module_file = Path(module.__file__)
        stem = module_file.stem  # e.g. "sra_guardduty_01"

        # Service base classes (GuardDutyCheck, ShieldCheck, ...) live in
        # base.py, declare no metadata of their own, and must stay out of the
        # catalog; so must any intermediate subclass declared outside a
        # sra_* module. The discriminator is the file name and never the
        # presence of `meta` (4.12): keying eligibility on `meta` would
        # conflate "this class is not a check" with "this check's author
        # forgot the metadata", and those two must not share a code path.
        if not stem.startswith(_CHECK_MODULE_PREFIX):
            return

        # Past this point the class is a check, so every remaining rule
        # raises. "Ineligible" and "invalid" are different facts.

        # ---- Identity 1: the file stem is the authority (4.3, 4.4) ---- #
        match = CHECK_MODULE_RE.fullmatch(stem)
        if match is None:
            raise CheckIdentityError(
                f"check module name is malformed: {stem!r} does not match "
                f"sra_<service>_<NN> with a service segment starting with a "
                f"lower-case letter and NN in 01-99 ({module_file})"
            )
        service_segment = match.group(1)  # "guardduty"
        expected_id = f"SRA-{service_segment.upper()}-{match.group(2)}"

        # Reversibility (4.3): asserted, not assumed. The file-to-registry
        # bijection depends on this derivation being invertible, and an
        # invariant that a downstream property test relies on should fail
        # here, where it is established, rather than there.
        assert expected_id.lower().replace("-", "_") == stem, (
            f"check ID derivation is not reversible: {expected_id!r} "
            f"derived from {stem!r} ({module_file})"
        )

        # ---- Metadata: read from the class body, never inherited (4.16)  #
        # vars(cls), NOT getattr(cls, "meta"): getattr would find an inherited
        # meta on a service base class or on another check and let this class
        # register under an ID it does not own. A check that forgot to declare
        # meta must raise, not silently inherit one.
        if "meta" not in vars(cls):
            raise CheckIdentityError(
                f"check declares no meta of its own: {cls.__name__} must "
                f"assign a CheckMeta to `meta` in its own class body "
                f"({module_file})"
            )
        meta = vars(cls)["meta"]

        # ---- Identity 2: the metadata check_id (4.5) ------------------ #
        # Still load-bearing with metadata declared inline: an author can
        # perfectly well write check_id="SRA-GUARDDUTY-02" inside
        # sra_guardduty_01.py, and nothing but this comparison catches it.
        if meta.check_id != expected_id:
            raise CheckIdentityError(
                f"metadata check_id {meta.check_id!r} disagrees with "
                f"{expected_id!r} derived from the module file name "
                f"({module_file})"
            )

        # ---- Identity 3: the class name (4.6) ------------------------- #
        # Applies to EVERY SecurityCheck subclass created inside a sra_*
        # module, so a second or intermediate subclass declared there fails
        # rather than registering under an ID it does not own.
        expected_class_name = expected_id.replace("-", "_")
        if cls.__name__ != expected_class_name:
            raise CheckIdentityError(
                f"check class name {cls.__name__!r} disagrees with "
                f"{expected_class_name!r} derived from the module file name "
                f"({module_file})"
            )

        # ---- Identity 4: the containing service package (4.14) -------- #
        # cls.__module__ is "sraverify.services.<svc>.checks.sra_<svc>_NN", so
        # the service package is the third component from the end. This is the
        # one rule that catches a *filing* mistake rather than a *naming* one:
        # services/guardduty/checks/sra_shield_01.py is fully self-consistent
        # under the three rules above, yet inherits GuardDutyCheck and would
        # run against GuardDuty's namespace, accessors, and client while
        # reporting Service=Shield on every row it emits.
        parts = cls.__module__.split(".")
        if len(parts) < 3 or parts[-2] != "checks":
            raise CheckIdentityError(
                f"check module is not in a service checks package: "
                f"{cls.__module__!r} ({module_file})"
            )
        containing_service = parts[-3]  # "guardduty"
        if containing_service != service_segment:
            raise CheckIdentityError(
                f"check module is filed under the wrong service: the file "
                f"name says {service_segment!r} but the module sits in the "
                f"{containing_service!r} service package ({module_file})"
            )

        # ---- Shape rule: no check inherits another check (6.12) ------- #
        # Two classes would then answer to one metadata lineage, and a Finding
        # would no longer be attributable to exactly one check ID.
        registered = set(all_checks().values())
        for base in cls.__mro__[1:]:
            if base in registered:
                raise CheckIdentityError(
                    f"check inherits from another check: {cls.__name__} has "
                    f"the registered check {base.__name__} among its bases "
                    f"({module_file})"
                )

        # ---- Shape rule: no shadowed metadata property (6.12) --------- #
        # Identity and account type come only from `meta`. A class attribute
        # of one of these names shadows the read-only property and silently
        # wins. Walk cls and every intermediate base below SecurityCheck, so a
        # service base class cannot smuggle one in either; SecurityCheck
        # itself is excluded because it is where the properties are declared.
        for klass in cls.__mro__:
            if klass is SecurityCheck:
                break
            klass_vars = vars(klass)
            for name in _SHADOWED_META_NAMES:
                if name in klass_vars:
                    raise CheckIdentityError(
                        f"metadata field shadowed by a class attribute: "
                        f"{klass.__name__}.{name} shadows the read-only "
                        f"property that delegates to meta ({module_file})"
                    )

        # ---- Shape rule: the discriminator table belongs to the service - #
        # A check may not declare NOT_CONFIGURED_ERRORS. The table's entire
        # purpose is that two checks reading the same error result from the same
        # operation cannot classify it differently; a check that declared its
        # own would have re-created the per-check classification this contract
        # removes, and it would do so invisibly, because the shadowing would be
        # legal Python and the check would keep working.
        #
        # Read via vars(cls) rather than getattr, exactly as the `meta` rule
        # does: every check *inherits* a table from its service base, and
        # getattr cannot tell an inherited one from a declared one.
        for name in _SERVICE_ONLY_NAMES:
            if name in vars(cls):
                raise CheckIdentityError(
                    f"discriminator table declared on a check: {cls.__name__}."
                    f"{name} must be declared on the service base class, not on "
                    f"an individual check, so that every check of the service "
                    f"classifies a given (operation, code) pair identically "
                    f"({module_file})"
                )

        # ---- Commit --------------------------------------------------- #
        # Register LAST. Every rule above raises before the registry is
        # touched, which is what gives 4.15 its "no partial entry" guarantee
        # for free. Nothing is assigned to cls: the class body already bound
        # cls.meta.
        register(meta.check_id, cls)

    def __setattr__(self, name: str, value: Any) -> None:
        """Reject the three attributes this change removed.

        Assignment, not just reading, has to fail. A migrated check that
        re-creates ``self.findings`` would append rows to a list nobody
        reads and report zero findings while exiting 0 -- the exact defect
        that made ``get_findings()`` return [] for 79 of 158 checks.

        The denylist deliberately excludes ``check_id``, ``service``,
        ``severity``, and ``account_type``: those are data descriptors with no
        setter, so delegating to ``super().__setattr__`` raises for them
        already. The two mechanisms compose without either knowing about the
        other.
        """
        if name in _REMOVED_ATTRS:
            raise AttributeError(
                f"{type(self).__name__}.{name} was removed. "
                f"execute() must yield Finding objects; see core/finding.py"
            )
        super().__setattr__(name, value)

    def __getattr__(self, name: str) -> Any:
        """Reject reads of the three removed attributes with a real message.

        Only called when normal lookup fails, so this costs nothing on the
        hot path and cannot shadow a real attribute.
        """
        if name in _REMOVED_ATTRS:
            raise AttributeError(
                f"{type(self).__name__}.{name} was removed. "
                f"Use passed() / failed() / error() and yield the result"
            )
        raise AttributeError(name)

    # ------------------------------------------------------------------ #
    # The abstract method.
    # ------------------------------------------------------------------ #

    @abstractmethod
    def execute(self) -> Iterable[Finding]:
        """Evaluate the control and yield one Finding per row of output.

        ``SecurityCheck`` is an ``ABC`` and this is an ``abstractmethod``, so a
        missing or misspelled ``execute`` fails at *instantiation* rather than
        only when that particular check happens to run.

        The return type is ``Iterable[Finding]``, so both a generator and a
        plain ``return [...]`` satisfy it; generators are the convention,
        because then no accumulator variable exists in the check body at all.
        A bare ``return`` is the early-exit idiom for a guard clause, and a
        check that yields nothing is legal and produces zero rows.
        """

    # ------------------------------------------------------------------ #
    # Finding construction helpers.
    #
    # Three status-specific public helpers over one private builder. Every
    # parameter of all three is keyword-only, enforced by the leading bare
    # ``*``, and that is the point rather than a stylistic preference.
    #
    # These are three near-identical signatures called from 158 migrated
    # check bodies. Were positional arguments allowed,
    #
    #     yield self.failed(region, "No detector in this Region",
    #                       "Enable GuardDuty")
    #
    # would be well-formed: the sentence lands in ``resource_id``, the advice
    # lands in ``actual_value``, and ``Remediation`` silently takes the
    # metadata default. Every value is a legal non-empty string in a legal
    # field, so ``Finding.__post_init__`` cannot catch it and no downstream
    # layer can either -- the row is plausible enough to survive review and to
    # render in a dashboard. Keyword-only turns that whole class of
    # wrong-cell defect into a ``TypeError`` at the call site (7.11).
    #
    # A second consequence: the parameter order below is not a contract, so
    # it can be reordered later without breaking a single caller.
    #
    # ``resource_id`` is required in all three (7.3) even though it accepts
    # ``None``. Optional-with-a-default would let it be forgotten; required-
    # but-nullable forces the author to decide whether this row identifies a
    # resource and to say so.
    # ------------------------------------------------------------------ #

    def _finding(
        self,
        status: Status,
        *,
        region: str,
        resource_id: Optional[str],
        actual_value: str,
        remediation: str,
        checked_value: Optional[str],
    ) -> Finding:
        """Build one ``Finding`` for the given status. Shared by all three helpers.

        Everything about the check's identity and description comes from
        ``meta`` (7.8), and ``account_id`` / ``account_name`` are copied **by
        value** out of the context's account-info dict. The returned
        ``Finding`` therefore holds no reference to this check and none to the
        ``ScanContext``, which is what lets the orchestrator ``del ctx`` while
        the findings it produced outlive the scan.

        ``title`` is composed here as ``f"{check_id} {title}"`` -- in exactly
        one place, which is what makes ``Finding``'s prefix rule enforceable at
        all. Any other path that assembles a ``Finding`` by hand is caught.

        Args:
            status: The ``Status`` member for the row. Positional, because
                this is private and never called from a check body.
            region: AWS region name, or ``GLOBAL_REGION`` for a non-regional
                check.
            resource_id: The resource this row is about, or ``None`` when the
                row identifies no single resource.
            actual_value: What was observed.
            remediation: Already resolved by the calling public helper.
            checked_value: What was examined; ``None`` selects the default.

        Returns:
            Exactly one ``Finding``. This check instance is left unmodified
            (7.9).

        Raises:
            RuntimeError: ``initialize(ctx)`` has not run (7.12). Raised by
                ``_require_ctx`` before any ``Finding`` is built, so no
                partial row escapes.
        """
        m = self.meta
        ctx = self._require_ctx(f"{_HELPER_NAMES[status]}()")
        info = ctx.get_account_info()
        return Finding(
            check_id=m.check_id,
            status=status,
            region=region,
            severity=m.severity,
            title=f"{m.check_id} {m.title}",
            description=m.description,
            resource_id=resource_id,
            resource_type=m.resource_type,
            account_id=info["account_id"],
            account_name=info["account_name"],
            checked_value=(
                checked_value
                if checked_value is not None
                else f"{m.service} Configuration"
            ),
            actual_value=actual_value,
            remediation=remediation,
            service=m.service,
            check_logic=m.check_logic,
            account_type=m.account_type,
        )

    def passed(
        self,
        *,
        region: str,
        resource_id: Optional[str],
        actual_value: str,
        checked_value: Optional[str] = None,
    ) -> Finding:
        """Build a PASS ``Finding``.

        There is deliberately **no** ``remediation`` parameter (7.2), not even
        one defaulting to ``""``. A PASS has nothing to remediate, so the empty
        cell is structural rather than conventional, and the several spellings of
        "nothing to do" that a free-text field invites are unrepresentable.
        Passing ``remediation=`` here is a ``TypeError`` (7.11).

        Args:
            region: AWS region name, or ``GLOBAL_REGION``.
            resource_id: The passing resource. Required, may be ``None``,
                though in practice a PASS has one -- something passed.
            actual_value: What was observed.
            checked_value: Defaults to ``f"{service} Configuration"`` (7.7).

        Returns:
            One ``Finding`` with ``status is Status.PASS`` and
            ``remediation == ""``.

        Raises:
            RuntimeError: ``initialize(ctx)`` has not run (7.12).
        """
        return self._finding(
            Status.PASS,
            region=region,
            resource_id=resource_id,
            actual_value=actual_value,
            remediation="",
            checked_value=checked_value,
        )

    def failed(
        self,
        *,
        region: str,
        resource_id: Optional[str],
        actual_value: str,
        remediation: Optional[str] = None,
        checked_value: Optional[str] = None,
    ) -> Finding:
        """Build a FAIL ``Finding``.

        ``remediation`` falls back to ``meta.remediation.text`` when omitted
        (7.4) and equally when supplied blank (7.5), so no FAIL row can carry
        an empty ``Remediation`` cell. The metadata default covers the common
        case and is what removes 468 literal ``remediation=`` arguments from
        the check bodies; the override exists for genuinely dynamic text, such
        as ``f"Enable GuardDuty in {region}"``. The blank-value fallback means
        a migrated check that still passes ``remediation=""`` emits usable
        advice rather than a hole.

        Args:
            region: AWS region name, or ``GLOBAL_REGION``.
            resource_id: The failing resource, or ``None``.
            actual_value: What was observed.
            remediation: Dynamic override. Omitted or blank uses
                ``meta.remediation.text``.
            checked_value: Defaults to ``f"{service} Configuration"`` (7.7).

        Returns:
            One ``Finding`` with ``status is Status.FAIL`` and a
            ``remediation`` that is non-empty after stripping.

        Raises:
            RuntimeError: ``initialize(ctx)`` has not run (7.12).
        """
        text = remediation if remediation and remediation.strip() else None
        return self._finding(
            Status.FAIL,
            region=region,
            resource_id=resource_id,
            actual_value=actual_value,
            remediation=text or self.meta.remediation.text,
            checked_value=checked_value,
        )

    def error(
        self,
        *,
        region: str,
        resource_id: Optional[str],
        actual_value: str,
        remediation: str,
        checked_value: Optional[str] = None,
    ) -> Finding:
        """Build an ERROR ``Finding``.

        ``remediation`` is **required** (7.6) and a blank value is refused
        outright. This is the one place the three helpers diverge on principle
        rather than convenience: for a FAIL, ``meta.remediation.text`` is by
        construction the right advice, because it is the remediation for this
        control. For an ERROR there is no such default -- the row reports that
        the control could not be evaluated, so an ERROR's remediation concerns
        fixing the *scan environment* (grant a permission, pass
        ``--audit-account``) and not fixing the control. Emitting "Enable
        GuardDuty in every enabled Region" against an ``AccessDeniedException``
        would be confidently wrong, which is worse than raising.

        The emptiness test is the whole of the validation applied here (7.6):
        any value that is non-empty after stripping is accepted, and no
        wording is judged.

        This stays a public method (7.10) because checks author their own ERROR
        findings -- 24 of the 25 GuardDuty checks do.

        Args:
            region: AWS region name, or ``GLOBAL_REGION``.
            resource_id: The resource the scan failed on, or ``None``.
            actual_value: What went wrong, including the AWS error message.
            remediation: How to fix the scan environment. Required, non-blank.
            checked_value: Defaults to ``f"{service} Configuration"`` (7.7).

        Returns:
            One ``Finding`` with ``status is Status.ERROR``.

        Raises:
            ValueError: ``remediation`` is empty after stripping. The message
                names the check ID. No ``Finding`` is returned.
            RuntimeError: ``initialize(ctx)`` has not run (7.12).
        """
        if not remediation.strip():
            raise ValueError(
                f"{self.meta.check_id}: error() requires a non-empty "
                f"remediation describing how to fix the scan environment"
            )
        return self._finding(
            Status.ERROR,
            region=region,
            resource_id=resource_id,
            actual_value=actual_value,
            remediation=remediation,
            checked_value=checked_value,
        )

    # ------------------------------------------------------------------ #
    # Initialization and client access.
    # ------------------------------------------------------------------ #

    def initialize(self, ctx: ScanContext) -> None:
        """
        Attach per-scan state to this check and set up service clients.

        This is the single initialization path.

        Args:
            ctx: The :class:`ScanContext` owning the boto3 session, region
                list, account-ID lists, bounded ``Client_Config``, and the
                per-scan client + response caches.
        """
        logger.debug(f"Initializing {self.__class__.__name__} check")

        self._ctx = ctx

        # Defer to subclass for per-region client wrapper construction.
        # Service base classes obtain their underlying boto3 clients from
        # ``self._ctx.get_client(...)`` so the bounded ``Client_Config``
        # is applied.
        self._setup_clients()

    def _setup_clients(self) -> None:
        """
        Set up service-level client wrappers for each region.

        Service base classes override this to populate ``self._clients``
        with their per-region wrapper objects, e.g.,
        ``self._clients[region] = GuardDutyClient(region, ctx=self._ctx)``.
        """
        raise NotImplementedError("Subclasses must implement _setup_clients method")

    def get_client(self, region: str) -> Optional[Any]:
        """
        Get the service-level client wrapper for a specific region.

        Args:
            region: AWS region name.

        Returns:
            The service-level wrapper for the region, or ``None`` if the
            subclass registered no wrapper for that region. That absence is
            the only condition under which this returns ``None``.
        """
        return self._clients.get(region)

    # ------------------------------------------------------------------ #
    # Error classification.
    #
    # A base accessor hands a check a dict. The check tests ``"Error" in
    # result`` before reading any success-path key, and if it is there, asks
    # these two methods what the error means and what to say about it.
    # ------------------------------------------------------------------ #

    def is_not_configured(self, error: Mapping[str, str]) -> bool:
        """
        Classify an error result's ``Error`` sub-dict against this service's table.

        ``True`` means AWS answered and the answer is that the control is
        absent, so the check should yield ``failed()``. ``False`` means the
        control could not be evaluated, so the check should yield ``error()``.

        Reads ``type(self).NOT_CONFIGURED_ERRORS`` rather than
        ``self.NOT_CONFIGURED_ERRORS`` for the same reason ``__init_subclass__``
        reads ``vars(cls)`` for ``meta``: the table is a class-level
        declaration, and going through the type makes it impossible for an
        instance attribute to shadow it.

        The error result carries ``Operation``, which is why this takes one
        argument. Threading the operation name separately would mean every
        accessor had to know which operation its client called and pass it
        upward, and every one of the 100-odd call sites would be a
        two-argument call.

        Args:
            error: An error result's ``Error`` sub-dict.

        Returns:
            ``True`` if the pair is declared semantic for this service.
        """
        return _is_not_configured(type(self).NOT_CONFIGURED_ERRORS, error)

    def _remediation_for(self, error: Mapping[str, str]) -> str:
        """
        Return scan-environment remediation wording for a non-semantic error.

        An ERROR row reports that the control could **not be evaluated**, so its
        remediation concerns fixing the *scan*, not fixing the control. That is
        why ``error()`` has no metadata fallback and why this helper exists:
        ``meta.remediation.text`` is the right advice for a FAIL by
        construction, and emitting "Enable GuardDuty in every enabled Region"
        against an ``AccessDeniedException`` would be confidently wrong.

        Wording is chosen by ``Code`` class, in four buckets: transport,
        ``NoClient``, access-denied, and everything else. The first two name the
        **service**; the last two name the **operation**. That split is not
        cosmetic -- it follows from which errors carry an operation at all. A
        transport failure and a missing client both mean nothing was sent, so
        ``AWSClient.aws_error`` records :data:`UNKNOWN_OPERATION` and there is no
        operation to name; interpolating the placeholder produced "so a client
        exists for Request", which reads as though ``Request`` were an API. An
        access-denied or otherwise-unclassified code came from AWS answering, so
        botocore attached the real operation and naming it is the most actionable
        thing available.

        This deliberately does **not** compose an IAM action string. Requirement
        4.8 forbids it, because ``meta.service`` is a display name and not an IAM
        prefix -- ``IAM Access Analyzer`` is ``access-analyzer``,
        ``FirewallManager`` is ``fms``, ``Security Lake`` is ``securitylake`` --
        so an interpolated ``f"{service}:{Operation}"`` would be wrong for
        several services, and a fabricated action is worse than a vague one. A
        check that wants to name the exact action passes its own
        ``remediation=``; ``error()`` still rejects a blank one.

        Args:
            error: An error result's ``Error`` sub-dict.

        Returns:
            A non-blank remediation string naming the service or the operation.
        """
        code = error.get("Code", "")
        operation = error.get("Operation", "") or "the AWS call"

        if code in TRANSPORT_ERROR_CODES:
            return (
                f"Confirm the {self.service} endpoint for this Region is "
                f"reachable from the scanner's network, then re-run the scan"
            )
        if code == NO_CLIENT_CODE:
            return (
                f"Confirm the Region is enabled for this account and was "
                f"supplied to --regions, so a {self.service} client exists for it"
            )
        if code in _ACCESS_DENIED_CODES:
            return (
                f"Grant the member role permission to call {operation} for this "
                f"service (see the SRAVerifyCheckPermissions policy in "
                f"1-sraverify-member-roles.yaml), then re-run the scan"
            )
        return (
            f"Investigate {code} from {operation} in the scan log "
            f"(the aws_call_failed record names the Region), then re-run the scan"
        )

    # ------------------------------------------------------------------ #
    # Read-only properties that delegate to the class's own metadata.
    #
    # None of these has a setter, so an assignment such as
    # ``self.account_type = "audit"`` after ``super().__init__()`` raises
    # ``AttributeError`` naming the property at the point of assignment
    # rather than quietly shadowing metadata.
    # ------------------------------------------------------------------ #

    @property
    def check_id(self) -> str:
        """The check's ID, from ``meta``."""
        return self.meta.check_id

    @property
    def service(self) -> str:
        """The AWS service display name, from ``meta``."""
        return self.meta.service

    @property
    def severity(self) -> Severity:
        """The check's severity, from ``meta``."""
        return self.meta.severity

    @property
    def account_type(self) -> AccountType:
        """The account type this check applies to, from ``meta``."""
        return self.meta.account_type

    # ------------------------------------------------------------------ #
    # Read-only properties that delegate to the attached ScanContext.
    #
    # All of these have no setter, so direct assignment (e.g.
    # ``check.audit_accounts = [...]``) raises ``AttributeError``: the
    # orchestrator MUST NOT mutate per-scan state on the check instance,
    # and account lists flow exclusively through the ``ScanContext``.
    #
    # Every one routes through ``_require_ctx``, so a read before
    # ``initialize(ctx)`` names the property and the check ID instead of
    # surfacing ``AttributeError: 'NoneType' object has no attribute ...``,
    # which named neither and sent readers into ``ScanContext`` looking for
    # a bug that was not there.
    # ------------------------------------------------------------------ #

    def _require_ctx(self, accessor: str) -> ScanContext:
        """Return the attached context, or explain precisely what is missing.

        Args:
            accessor: Name of the property or helper doing the read, quoted
                back in the error message.

        Returns:
            The attached :class:`ScanContext`.

        Raises:
            RuntimeError: No context is attached, i.e. ``initialize(ctx)``
                has not run. The check ID is always available because ``meta``
                is a ``ClassVar`` set at import and does not depend on
                initialization, so the message is always attributable.
        """
        if self._ctx is None:
            raise RuntimeError(
                f"{self.meta.check_id}.{accessor} was read before "
                f"initialize(ctx); a check must be initialized with a "
                f"ScanContext before it can be executed"
            )
        return self._ctx

    @property
    def session(self) -> boto3.Session:
        """The boto3 ``Session`` for the current scan, from the context."""
        return self._require_ctx("session").session

    @property
    def regions(self) -> list[str]:
        """The region list for the current scan.

        When the ``ScanContext`` was constructed with an explicit non-empty
        region list, that list is returned. Otherwise enabled regions are
        lazily resolved via ``ctx.get_enabled_regions()`` (one EC2
        ``DescribeRegions`` call per scan, cached for the rest of the scan).
        """
        ctx = self._require_ctx("regions")
        ctx_regions = ctx.regions
        if ctx_regions:
            return ctx_regions
        return ctx.get_enabled_regions()

    @property
    def account_info(self) -> dict[str, str]:
        """The ``{"account_id", "account_name"}`` dict for the current scan."""
        return self._require_ctx("account_info").get_account_info()

    @property
    def account_id(self) -> str:
        """The current AWS account ID, sourced from the ``ScanContext``."""
        return self._require_ctx("account_id").get_account_info()["account_id"]

    @property
    def account_name(self) -> str:
        """The current AWS account name, sourced from the ``ScanContext``."""
        return self._require_ctx("account_name").get_account_info()["account_name"]

    @property
    def audit_accounts(self) -> list[str]:
        """Audit account IDs for the current scan; ``[]`` when none supplied."""
        return self._require_ctx("audit_accounts").audit_accounts

    @property
    def log_archive_accounts(self) -> list[str]:
        """Log-archive account IDs for the current scan; ``[]`` when none supplied."""
        return self._require_ctx("log_archive_accounts").log_archive_accounts

    def get_management_accountId(self, session: Optional[boto3.Session] = None) -> str:
        """
        Get the AWS Organizations management account ID for the current scan.

        Delegates to ``self._ctx.get_management_account_id()``, which issues
        ``organizations:DescribeOrganization`` once per scan and caches the
        result. The ``session`` parameter is preserved for backward
        compatibility with the pre-refactor signature but is ignored; the
        attached ``ScanContext`` owns the session.

        Args:
            session: Ignored. Kept for backward compatibility.

        Returns:
            AWS account ID of the organization's management account.
        """
        if session is not None:
            logger.debug(
                "SecurityCheck.get_management_accountId received an explicit "
                "session argument; this is ignored now that the ScanContext "
                "owns the session."
            )
        return self._require_ctx("get_management_accountId").get_management_account_id()
