"""Property-based test for the removed accumulator trio (task 8.7).

This module implements **Property 12: yielded output is the only source of
findings**:

    ``execute()``'s yielded output is the only source of findings. No
    instance-level accumulator exists: ``hasattr(check, "findings")`` is
    ``False`` and ``SecurityCheck`` has no ``create_finding`` or
    ``get_findings`` attribute.

**Validates: Requirements 6.3, 6.11**

Why a property rather than three assertions
-------------------------------------------

The defect this closes is not hypothetical: ``self.findings = []`` followed by
``self.findings.append(...)`` left ``get_findings()`` returning ``[]`` for 79 of
158 checks, and the scan exited 0 while reporting nothing. Requirement 6.3
deletes the three names; requirement 6.11 is the stronger claim, that
*re-creating* any of them raises. Deletion alone would not have prevented the
defect from re-forming, because an author migrating a check by hand naturally
reaches for the accumulator idiom again, and an ordinary instance attribute
assignment would have accepted it silently.

So the interesting quantification is over the *assigned value*, not just the
name. ``findings = []`` is the historical idiom, but a re-creation could equally
be a list of real ``Finding`` objects, a dict, a bound helper function, or
``None``, and every one of those has to be refused. Both the name and the value
are drawn.

Both directions are asserted for each draw, because they are enforced by two
different mechanisms that the design deliberately kept separate:

  * assignment is blocked by the ``_REMOVED_ATTRS`` denylist in
    ``__setattr__``;
  * reading is blocked by ``__getattr__``, which only fires because normal
    lookup fails -- i.e. because the class genuinely does not carry the name.

A change that dropped either half would leave the other passing.

The over-broad guard this test also rules out
---------------------------------------------

Per the design, ``__slots__`` was **not** used. That was a decision, not an
oversight: service base classes assign ad-hoc attributes (``self._clients``,
``self._org_client``, and in ``securityincidentresponse/base.py`` others
besides), and ``__slots__`` would have broken all of them. A denylist that had
been widened -- to any name containing ``finding``, say, or to any name not
declared up front -- would satisfy the property above while breaking the
catalog. ``test_ordinary_attributes_remain_assignable`` is therefore not a
courtesy test; without it this module would pass on a guard that is wrong.
Its name strategy deliberately includes the near-misses ``_findings``,
``findings_list``, and ``get_findings_for_region``, which must all be assignable,
because the denylist is an exact-match membership test and nothing looser.

Throwaway subclasses
--------------------

The subclasses below are declared in this module, which is what task 8.2's
eligibility rule makes possible: ``__init_subclass__`` returns silently when the
defining module's file stem does not begin with ``sra_``. This file's stem is
``test_no_accumulator_property``, so none of these classes needs a ``meta``, and
none of them registers. ``test_in_memory_subclasses_do_not_register`` pins that,
since if it ever stopped holding, every property test that declares a subclass
would start polluting the catalog it shares a process with.
"""
from __future__ import annotations

import string
from typing import Any, Iterable, Iterator

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sraverify.core.check import _REMOVED_ATTRS, SecurityCheck
from sraverify.core.finding import Finding
from sraverify.core.registry import all_checks
from sraverify.tests.property.strategies import findings

# ---------------------------------------------------------------------- #
# Throwaway subclasses. None of these declares `meta`; none registers.
# ---------------------------------------------------------------------- #


class _DirectCheck(SecurityCheck):
    """A concrete check one level below the base, returning a list."""

    def execute(self) -> Iterable[Finding]:
        """Yield nothing, by returning an empty list."""
        return []


class _IntermediateCheck(SecurityCheck):
    """Stands in for a service base class: no `execute`, so still abstract."""

    NAMESPACE = "throwaway"

    def _setup_clients(self) -> None:
        """Register no wrappers."""
        self._clients.clear()


class _LeafCheck(_IntermediateCheck):
    """A concrete check two levels below the base, as real checks are."""

    def execute(self) -> Iterator[Finding]:
        """Yield nothing, as a generator."""
        yield from ()


class _CustomInitCheck(SecurityCheck):
    """A check whose constructor assigns an ad-hoc attribute of its own."""

    def __init__(self) -> None:
        """Set up scratch state the way a service base class would."""
        super().__init__()
        self._scratch: dict[str, Any] = {}

    def execute(self) -> Iterator[Finding]:
        """Yield nothing."""
        yield from ()


#: Created through ``type()`` rather than a class statement. Covered here
#: because it is the other shape a test or a REPL session produces, and it must
#: be as unregistered as the rest.
_DynamicCheck = type(
    "_DynamicCheck",
    (SecurityCheck,),
    {
        "__doc__": "A dynamically created throwaway check.",
        "execute": lambda self: iter(()),
    },
)

#: Every throwaway subclass declared above, abstract ones included.
_ALL_SUBCLASSES = (
    _DirectCheck,
    _IntermediateCheck,
    _LeafCheck,
    _CustomInitCheck,
    _DynamicCheck,
)

#: The subset that can be instantiated -- ``_IntermediateCheck`` leaves
#: ``execute`` abstract, so ``SecurityCheck`` being an ``ABC`` refuses it.
_CONCRETE_SUBCLASSES = tuple(
    cls for cls in _ALL_SUBCLASSES if cls is not _IntermediateCheck
)


# ---------------------------------------------------------------------- #
# Strategies.
# ---------------------------------------------------------------------- #

#: Names already carried by the base class -- properties, helpers, dunders.
#: Assigning over one of these is a separate concern (the metadata properties
#: are data descriptors with no setter and raise on their own account, which
#: requirement 6.7 covers), so they are excluded from the "ordinary attribute"
#: population rather than asserted about here.
_BASE_CLASS_NAMES = frozenset(dir(SecurityCheck))

#: Near-misses that the exact-match denylist must let through, alongside the
#: ad-hoc attribute names the real service base classes actually assign.
_ORDINARY_NAMES = (
    "_clients",
    "_ctx",
    "_org_client",
    "_scratch",
    "_detector_ids",
    "_findings",
    "findings_list",
    "all_findings",
    "create_finding_helper",
    "get_findings_for_region",
    "Findings",
    "FINDINGS",
)


def _sentinel_helper(*args: Any, **kwargs: Any) -> None:
    """Stand in for a re-created ``create_finding`` / ``get_findings`` method."""
    return None


def assigned_values() -> st.SearchStrategy[Any]:
    """Return a strategy for the value side of an attribute assignment.

    Spans what a re-created accumulator would plausibly be: the historical
    ``[]``, a list of real findings, a callable standing in for a re-created
    ``create_finding``, and a spread of ordinary scalars and containers so the
    refusal cannot depend on the value's type.

    Returns:
        A strategy producing arbitrary Python objects.
    """
    return st.one_of(
        # The exact idiom that produced the 79/158 defect.
        st.builds(list),
        st.lists(findings(), max_size=2),
        st.just(_sentinel_helper),
        st.none(),
        st.booleans(),
        st.integers(),
        st.text(max_size=20),
        st.lists(st.text(max_size=8), max_size=3),
        st.dictionaries(st.text(max_size=4), st.integers(), max_size=3),
        st.builds(object),
    )


def removed_names() -> st.SearchStrategy[str]:
    """Return a strategy over the three names this change removed.

    Drawn from ``_REMOVED_ATTRS`` itself rather than from a literal tuple, so a
    fourth name added to the denylist is quantified over without editing this
    strategy. ``test_removed_attrs_is_exactly_the_accumulator_trio`` pins which
    three those are today.

    Returns:
        A strategy producing ``"findings"``, ``"create_finding"``, or
        ``"get_findings"``.
    """
    return st.sampled_from(sorted(_REMOVED_ATTRS))


def ordinary_names() -> st.SearchStrategy[str]:
    """Return a strategy over attribute names that must remain assignable.

    Mixes the hand-picked near-misses and real-world names above with generated
    lower-case identifiers, filtered to exclude the denylist and anything the
    base class already carries.

    Returns:
        A strategy producing valid Python identifiers.
    """
    generated = st.builds(
        lambda underscore, first, rest: f"{underscore}{first}{rest}",
        st.sampled_from(["", "_"]),
        st.sampled_from(string.ascii_lowercase),
        st.text(alphabet=string.ascii_lowercase + string.digits + "_", max_size=12),
    )
    return st.one_of(st.sampled_from(_ORDINARY_NAMES), generated).filter(
        lambda name: name not in _REMOVED_ATTRS and name not in _BASE_CLASS_NAMES
    )


# ---------------------------------------------------------------------- #
# The property.
# ---------------------------------------------------------------------- #


@given(
    cls=st.sampled_from(_CONCRETE_SUBCLASSES),
    name=removed_names(),
    value=assigned_values(),
)
def test_removed_attributes_can_be_neither_read_nor_assigned(
    cls: type[SecurityCheck], name: str, value: Any
) -> None:
    """Property 12: the accumulator trio is unreachable and unrecreatable.

    Validates: Requirements 6.3, 6.11
    """
    check = cls()

    # ---- The name is absent, at every level of lookup ---------------- #
    assert not hasattr(check, name), (
        f"{cls.__name__} instance still exposes {name!r}; the accumulator "
        f"was supposed to be deleted outright"
    )
    assert not hasattr(cls, name), f"{cls.__name__} carries a class-level {name!r}"
    assert not hasattr(SecurityCheck, name), f"SecurityCheck carries {name!r}"
    assert name not in vars(check), f"{name!r} is in the instance dict"

    # ---- Reading raises, and says which name and which check --------- #
    with pytest.raises(AttributeError) as read_error:
        getattr(check, name)
    read_message = str(read_error.value)
    assert name in read_message, (
        f"the AttributeError from reading {name!r} does not name the "
        f"attribute: {read_message!r}"
    )
    assert cls.__name__ in read_message, (
        f"the AttributeError from reading {name!r} does not name the check "
        f"class: {read_message!r}"
    )

    # ---- Assigning raises too. This is the half that matters: with only
    # the read guard, `self.findings = []` would succeed and the defect
    # would be back, because after a successful assignment normal lookup
    # finds the attribute and __getattr__ never fires again.
    with pytest.raises(AttributeError) as write_error:
        setattr(check, name, value)
    write_message = str(write_error.value)
    assert name in write_message, (
        f"the AttributeError from assigning {name!r} does not name the "
        f"attribute: {write_message!r}"
    )
    assert cls.__name__ in write_message, (
        f"the AttributeError from assigning {name!r} does not name the check "
        f"class: {write_message!r}"
    )

    # ---- The refused assignment left nothing behind ------------------ #
    # A guard that raised *after* writing would be worse than none: the
    # attribute would exist, so the read guard would stop firing.
    assert name not in vars(check), (
        f"the refused assignment of {name!r} still landed in the instance "
        f"dict: {vars(check)[name]!r}"
    )
    assert not hasattr(check, name), (
        f"{name!r} became reachable after the assignment was refused"
    )
    with pytest.raises(AttributeError):
        getattr(check, name)

    # ---- And execute() is still the only source of findings ---------- #
    # Not a restatement: it pins that refusing the assignment did not damage
    # the instance, so the check remains usable and its yielded output is all
    # there is to collect.
    assert list(check.execute()) == []


@given(
    cls=st.sampled_from(_CONCRETE_SUBCLASSES),
    name=ordinary_names(),
    value=assigned_values(),
)
def test_ordinary_attributes_remain_assignable(
    cls: type[SecurityCheck], name: str, value: Any
) -> None:
    """The guard is an exact-match denylist, not a lockdown.

    ``__slots__`` was deliberately not used, so every ad-hoc attribute a
    service base class assigns must still work. Without this, Property 12
    would pass on an over-broad guard that breaks
    ``securityincidentresponse/base.py``.

    Validates: Requirements 6.3, 6.11
    """
    check = cls()

    setattr(check, name, value)

    assert getattr(check, name) is value, (
        f"{cls.__name__}.{name} did not round-trip: assigned {value!r}, "
        f"read back {getattr(check, name)!r}"
    )
    assert vars(check)[name] is value, (
        f"{cls.__name__}.{name} did not land in the instance dict"
    )

    # Reassignment works too, so nothing was frozen on first write.
    setattr(check, name, value)
    assert getattr(check, name) is value


def test_removed_attrs_is_exactly_the_accumulator_trio() -> None:
    """Pin the denylist's contents, since the property quantifies over it.

    ``removed_names()`` draws from ``_REMOVED_ATTRS``, so a name quietly
    dropped from that set would silently shrink the property's scope rather
    than fail it. This is the assertion that notices.

    Validates: Requirements 6.3, 6.11
    """
    assert _REMOVED_ATTRS == frozenset({"findings", "create_finding", "get_findings"})


def test_in_memory_subclasses_do_not_register() -> None:
    """Throwaway subclasses declared here stay out of the catalog.

    Task 8.2's eligibility rule: ``__init_subclass__`` returns silently when
    the defining module's file stem does not begin with ``sra_``. That is what
    lets this module declare five ``meta``-less subclasses without raising
    ``CheckIdentityError`` and without polluting the shared registry.

    Validates: Requirements 6.3, 6.11
    """
    catalog = all_checks()
    registered = set(catalog.values())

    for cls in _ALL_SUBCLASSES:
        assert cls not in registered, (
            f"{cls.__name__} was declared in a test module and still "
            f"registered in the check catalog"
        )
        assert cls.__name__ not in catalog, (
            f"{cls.__name__} appears as a check ID in the catalog"
        )
