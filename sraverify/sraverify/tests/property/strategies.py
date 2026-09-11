"""Shared ``hypothesis`` strategies for the finding-model property tests.

`findings()` is the reusable generator of arbitrary **valid** ``Finding``
instances. It is shared rather than duplicated because Properties 6 through 9
all quantify over the same population -- "every Finding that can legally
exist" -- and each one asserts a different invariant over it:

  * Property 6 -- ``to_row()`` yields exactly ``FIELDS`` in order.
  * Property 7 -- every row value is a ``str`` and none is ``None``.
  * Property 8 -- no ``Finding`` carries an out-of-enum status or severity.
  * Property 9 -- findings are immutable.

Keeping one generator means a field added to ``Finding``, or a validation rule
added to ``__post_init__``, is reflected in every property at once. A per-module
copy would let three of the four drift silently.

The interesting design choice is `cell_text()`. Field values are drawn from a
strategy that deliberately includes the characters a CSV layer can mishandle --
commas, double quotes, already-doubled double quotes, ``\\r``, ``\\n``,
``\\r\\n``, tabs, leading and trailing spaces, and non-ASCII text. For
Property 6 that is a strengthening move rather than a decorative one: the key
set and key order of ``to_row()`` must not depend on the *values* of the cells,
and drawing hostile values is how that independence gets exercised. The same
strategy is the one Property 20 (CSV round-trip fidelity) needs, so it is
written once here.

These strategies generate values that satisfy every ``Finding.__post_init__``
rule, so ``findings()`` never produces a draw that fails construction:

  * the three enum fields are drawn as enum *members*;
  * every other field except ``resource_id`` is drawn as a ``str``;
  * ``resource_id`` is the one nullable field, so ``None`` is in its range;
  * ``title`` is built as ``f"{check_id} {...}"``, satisfying the rule that a
    title must begin with its check ID followed by one space.

Strategies that generate *illegal* input belong with the property that needs
them (Property 8 needs non-member enum strings), not here.
"""
from __future__ import annotations

from hypothesis import strategies as st

from sraverify.core.enums import AccountType, Severity, Status
from sraverify.core.finding import GLOBAL_REGION, Finding

__all__ = [
    "cell_text",
    "check_ids",
    "findings",
    "regions",
]


#: Cell values that have historically broken one CSV layer or another. Drawn
#: alongside ordinary text so an ordinary run sees both.
_HOSTILE_CELLS = (
    "",
    " ",
    ",",
    "a,b",
    '"',
    '""',
    'he said "no"',
    "\r",
    "\n",
    "\r\n",
    "line one\nline two",
    "\t",
    "  leading spaces",
    "trailing spaces  ",
    "é",
    "日本語",
    "emoji \U0001f600",
    "arn:aws:s3:::bucket/key,with-comma",
    "AccessDenied: User is not authorized to perform: guardduty:GetDetector",
)


def cell_text(max_size: int = 40) -> st.SearchStrategy[str]:
    """Return a strategy for one CSV cell's worth of text.

    Mixes ordinary generated text with the hostile literals above, and with
    short concatenations of the two so a single cell can carry, say, a comma
    and a newline and a quote at once.

    Args:
        max_size: Upper bound on the length of the ordinary-text component.

    Returns:
        A strategy producing ``str`` values, including the empty string.
    """
    plain = st.text(max_size=max_size)
    hostile = st.sampled_from(_HOSTILE_CELLS)
    mixed = st.lists(
        st.one_of(st.text(max_size=8), hostile), min_size=2, max_size=4
    ).map("".join)
    return st.one_of(plain, hostile, mixed)


def check_ids() -> st.SearchStrategy[str]:
    """Return a strategy for check IDs in the ``SRA-<SERVICE>-NN`` shape.

    ``Finding`` itself does not constrain ``check_id`` beyond requiring a
    ``str`` -- the format rule lives on ``CheckMeta``. Generating the real
    shape anyway keeps the drawn findings representative of what a scan
    actually emits, and keeps the generated ``title`` prefix realistic.

    Returns:
        A strategy producing strings such as ``"SRA-GUARDDUTY-01"``.
    """
    service = st.text(
        alphabet=st.characters(min_codepoint=ord("A"), max_codepoint=ord("Z")),
        min_size=1,
        max_size=12,
    )
    number = st.integers(min_value=1, max_value=99).map(lambda n: f"{n:02d}")
    return st.builds(lambda s, n: f"SRA-{s}-{n}", service, number)


def regions() -> st.SearchStrategy[str]:
    """Return a strategy for the ``region`` field.

    Includes ``GLOBAL_REGION``, which non-regional checks use, alongside a
    handful of real region names and arbitrary text -- ``Finding`` places no
    constraint on the value beyond it being a ``str``.

    Returns:
        A strategy producing ``str`` values.
    """
    known = st.sampled_from(
        [
            GLOBAL_REGION,
            "us-east-1",
            "us-west-2",
            "eu-west-1",
            "ap-southeast-2",
            "us-gov-west-1",
        ]
    )
    return st.one_of(known, cell_text(max_size=16))


@st.composite
def findings(draw: st.DrawFn) -> Finding:
    """Draw one arbitrary valid ``Finding``.

    Every field is drawn independently except ``title``, which is derived from
    the drawn ``check_id`` so the ``__post_init__`` prefix rule holds. The
    three enum fields are drawn as members rather than as their values, which
    is the shape a real check produces and the shape Property 5 requires
    elsewhere in the design.

    Args:
        draw: Supplied by ``hypothesis``.

    Returns:
        A ``Finding`` that constructed successfully, so every
        ``__post_init__`` rule is satisfied.
    """
    check_id = draw(check_ids())
    return Finding(
        check_id=check_id,
        status=draw(st.sampled_from(list(Status))),
        region=draw(regions()),
        severity=draw(st.sampled_from(list(Severity))),
        # The prefix rule: a title must begin with its check ID and one space.
        title=f"{check_id} {draw(cell_text())}",
        description=draw(cell_text()),
        # The one nullable field.
        resource_id=draw(st.one_of(st.none(), cell_text())),
        resource_type=draw(cell_text(max_size=24)),
        account_id=draw(
            st.one_of(
                st.text(alphabet="0123456789", min_size=12, max_size=12),
                st.just(""),
                cell_text(max_size=16),
            )
        ),
        account_name=draw(cell_text(max_size=24)),
        checked_value=draw(cell_text()),
        actual_value=draw(cell_text()),
        remediation=draw(cell_text()),
        service=draw(cell_text(max_size=24)),
        check_logic=draw(cell_text()),
        account_type=draw(st.sampled_from(list(AccountType))),
    )
