"""
Unit tests for ``SecurityCheck._remediation_for`` and ``is_not_configured``.

``_remediation_for`` supplies the ``remediation`` cell for an ERROR row built
from an error result. ``error()`` refuses a blank one, so this helper is what
stands between "the control could not be evaluated" and an unfillable required
field.

The two things worth testing are what it says and what it refuses to say.

**What it says:** wording chosen by ``Code`` class -- transport, ``NoClient``,
access-denied, everything else -- each naming the operation, because an ERROR
row's job is to distinguish a permission gap from an unreachable endpoint
without sending the reader to the build log (Requirement 4.8).

**What it refuses to say:** an IAM action string. Requirement 4.8 forbids
composing one from ``meta.service``, because that is a display name and not an
IAM prefix. ``IAM Access Analyzer`` is ``access-analyzer``, ``FirewallManager``
is ``fms``, ``Security Lake`` is ``securitylake``, ``GuardDuty`` is
``guardduty`` -- so an interpolated ``f"{service}:{Operation}"`` is wrong for
several services, and a confidently wrong action is worse than a vague one.

Validates: Requirements 4.3, 4.4, 4.8.
"""
from __future__ import annotations

import re
from typing import Any

import pytest

from sraverify.core.aws_errors import (
    NO_CLIENT_CODE,
    TRANSPORT_ERROR_CODES,
    UNKNOWN_OPERATION,
    NotConfigured,
    error_result,
    no_client_result,
)
from sraverify.core.check import SecurityCheck
from sraverify.core.enums import AccountType, Severity
from sraverify.core.metadata import CheckMeta, Remediation

#: Display names in the real catalog whose IAM prefix differs from the name.
#: These are the values that make a composed action string wrong.
_MISLEADING_SERVICE_NAMES: tuple[tuple[str, str], ...] = (
    ("IAM Access Analyzer", "access-analyzer"),
    ("FirewallManager", "fms"),
    ("Security Lake", "securitylake"),
    ("Security Hub", "securityhub"),
    ("Audit Manager", "auditmanager"),
    ("Security Incident Response", "security-ir"),
)


def _concrete(
    *, service: str = "GuardDuty", table: Any = None
) -> type[SecurityCheck]:
    """Build a throwaway concrete ``SecurityCheck`` subclass.

    Declared in this module, whose file stem does not start with ``sra_``, so
    ``__init_subclass__`` returns silently and the class does not register. That
    is also why this can legally declare ``NOT_CONFIGURED_ERRORS``: the
    service-only rule fires for classes in ``sra_*`` modules, and a class here
    stands in for a *service base*, not for a check.

    Args:
        service: ``meta.service``, so the IAM-prefix tests can vary it.
        table: An optional ``NOT_CONFIGURED_ERRORS`` value.

    Returns:
        A concrete subclass, ready to instantiate.
    """
    namespace: dict[str, Any] = {
        "__doc__": "Throwaway check for a remediation test.",
        "__module__": __name__,
        "meta": CheckMeta(
            check_id="SRA-GUARDDUTY-01",
            title="A synthetic control is configured",
            description="Synthetic description for a remediation test.",
            check_logic="Synthetic logic.",
            severity=Severity.HIGH,
            account_type=AccountType.APPLICATION,
            service=service,
            resource_type="AWS::GuardDuty::Detector",
            remediation=Remediation(text="Enable the control in every Region."),
        ),
        "execute": lambda self: iter(()),
        "_setup_clients": lambda self: None,
    }
    if table is not None:
        namespace["NOT_CONFIGURED_ERRORS"] = table
    return type("SRA_GUARDDUTY_01", (SecurityCheck,), namespace)


@pytest.fixture
def check() -> SecurityCheck:
    """A concrete check instance with the default (empty) table.

    Returns:
        An instance. ``_remediation_for`` and ``is_not_configured`` are both
        pure with respect to per-scan state, so no ``ScanContext`` is attached --
        which is itself worth knowing: an ERROR row's remediation must be
        derivable without a working context, because a ``NoClient`` error result
        arises precisely when part of the scan environment is missing.
    """
    return _concrete()()


# --------------------------------------------------------------------------- #
# The four Code classes
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("code", sorted(TRANSPORT_ERROR_CODES))
def test_a_transport_code_gets_network_wording(check: SecurityCheck, code: str) -> None:
    """A transport failure points at reachability, not at permissions.

    Reading ``EndpointConnectionError`` as a permission problem would send the
    reader to the IAM policy for a DNS failure.

    The wording names the **service**, not an operation. A transport failure means
    the request never went out, so ``AWSClient.aws_error`` records no operation and
    there is none to name -- the row's own ``Region`` column supplies the rest of
    the address.
    """
    text = check._remediation_for(
        error_result(code=code, message="m", operation=UNKNOWN_OPERATION)["Error"]
    )

    assert "reachable" in text.lower()
    assert check.service in text
    assert "permission" not in text.lower()
    assert UNKNOWN_OPERATION not in text, (
        f"the placeholder operation leaked into remediation wording: {text!r}"
    )


def test_the_no_client_code_points_at_the_regions_flag(check: SecurityCheck) -> None:
    """``NoClient`` is a scan-configuration condition, so name the flag.

    The row means no client wrapper existed for the Region, which is either a
    Region the account has not enabled or one the operator did not pass.
    """
    text = check._remediation_for(
        no_client_result(service="Security Lake", region="eu-west-3")["Error"]
    )

    assert "--regions" in text
    assert check.service in text
    assert UNKNOWN_OPERATION not in text, (
        f"the placeholder operation leaked into remediation wording: {text!r}"
    )


@pytest.mark.parametrize(
    "code",
    [
        "AccessDeniedException",
        "AccessDenied",
        "UnauthorizedOperation",
        "UnauthorizedException",
    ],
)
def test_every_spelling_of_access_denied_gets_permission_shaped_advice(
    check: SecurityCheck, code: str
) -> None:
    """AWS spells "not permitted" four ways; none may fall through to the generic bucket.

    ``s3control`` says ``AccessDenied``, ``macie2`` and most others say
    ``AccessDeniedException``, ``ec2`` says ``UnauthorizedOperation``, and
    ``securitylake`` says ``UnauthorizedException``. Matching one literal would
    leave the other three landing on "investigate the code in the scan log", which
    is what the generic bucket says and is much less useful than naming a cause.

    The assertion is *permission-shaped advice*, not one exact sentence. With a
    message that discriminates nothing -- ``"m"`` here -- all four land in the
    cause-not-stated bucket, which offers the IAM grant and the delegated
    administrator together. Requiring "Grant the member role" verbatim would be
    requiring the helper to guess between them, which is what
    ``_IAM_DENIAL_NEEDLES`` exists to stop it doing.
    """
    text = check._remediation_for(
        error_result(code=code, message="m", operation="GetDetector")["Error"]
    )

    assert "GetDetector" in text
    assert "1-sraverify-member-roles.yaml" in text, (
        f"{code} did not offer the IAM cause: {text!r}"
    )
    assert "scan log" not in text, (
        f"{code} fell through to the generic bucket: {text!r}"
    )


def test_an_unrecognized_code_gets_the_generic_wording(check: SecurityCheck) -> None:
    """Anything else names the code and sends the reader to the log.

    Vague on purpose: the helper knows nothing about a code it has never seen,
    and naming it plus where to look is the most it can honestly offer.
    """
    text = check._remediation_for(
        error_result(
            code="ThrottlingException", message="m", operation="ListProtections"
        )["Error"]
    )

    assert "ThrottlingException" in text
    assert "ListProtections" in text


# --------------------------------------------------------------------------- #
# Requirement 4.8 -- no fabricated IAM action
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "code",
    [
        "AccessDeniedException",
        "AccessDenied",
        "UnauthorizedOperation",
        "UnauthorizedException",
        "EndpointConnectionError",
        NO_CLIENT_CODE,
        "SomeFutureException",
    ],
)
@pytest.mark.parametrize(
    "service,iam_prefix", _MISLEADING_SERVICE_NAMES, ids=[s for s, _ in _MISLEADING_SERVICE_NAMES]
)
def test_no_bucket_composes_an_iam_action_from_the_display_name(
    code: str, service: str, iam_prefix: str
) -> None:
    """The helper never emits ``<DisplayName>:<Operation>``.

    Checked across every ``Code`` bucket and every display name in the catalog
    whose IAM prefix differs from it, because the access-denied bucket is the
    tempting place to compose one and the generic bucket is where it would be
    added later without thinking.

    The assertion is structural rather than a string comparison: no ``:``
    immediately joining a word to the operation name.
    """
    instance = _concrete(service=service)()

    text = instance._remediation_for(
        error_result(code=code, message="m", operation="GetDetector")["Error"]
    )

    assert f"{service}:GetDetector" not in text
    assert f"{iam_prefix}:GetDetector" not in text
    # No token of any kind glued to the operation by a colon.
    assert not re.search(r"\S:GetDetector", text), (
        f"{service!r}/{code}: composed an action-like string in {text!r}"
    )


# --------------------------------------------------------------------------- #
# Invariants every bucket shares
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "code",
    [
        "AccessDeniedException",
        "EndpointConnectionError",
        "ConnectTimeoutError",
        "ReadTimeoutError",
        NO_CLIENT_CODE,
        "ValidationException",
        "ThrottlingException",
        "BadRequestException",
        "InvalidAccessException",
    ],
)
def test_every_bucket_returns_a_non_blank_string_naming_its_subject(
    check: SecurityCheck, code: str
) -> None:
    """``error()`` raises on a blank remediation, so this may never return one.

    Requirement 4.8 asks that the wording identify *what* could not be done, and
    which noun does that depends on the bucket. Where AWS answered, the operation
    is the sharpest available subject. Where nothing was sent -- transport and
    ``NoClient`` -- there is no operation, and the service plus the row's Region
    is the whole of what is knowable. Either way a reader can tell a permission
    gap from an unreachable endpoint from the CSV alone, which is the point.
    """
    text = check._remediation_for(
        error_result(code=code, message="m", operation="DescribeTrails")["Error"]
    )

    assert isinstance(text, str)
    assert text.strip()

    names_nothing_sent = code in TRANSPORT_ERROR_CODES or code == NO_CLIENT_CODE
    expected = check.service if names_nothing_sent else "DescribeTrails"
    assert expected in text, (
        f"{code}: expected {expected!r} in remediation, got {text!r}"
    )


@pytest.mark.parametrize(
    "error",
    [
        {},
        {"Code": "AccessDeniedException"},
        {"Operation": "GetDetector"},
        {"Code": "", "Operation": "", "Message": ""},
    ],
    ids=["empty", "code-only", "operation-only", "blank"],
)
def test_a_malformed_error_dict_still_yields_a_usable_string(
    check: SecurityCheck, error: Any
) -> None:
    """Total over its input, and never blank.

    A ``KeyError`` here would abort the check and cost every row it had already
    yielded, to avoid filling in one cell. The operation falls back to a phrase
    rather than to the empty string, so ``error()``'s non-blank guard cannot be
    tripped by a degenerate error result.
    """
    text = check._remediation_for(error)

    assert isinstance(text, str)
    assert text.strip()


def test_the_remediation_does_not_repeat_the_control_level_advice(
    check: SecurityCheck,
) -> None:
    """An ERROR row's remediation addresses the scan, not the control.

    ``meta.remediation.text`` ("Enable the control in every Region.") is the
    right advice for a FAIL and the wrong advice for an ERROR: the scanner never
    established that the control is absent. This is why ``error()`` has no
    metadata fallback, and this asserts the helper does not reintroduce one.
    """
    text = check._remediation_for(
        error_result(
            code="AccessDeniedException", message="m", operation="GetDetector"
        )["Error"]
    )

    assert check.meta.remediation.text not in text


# --------------------------------------------------------------------------- #
# is_not_configured on the check
# --------------------------------------------------------------------------- #


def test_the_default_table_classifies_nothing(check: SecurityCheck) -> None:
    """An unmigrated service resolves every error to ERROR.

    This is what makes the migration safe to land in batches: a service whose
    table has not been written yet cannot emit a fabricated FAIL.
    """
    assert (
        check.is_not_configured(
            error_result(
                code="ResourceNotFoundException",
                message="m",
                operation="GetDetector",
            )["Error"]
        )
        is False
    )


def test_a_declared_pair_classifies_as_not_configured() -> None:
    """The delegation works end to end from an instance."""
    instance = _concrete(
        table={
            "DescribeOrganizationConfiguration": {
                "BadRequestException": NotConfigured(evidence="API reference"),
            }
        }
    )()

    assert instance.is_not_configured(
        error_result(
            code="BadRequestException",
            message="a delegated administrator account has not been enabled",
            operation="DescribeOrganizationConfiguration",
        )["Error"]
    )


def test_the_same_code_from_another_operation_does_not_classify() -> None:
    """The operation dimension, exercised through the check.

    This is the case that motivated keying the table by operation:
    ``BadRequestException`` means "no delegated administrator" -- the control is
    absent -- through ``DescribeOrganizationConfiguration``, and "not the master
    account" -- run it somewhere else -- through
    ``ListOrganizationAdminAccounts``. One is a FAIL and the other an ERROR, and
    the code alone cannot tell them apart.
    """
    instance = _concrete(
        table={
            "DescribeOrganizationConfiguration": {
                "BadRequestException": NotConfigured(evidence="API reference"),
            }
        }
    )()

    assert (
        instance.is_not_configured(
            error_result(
                code="BadRequestException",
                message="The request is rejected since no such resource found.",
                operation="ListOrganizationAdminAccounts",
            )["Error"]
        )
        is False
    )


def test_is_not_configured_reads_the_class_not_the_instance() -> None:
    """An instance attribute cannot redirect the classification.

    The table is a class-level declaration -- ``__init_subclass__`` enforces
    where it may be declared -- and reading it through ``type(self)`` is what
    makes that enforcement meaningful at call time as well as at import time.
    """
    instance = _concrete(
        table={"GetDetector": {"CodeA": NotConfigured(evidence="e")}}
    )()

    object.__setattr__(
        instance,
        "NOT_CONFIGURED_ERRORS",
        {"GetDetector": {"CodeB": NotConfigured(evidence="e")}},
    )

    assert instance.is_not_configured(
        error_result(code="CodeA", message="m", operation="GetDetector")["Error"]
    )
    assert (
        instance.is_not_configured(
            error_result(code="CodeB", message="m", operation="GetDetector")["Error"]
        )
        is False
    )


# --------------------------------------------------------------------------- #
# The wrong-account bucket
#
# Several AWS services refuse an organization-scoped read from any account that
# is not the delegated administrator, and report it as ``AccessDeniedException``
# -- the same code a genuine IAM gap produces. Both messages below were observed
# on a 13-account organization scan on 2026-09-16 from an account that *held* the
# action, and reproduced with ``AdministratorAccess``, which is what establishes
# that IAM was not the constraint.
#
# Before this bucket existed, 500 of 501 ERROR rows in that report told the
# operator to grant a permission the role already had.
# --------------------------------------------------------------------------- #

#: The verbatim message ``securitylake`` returns to a non-delegated-administrator.
_SECURITYLAKE_REFUSAL = (
    "The request failed because you don't have sufficient permissions to perform "
    "this operation for your organization. Contact your administrator for assistance."
)

#: The verbatim message ``macie2`` returns to an account that is not the Macie
#: administrator.
_MACIE_REFUSAL = (
    "The request failed because you must be the Macie administrator for an "
    "organization to perform this operation"
)

#: A genuine IAM denial, verbatim, for contrast. This one *should* keep the
#: grant-the-permission wording, because granting it is the fix.
_IAM_DENIAL = (
    "User: arn:aws:sts::111122223333:assumed-role/SRAMemberRole/sraverify-session "
    "is not authorized to perform: iam:ListUsers on resource: arn:aws:iam::"
    "111122223333:user/"
)


@pytest.mark.parametrize(
    "message,operation",
    [
        (_SECURITYLAKE_REFUSAL, "ListLogSources"),
        (_SECURITYLAKE_REFUSAL, "ListSubscribers"),
        (_SECURITYLAKE_REFUSAL, "GetDataLakeSources"),
        (_MACIE_REFUSAL, "DescribeOrganizationConfiguration"),
    ],
)
def test_a_wrong_account_refusal_does_not_advise_granting_a_permission(
    check: SecurityCheck, message: str, operation: str
) -> None:
    """The advice must not be one that cannot work.

    This is the same failure mode as a confessing FAIL, one column over: a row
    that reads as actionable and sends the reader somewhere useless. An operator
    who grants the action, re-runs, and sees the identical row has spent a policy
    change to learn nothing, and has good reason to stop trusting the report.
    """
    wording = check._remediation_for(
        error_result(code="AccessDeniedException", message=message, operation=operation)[
            "Error"
        ]
    )

    assert "Grant the member role" not in wording, (
        f"{operation} was refused for being the wrong account, but the "
        f"remediation still asks for an IAM grant: {wording!r}"
    )
    assert "delegated administrator" in wording, (
        f"the remediation should name the actual obstacle: {wording!r}"
    )
    assert operation in wording, f"the operation should be named: {wording!r}"


def test_a_genuine_iam_denial_still_advises_granting_the_permission(
    check: SecurityCheck,
) -> None:
    """The narrow needles must not swallow the case they were carved out of.

    A plain IAM denial names the principal and the action and matches neither
    needle, so it keeps the grant-the-permission advice -- which for it is
    correct, and was correct for exactly 1 of the 501 ERROR rows in the observed
    report.
    """
    wording = check._remediation_for(
        error_result(
            code="AccessDenied", message=_IAM_DENIAL, operation="ListUsers"
        )["Error"]
    )

    assert "Grant the member role" in wording, (
        f"a real permission gap must still say so: {wording!r}"
    )
    assert "delegated administrator" not in wording


def test_the_two_access_denied_buckets_are_split_on_message_not_code(
    check: SecurityCheck,
) -> None:
    """One code, two remediations. That is the whole point of the split.

    If this ever collapses to one bucket, the report goes back to giving 500 rows
    advice that cannot work.
    """
    same_code = "AccessDeniedException"
    refused = check._remediation_for(
        error_result(
            code=same_code, message=_SECURITYLAKE_REFUSAL, operation="ListLogSources"
        )["Error"]
    )
    denied = check._remediation_for(
        error_result(
            code=same_code, message=_IAM_DENIAL, operation="ListLogSources"
        )["Error"]
    )

    assert refused != denied, (
        "the same code with two different messages produced the same remediation; "
        "the message needles are not being consulted"
    )
    assert refused.strip() and denied.strip()


def test_an_access_denied_that_states_no_cause_names_both(check: SecurityCheck) -> None:
    """``UnauthorizedException: Unauthorized`` -- observed, and it says nothing.

    ``securitylake:GetDataLakeSources`` answers a non-delegated-administrator
    account with exactly that: no principal, no action, no mention of the
    organization. Reproduced with ``AdministratorAccess``, so it is provably not
    an IAM gap in that account -- but the response does not say so, and 52 rows in
    the observed report landed here.

    Guessing either way would be asserting something the evidence does not
    support, which is the FAIL-versus-ERROR discipline applied one column over. So
    the wording names both causes.
    """
    wording = check._remediation_for(
        error_result(
            code="UnauthorizedException",
            message="Unauthorized",
            operation="GetDataLakeSources",
        )["Error"]
    )

    assert "GetDataLakeSources" in wording
    assert "1-sraverify-member-roles.yaml" in wording, (
        f"the IAM cause should still be offered: {wording!r}"
    )
    assert "delegated administrator" in wording, (
        f"the wrong-account cause should also be offered: {wording!r}"
    )
    assert "not for want of an IAM permission" not in wording, (
        f"this bucket must not claim to know which cause it is: {wording!r}"
    )


def test_the_three_access_denied_buckets_are_mutually_distinct(
    check: SecurityCheck,
) -> None:
    """Three messages, three different remediations, one shared code family."""
    wordings = {
        label: check._remediation_for(
            error_result(code=code, message=msg, operation="ListLogSources")["Error"]
        )
        for label, code, msg in (
            ("wrong_account", "AccessDeniedException", _SECURITYLAKE_REFUSAL),
            ("iam_gap", "AccessDeniedException", _IAM_DENIAL),
            ("unstated", "UnauthorizedException", "Unauthorized"),
        )
    }
    assert len(set(wordings.values())) == 3, (
        f"two buckets collapsed to the same wording: {wordings}"
    )
    for label, w in wordings.items():
        assert w.strip(), f"{label} produced a blank remediation"
