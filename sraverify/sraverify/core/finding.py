"""The formalized finding model and the CSV column contract."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Final

from sraverify.core.enums import AccountType, Severity, Status

GLOBAL_REGION: Final = "global"

#: The three enum-typed fields, paired with their enum. Drives coercion.
_ENUM_FIELDS: Final = (
    ("status", Status),
    ("severity", Severity),
    ("account_type", AccountType),
)

#: Every field that must hold a str. ``resource_id`` is excluded: it is the
#: one nullable field. The three enum fields are excluded: they are coerced.
_STR_FIELDS: Final = (
    "check_id", "region", "title", "description", "resource_type",
    "account_id", "account_name", "checked_value", "actual_value",
    "remediation", "service", "check_logic",
)


@dataclass(frozen=True, slots=True)
class Finding:
    """One row of scanner output. Immutable once constructed."""

    check_id: str
    status: Status
    region: str
    severity: Severity
    title: str
    description: str
    resource_id: str | None
    resource_type: str
    account_id: str
    account_name: str
    checked_value: str
    actual_value: str
    remediation: str
    service: str
    check_logic: str
    account_type: AccountType

    #: The public CSV contract. An immutable sequence, and the single
    #: declaration of the sixteen column names. Order is parsed by
    #: sra-verify-dashboard.html and sra-verify-comparison-dashboard.html.
    #: Do not reorder.
    FIELDS: ClassVar[tuple[str, ...]] = (
        "AccountId", "AccountName", "Region", "CheckId", "Status", "Severity",
        "Title", "Description", "ResourceId", "ResourceType", "CheckedValue",
        "ActualValue", "Remediation", "Service", "CheckLogic", "AccountType",
    )

    def __post_init__(self) -> None:
        """Coerce the enum fields and reject anything that cannot be a cell.

        A dataclass field annotation performs no run-time check, and both
        ``StrEnum`` members and plain strings are ``str``. Without this method
        ``Finding(status="pass", severity="Unknown", ...)`` constructs happily
        and renders straight into a CSV cell.

        Runs after every field is bound, so it validates a fully constructed
        instance and can compare fields against one another.
        """
        # Coercion on a frozen dataclass must bypass the blocked __setattr__.
        # This works under slots=True as well: object.__setattr__ writes the
        # slot descriptor directly.
        for name, enum_cls in _ENUM_FIELDS:
            raw = getattr(self, name)
            if isinstance(raw, enum_cls):
                continue
            try:
                object.__setattr__(self, name, enum_cls(raw))
            except ValueError:
                raise ValueError(
                    f"Finding.{name}: {raw!r} is not a member of "
                    f"{enum_cls.__name__} nor one of its values "
                    f"{[m.value for m in enum_cls]}"
                ) from None

        for name in _STR_FIELDS:
            value = getattr(self, name)
            if not isinstance(value, str):
                raise TypeError(
                    f"Finding.{name} must be str, got "
                    f"{type(value).__name__}: {value!r}"
                )

        if self.resource_id is not None and not isinstance(self.resource_id, str):
            raise TypeError(
                f"Finding.resource_id must be str or None, got "
                f"{type(self.resource_id).__name__}: {self.resource_id!r}"
            )

        if not self.title.startswith(f"{self.check_id} "):
            raise ValueError(
                f"Finding.title must begin with check_id and one space: "
                f"title={self.title!r}, check_id={self.check_id!r}"
            )

    def to_row(self) -> dict[str, str]:
        """Render this finding as one CSV row, keyed by FIELDS in FIELDS order.

        Enum fields are rendered with an explicit ``.value`` so the output does
        not depend on enum ``__str__`` / ``__format__`` behavior, which varies
        by Python version for str-mixin enums. ``resource_id=None`` renders as
        the empty string, matching what ``csv.DictWriter`` already writes today.

        No quoting, no escaping, and no truncation is applied: delimiter
        handling belongs solely to the CSV writer.
        """
        return {
            "AccountId": self.account_id,
            "AccountName": self.account_name,
            "Region": self.region,
            "CheckId": self.check_id,
            "Status": self.status.value,
            "Severity": self.severity.value,
            "Title": self.title,
            "Description": self.description,
            "ResourceId": self.resource_id if self.resource_id is not None else "",
            "ResourceType": self.resource_type,
            "CheckedValue": self.checked_value,
            "ActualValue": self.actual_value,
            "Remediation": self.remediation,
            "Service": self.service,
            "CheckLogic": self.check_logic,
            "AccountType": self.account_type.value,
        }
