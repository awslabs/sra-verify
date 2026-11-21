from collections.abc import Iterable, Mapping

from sraverify.core.aws_errors import is_error
from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.kms.base import KMSCheck


_REQUIRED_KEY_PROPERTIES = {
    "KeyManager": "CUSTOMER",
    "KeyState": "Enabled",
    "KeySpec": "SYMMETRIC_DEFAULT",
    "Origin": "AWS_KMS",
}


class SRA_KMS_01(KMSCheck):
    meta = CheckMeta(
        check_id="SRA-KMS-01",
        title="Eligible KMS keys rotate automatically at least annually",
        description=(
            "Checks automatic rotation for enabled customer-managed symmetric KMS keys with AWS-generated key material. "
            "Multi-Region keys are evaluated in the primary key's Region."
        ),
        check_logic="Check whether automatic key rotation is enabled with a rotation period of at most 365 days.",
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service="KMS",
        resource_type="AWS::KMS::Key",
        remediation=Remediation(text="Enable automatic rotation for the KMS key and set a rotation period of 365 days or less."),
        sra_sections=("AWS Key Management Service",),
        additional_urls=("https://docs.aws.amazon.com/kms/latest/APIReference/API_EnableKeyRotation.html",),
    )

    def execute(self) -> Iterable[Finding]:
        for region in dict.fromkeys(self.regions):
            inventory = self.get_keys(region)
            regional_id = f"kms:{region}"
            if is_error(inventory):
                yield self._read_error(region, regional_id, inventory["Error"])
                continue
            keys = inventory.get("Keys") if isinstance(inventory, Mapping) and "Error" not in inventory else None
            if not isinstance(keys, list):
                yield self._malformed(region, regional_id, "ListKeys", "an invalid inventory")
                continue
            seen = set()
            malformed_entry = False
            for key in keys:
                identity = self._key_identity(key, region)
                if identity is None:
                    malformed_entry = True
                    continue
                key_id, arn = identity
                if arn not in seen:
                    seen.add(arn)
                    yield from self._evaluate_key(region, key_id, arn)
            if malformed_entry:
                yield self._malformed(region, regional_id, "ListKeys", "an invalid key identity")

    def _key_identity(self, entry: object, region: str) -> tuple[str, str] | None:
        if not isinstance(entry, Mapping):
            return None
        key_id, arn = entry.get("KeyId"), entry.get("KeyArn")
        if not isinstance(key_id, str) or not key_id.strip() or not isinstance(arn, str):
            return None
        parts = arn.split(":", 5)
        if (
            len(parts) != 6 or parts[0] != "arn" or not parts[1].startswith("aws")
            or parts[2:] != ["kms", region, self.account_id, f"key/{key_id}"]
        ):
            return None
        return key_id, arn

    @staticmethod
    def _eligible(metadata: Mapping) -> bool | None:
        for field, expected in _REQUIRED_KEY_PROPERTIES.items():
            value = metadata.get(field)
            if not isinstance(value, str) or not value.strip():
                return None
            if value != expected:
                return False
        multi_region = metadata.get("MultiRegion")
        if multi_region is False:
            return True
        if multi_region is True:
            configuration = metadata.get("MultiRegionConfiguration")
            role = configuration.get("MultiRegionKeyType") if isinstance(configuration, Mapping) else None
            if role in ("PRIMARY", "REPLICA"):
                return role == "PRIMARY"
        return None

    def _evaluate_key(self, region: str, key_id: str, arn: str) -> Iterable[Finding]:
        result = self.get_key(region, arn)
        if is_error(result):
            yield self._read_error(region, arn, result["Error"], key_level=True)
            return
        metadata = result.get("KeyMetadata") if isinstance(result, Mapping) and "Error" not in result else None
        if (
            not isinstance(metadata, Mapping) or metadata.get("Arn") != arn
            or metadata.get("KeyId") != key_id or metadata.get("AWSAccountId") != self.account_id
        ):
            yield self._malformed(region, arn, "DescribeKey", "missing or mismatched key metadata")
            return
        eligible = self._eligible(metadata)
        if eligible is None:
            yield self._malformed(region, arn, "DescribeKey", "incomplete eligibility information")
            return
        if not eligible:
            return

        rotation = self.get_rotation_status(region, arn)
        if is_error(rotation):
            yield self._read_error(region, arn, rotation["Error"], key_level=True)
            return
        if (
            not isinstance(rotation, Mapping) or "Error" in rotation
            or rotation.get("KeyId", arn) not in (key_id, arn)
        ):
            yield self._malformed(region, arn, "GetKeyRotationStatus", "invalid or mismatched rotation information")
            return
        enabled = rotation.get("KeyRotationEnabled")
        period = rotation.get("RotationPeriodInDays")
        if enabled is False:
            yield self.failed(region=region, resource_id=arn, actual_value="Automatic key rotation is disabled")
        elif enabled is not True or type(period) is not int or not 90 <= period <= 2560:
            yield self._malformed(region, arn, "GetKeyRotationStatus", "a missing or invalid rotation setting")
        elif period <= 365:
            yield self.passed(region=region, resource_id=arn, actual_value=f"Automatic key rotation is enabled every {period} days")
        else:
            yield self.failed(region=region, resource_id=arn, actual_value=f"Automatic key rotation period is {period} days, exceeding 365 days")

    def _read_error(self, region: str, resource_id: str, error: Mapping[str, str], *, key_level: bool = False) -> Finding:
        remediation = self._remediation_for(error)
        if key_level and error["Code"] in {"AccessDenied", "AccessDeniedException"}:
            remediation += " Verify that the KMS key policy allows the scan role to read the key or delegates access to IAM."
        return self.error(
            region=region, resource_id=resource_id,
            actual_value=f"{error['Operation']} failed: {error['Code']}: {error['Message']}", remediation=remediation,
        )

    def _malformed(self, region: str, resource_id: str, operation: str, problem: str) -> Finding:
        return self.error(
            region=region, resource_id=resource_id, actual_value=f"{operation} returned {problem}",
            remediation=f"Retry the scan and inspect the KMS {operation} response.",
        )
