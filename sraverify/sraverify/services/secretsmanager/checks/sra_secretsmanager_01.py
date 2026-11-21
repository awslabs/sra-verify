"""
SRA-SECRETSMANAGER-01: Secrets Manager automatic rotation is enabled for every secret.
"""
import re
from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any

from sraverify.core.aws_errors import error_result
from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.secretsmanager.base import SecretsManagerCheck

_SECRET_ARN = re.compile(
    r"^arn:aws[a-z-]*:secretsmanager:(?P<region>[a-z0-9-]+):(?P<account>\d{12}):secret:[^\s]+$"
)


class SRA_SECRETSMANAGER_01(SecretsManagerCheck):
    """Check if automatic rotation is enabled for every primary secret."""

    meta = CheckMeta(
        check_id="SRA-SECRETSMANAGER-01",
        title="Secrets Manager automatic rotation is enabled for every secret",
        description=(
            "This check verifies that every secret the account owns in each Region has "
            "automatic rotation enabled in its configuration. It reports the configured "
            "state only: it does not establish that a secret can be rotated or that a "
            "rotation has run. Secrets pending deletion and replica secrets are skipped."
        ),
        check_logic=(
            "For each Region list secret ARNs with ListSecrets, then call DescribeSecret per "
            "ARN. Skips secrets with a DeletedDate, a PrimaryRegion in another Region or a "
            "CrossAccountPrimary. Passes when RotationEnabled is true; fails when it is "
            "false or absent. A failed or malformed API result is an ERROR."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service="Secrets Manager",
        resource_type="AWS::SecretsManager::Secret",
        remediation=Remediation(
            text=(
                "Confirm that the secret type supports automatic rotation, then enable it "
                "through the service that manages the secret or through the applicable "
                "Secrets Manager rotation option (managed rotation, external secret "
                "provider rotation or a rotation Lambda function)."
            ),
            cli=(
                "aws secretsmanager describe-secret --secret-id <secret-arn> --region <region>\n"
                "Rotation Lambda function only: aws secretsmanager rotate-secret "
                "--secret-id <secret-arn> --rotation-lambda-arn <lambda-arn> "
                "--rotation-rules AutomaticallyAfterDays=<days> --region <region>"
            ),
            console=(
                "Secrets Manager console, choose the secret, Rotation configuration, Edit "
                "rotation, and choose the rotation option the secret type supports."
            ),
        ),
        sra_sections=("Application account", "AWS Secrets Manager"),
        additional_urls=(
            "https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html",
            "https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DescribeSecret.html",
        ),
    )

    def _region_error(self, region: str, code: str, message: str, operation: str) -> Finding:
        failure = error_result(code=code, message=message, operation=operation)["Error"]
        return self._region_error_from(region, failure)

    def _region_error_from(self, region: str, error: Mapping[str, str]) -> Finding:
        return self.error(
            region=region,
            resource_id=f"secretsmanager:{region}:{self.account_id}",
            actual_value=f"{error['Operation']} failed: {error['Code']}: {error['Message']}",
            remediation=self._remediation_for(error),
        )

    def _candidates(self, listing: Any, region: str) -> tuple[list[str], int] | None:
        if (
            not isinstance(listing, Mapping)
            or not isinstance(listing.get("SecretList"), list)
            or listing.get("InvalidPages")
        ):
            return None
        arns: set[str] = set()
        malformed = 0
        for entry in listing["SecretList"]:
            arn = entry.get("ARN") if isinstance(entry, Mapping) else None
            match = _SECRET_ARN.match(arn) if isinstance(arn, str) else None
            if match and match["region"] == region and match["account"] == self.account_id:
                arns.add(arn)
            else:
                malformed += 1
        return sorted(arns), malformed

    def _evaluate(self, region: str, arn: str) -> Finding | None:
        described = self.get_secret(region, arn)
        if isinstance(described, Mapping) and "Error" in described:
            error = described["Error"]
            return self.error(
                region=region,
                resource_id=arn,
                actual_value=f"{error['Operation']} failed: {error['Code']}: {error['Message']}",
                remediation=self._remediation_for(error),
            )

        def invalid(reason: str) -> Finding:
            return self.error(
                region=region,
                resource_id=arn,
                actual_value=f"DescribeSecret returned {reason}",
                remediation=(
                    "Re-run the scan; if it persists, check the SDK version and the "
                    "DescribeSecret response for this secret."
                ),
            )

        if not isinstance(described, Mapping) or described.get("ARN") != arn:
            return invalid("a response that does not match the requested secret")

        deleted = described.get("DeletedDate")
        if deleted is not None:
            return None if isinstance(deleted, datetime) else invalid("an invalid DeletedDate")

        primary = described.get("PrimaryRegion")
        if primary is not None:
            if not isinstance(primary, str):
                return invalid("an invalid PrimaryRegion")
            if primary != region:
                return None

        cross_account = described.get("CrossAccountPrimary")
        if cross_account is not None:
            return None if isinstance(cross_account, Mapping) else invalid(
                "an invalid CrossAccountPrimary"
            )

        enabled = described.get("RotationEnabled")
        if enabled is True:
            return self.passed(
                region=region,
                resource_id=arn,
                actual_value="Automatic rotation is enabled in the secret configuration",
            )
        if enabled is None or enabled is False:
            return self.failed(
                region=region,
                resource_id=arn,
                actual_value="Automatic rotation is not enabled in the secret configuration",
                remediation=(
                    f"Confirm that {arn} supports automatic rotation, then enable it through "
                    f"the service that manages the secret or the applicable Secrets Manager "
                    f"rotation option in {region}."
                ),
            )
        return invalid("an invalid RotationEnabled")

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per evaluated secret, plus one Region-level ERROR when the
            inventory fails, is invalid or holds malformed entries. No Finding when
            a Region has no secret to evaluate.
        """
        for region in dict.fromkeys(self.regions):
            listing = self.get_secrets(region)
            if isinstance(listing, Mapping) and "Error" in listing:
                yield self._region_error_from(region, listing["Error"])
                continue

            candidates = self._candidates(listing, region)
            if candidates is None:
                yield self._region_error(
                    region,
                    "InvalidResponse",
                    "ListSecrets returned an invalid inventory",
                    "ListSecrets",
                )
                continue

            arns, malformed = candidates
            if malformed:
                yield self._region_error(
                    region,
                    "InvalidResponse",
                    f"ListSecrets returned {malformed} entries that are not a secret ARN "
                    "in this account and Region; they were not evaluated",
                    "ListSecrets",
                )
            for arn in arns:
                finding = self._evaluate(region, arn)
                if finding is not None:
                    yield finding
