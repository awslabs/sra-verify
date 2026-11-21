from collections.abc import Iterable, Mapping
import re

from sraverify.core.aws_errors import is_error
from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.guardduty.base import GuardDutyCheck

_BUCKET = re.compile(
    r"arn:aws(?:-[a-z0-9]+)*:s3:::([a-zA-Z0-9][a-zA-Z0-9._-]{1,253}[a-zA-Z0-9])(?:/[\s\S]+)?\Z"
)
_KEY = re.compile(
    r"arn:aws(?:-[a-z0-9]+)*:kms:[a-z0-9-]+:[0-9]{12}:key/(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|mrk-[0-9a-f]{32})\Z"
)
_NON_PUBLISHING = {
    "PENDING_VERIFICATION",
    "UNABLE_TO_PUBLISH_FIX_DESTINATION_PROPERTY",
    "STOPPED",
}


class SRA_GUARDDUTY_27(GuardDutyCheck):
    meta = CheckMeta(
        check_id="SRA-GUARDDUTY-27",
        title="GuardDuty findings export to S3 is configured",
        description=(
            "Checks the regional GuardDuty detector for a publishing S3 destination with a KMS key ARN. "
            "An administrator's regional export covers findings from associated member accounts; "
            "Audit account filtering does not verify delegated administrator status."
        ),
        check_logic="Inspect each regional detector and its publishing destinations for an active S3 destination with bucket and KMS key ARNs.",
        severity=Severity.MEDIUM,
        account_type=AccountType.AUDIT,
        service="GuardDuty",
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(
            text="Configure GuardDuty findings export to an S3 bucket with a KMS key in each source Region."
        ),
        sra_sections=("Security Tooling account", "Amazon GuardDuty"),
        additional_urls=(
            "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_exportfindings.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        for region in self.regions:
            resource_id = f"guardduty:{region}"
            detectors = self.get_detector_id(region)
            if is_error(detectors):
                error = detectors["Error"]
                yield self.error(
                    region=region,
                    resource_id=resource_id,
                    actual_value=f"{error['Operation']} failed: {error['Code']}: {error['Message']}",
                    remediation=self._remediation_for(error),
                )
                continue
            if isinstance(detectors, Mapping) and "Error" in detectors:
                yield self.error(
                    region=region,
                    resource_id=resource_id,
                    actual_value="ListDetectors returned a malformed error",
                    remediation="Retry the scan and inspect the ListDetectors response.",
                )
                continue
            ids = (
                detectors.get("DetectorIds") if isinstance(detectors, Mapping) else None
            )
            if ids == []:
                yield self.failed(
                    region=region,
                    resource_id=resource_id,
                    actual_value="No GuardDuty detector in this Region",
                )
                continue
            if (
                not isinstance(ids, list)
                or len(ids) != 1
                or not isinstance(ids[0], str)
                or not ids[0].strip()
                or ids[0] != ids[0].strip()
            ):
                yield self.error(
                    region=region,
                    resource_id=resource_id,
                    actual_value="ListDetectors returned malformed detector IDs",
                    remediation="Retry the scan and inspect the ListDetectors response.",
                )
                continue
            detector_id = ids[0]
            detector = self.get_detector_details(region)
            if is_error(detector):
                error = detector["Error"]
                yield self.error(
                    region=region,
                    resource_id=resource_id,
                    actual_value=f"{error['Operation']} failed: {error['Code']}: {error['Message']}",
                    remediation=self._remediation_for(error),
                )
                continue
            if isinstance(detector, Mapping) and "Error" in detector:
                yield self.error(
                    region=region,
                    resource_id=resource_id,
                    actual_value="GetDetector returned a malformed error",
                    remediation="Retry the scan and inspect the GetDetector response.",
                )
                continue
            status = detector.get("Status") if isinstance(detector, Mapping) else None
            if status == "DISABLED":
                yield self.failed(
                    region=region,
                    resource_id=resource_id,
                    actual_value=f"GuardDuty detector {detector_id} is disabled",
                )
                continue
            if status != "ENABLED":
                yield self.error(
                    region=region,
                    resource_id=resource_id,
                    actual_value="GetDetector returned an unknown or missing status",
                    remediation="Retry the scan and inspect the GetDetector response.",
                )
                continue
            destinations = []
            token = None
            seen = set()
            list_error = None
            while True:
                page = self.list_publishing_destinations(region, detector_id, token)
                if is_error(page):
                    list_error = page["Error"]
                    break
                if isinstance(page, Mapping) and "Error" in page:
                    list_error = "ListPublishingDestinations returned a malformed error"
                    break
                if not isinstance(page, Mapping) or not isinstance(
                    page.get("Destinations"), list
                ):
                    list_error = "ListPublishingDestinations returned a malformed page"
                    break
                destinations.extend(page["Destinations"])
                if "NextToken" not in page:
                    break
                token = page["NextToken"]
                if not isinstance(token, str) or not token.strip() or token in seen:
                    list_error = "ListPublishingDestinations returned a malformed or repeated token"
                    break
                seen.add(token)
            if list_error is not None:
                if isinstance(list_error, Mapping):
                    yield self.error(
                        region=region,
                        resource_id=resource_id,
                        actual_value=f"{list_error['Operation']} failed: {list_error['Code']}: {list_error['Message']}",
                        remediation=self._remediation_for(list_error),
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=resource_id,
                        actual_value=list_error,
                        remediation="Retry the scan and inspect the ListPublishingDestinations response.",
                    )
                continue
            inconclusive = False
            describe_error = None
            passed = False
            candidates = []
            for item in destinations:
                if (
                    not isinstance(item, Mapping)
                    or not isinstance(item.get("DestinationType"), str)
                    or not item.get("DestinationType", "").strip()
                ):
                    inconclusive = True
                elif item["DestinationType"] == "S3":
                    destination_id = item.get("DestinationId")
                    if (
                        not isinstance(destination_id, str)
                        or not destination_id.strip()
                        or destination_id != destination_id.strip()
                    ):
                        inconclusive = True
                    else:
                        candidates.append(destination_id)
            for destination_id in sorted(set(candidates)):
                detail = self.describe_publishing_destination(
                    region, detector_id, destination_id
                )
                if not isinstance(detail, Mapping):
                    inconclusive = True
                    continue
                if "Error" in detail:
                    inconclusive = True
                    if is_error(detail) and describe_error is None:
                        describe_error = detail["Error"]
                    continue
                if (
                    detail.get("DestinationId") != destination_id
                    or detail.get("DestinationType") != "S3"
                ):
                    inconclusive = True
                    continue
                status = detail.get("Status")
                if isinstance(status, str) and status in _NON_PUBLISHING:
                    continue
                if status != "PUBLISHING":
                    inconclusive = True
                    continue
                properties = detail.get("DestinationProperties")
                if not isinstance(properties, Mapping):
                    inconclusive = True
                    continue
                bucket, key = properties.get("DestinationArn"), properties.get(
                    "KmsKeyArn"
                )
                if any(
                    name in properties and not isinstance(properties[name], str)
                    for name in ("DestinationArn", "KmsKeyArn")
                ):
                    inconclusive = True
                elif (
                    isinstance(bucket, str)
                    and isinstance(key, str)
                    and _BUCKET.fullmatch(bucket)
                    and _KEY.fullmatch(key)
                ):
                    bucket_name = _BUCKET.fullmatch(bucket).group(1)
                    modern_name = re.fullmatch(
                        r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket_name
                    )
                    legacy_location = bucket.startswith(
                        "arn:aws:s3:::"
                    ) and key.startswith("arn:aws:kms:us-east-1:")
                    if (
                        (modern_name or legacy_location)
                        and ".." not in bucket_name
                        and not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", bucket_name)
                    ):
                        passed = True
            if passed:
                yield self.passed(
                    region=region,
                    resource_id=resource_id,
                    actual_value=f"GuardDuty detector {detector_id} has a publishing S3 destination with bucket and KMS key ARNs",
                )
            elif describe_error is not None:
                yield self.error(
                    region=region,
                    resource_id=resource_id,
                    actual_value=f"{describe_error['Operation']} failed: {describe_error['Code']}: {describe_error['Message']}",
                    remediation=self._remediation_for(describe_error),
                )
            elif inconclusive:
                yield self.error(
                    region=region,
                    resource_id=resource_id,
                    actual_value="Could not determine the status or properties of all S3 publishing destinations",
                    remediation="Retry the scan and inspect the GuardDuty publishing destination responses and permissions.",
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=resource_id,
                    actual_value="No publishing S3 destination with valid bucket and KMS key ARNs",
                )
