from collections.abc import Iterable, Mapping

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.cloudtrail.base import CloudTrailCheck


class SRA_CLOUDTRAIL_16(CloudTrailCheck):
    meta = CheckMeta(
        check_id="SRA-CLOUDTRAIL-16",
        title="Organization trail log bucket has default Object Lock retention",
        description="Checks fixed default Object Lock retention for new objects in visible organization trail destinations owned by the scanned Log Archive account.",
        check_logic="Discover organization trails in each scan Region, match destinations to owned buckets, and inspect default retention in each bucket's Region.",
        severity=Severity.HIGH,
        account_type=AccountType.LOG_ARCHIVE,
        service="CloudTrail",
        resource_type="AWS::S3::Bucket",
        remediation=Remediation(
            text="Configure default Object Lock retention on the log bucket."
        ),
        sra_sections=("Log Archive account", "AWS CloudTrail"),
        additional_urls=(
            "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectLockConfiguration.html",
        ),
    )

    def _response_error(
        self, response: object, fallback: str, region: str, resource_id: str
    ) -> Finding:
        error = response.get("Error") if isinstance(response, Mapping) else None
        if isinstance(error, Mapping):
            actual = (
                f"{error.get('Operation')} failed: {error.get('Code')}: "
                f"{error.get('Message')}"
            )
            remediation = self._remediation_for(error)
        else:
            actual = fallback
            remediation = "Verify access and retry the scan"
        return self.error(
            remediation=remediation,
            region=region,
            resource_id=resource_id,
            actual_value=actual,
        )

    def execute(self) -> Iterable[Finding]:
        account = self.account_id
        destinations = set()
        for region in self.regions:
            response = self.describe_trails(region=region)
            resource = f"cloudtrail:{region}:{account}"
            if (
                not isinstance(response, Mapping)
                or "Error" in response
                or not isinstance(response.get("trailList"), list)
            ):
                yield self._response_error(
                    response, "Malformed trail response", region, resource
                )
                continue
            for trail in response["trailList"]:
                if not isinstance(trail, Mapping):
                    yield self._response_error(
                        None, "Malformed trail record", region, resource
                    )
                    continue
                classification = trail.get("IsOrganizationTrail")
                if classification is False:
                    continue
                if classification is not True:
                    yield self._response_error(
                        None,
                        "Organization trail classification is missing or invalid",
                        region,
                        resource,
                    )
                    continue
                name = trail.get("S3BucketName")
                if not isinstance(name, str) or not name.strip():
                    yield self._response_error(
                        None,
                        "Organization trail has no destination bucket name",
                        region,
                        resource,
                    )
                    continue
                destinations.add(name)
        if not destinations:
            return
        inventory = self._list_owned_buckets()
        if (
            not isinstance(inventory, Mapping)
            or "Error" in inventory
            or not isinstance(inventory.get("Buckets"), list)
        ):
            yield self._response_error(
                inventory, "Malformed bucket inventory", "global", f"s3:{account}"
            )
            return
        seen = set()
        for bucket in inventory["Buckets"]:
            if (
                not isinstance(bucket, Mapping)
                or not isinstance(bucket.get("Name"), str)
                or not bucket["Name"].strip()
            ):
                yield self._response_error(
                    None, "Malformed bucket inventory record", "global", f"s3:{account}"
                )
                continue
            name = bucket["Name"]
            if name not in destinations or name in seen:
                continue
            seen.add(name)
            region = bucket.get("BucketRegion")
            if not isinstance(region, str) or not region.strip():
                yield self._response_error(
                    None, "Bucket Region is missing", "global", name
                )
                continue
            response = self._get_object_lock_configuration(region, name)
            if not isinstance(response, Mapping):
                yield self._response_error(
                    None, "Malformed Object Lock response", region, name
                )
                continue
            if "Error" in response:
                err = response["Error"]
                if isinstance(err, Mapping) and self.is_not_configured(err):
                    yield self.failed(
                        region=region,
                        resource_id=name,
                        actual_value=f"{err.get('Operation')} failed: {err.get('Code')}: {err.get('Message')}",
                    )
                else:
                    yield self._response_error(
                        response, "Malformed Object Lock error", region, name
                    )
                continue
            config = response.get("ObjectLockConfiguration")
            if (
                not isinstance(config, Mapping)
                or config.get("ObjectLockEnabled") != "Enabled"
            ):
                yield self._response_error(
                    None, "Malformed Object Lock configuration", region, name
                )
                continue
            rule = config.get("Rule")
            if (
                rule is None
                or isinstance(rule, Mapping)
                and "DefaultRetention" not in rule
            ):
                yield self.failed(
                    region=region,
                    resource_id=name,
                    actual_value="No fixed default retention configured",
                )
                continue
            retention = (
                rule.get("DefaultRetention") if isinstance(rule, Mapping) else None
            )
            if not isinstance(retention, Mapping):
                yield self._response_error(
                    None, "Malformed default retention", region, name
                )
                continue
            durations = [retention[k] for k in ("Days", "Years") if k in retention]
            if (
                retention.get("Mode") not in ("GOVERNANCE", "COMPLIANCE")
                or len(durations) != 1
                or type(durations[0]) is not int
                or durations[0] <= 0
            ):
                yield self._response_error(
                    None, "Invalid default retention", region, name
                )
                continue
            yield self.passed(
                region=region,
                resource_id=name,
                actual_value=f"Fixed default retention configured: {dict(retention)}",
            )
