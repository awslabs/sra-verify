"""
Base class for GuardDuty security checks.

Per-scan cached AWS responses live on the attached :class:`ScanContext` under the
``"guardduty"`` namespace. Every accessor returns the client's response dict unchanged,
or an error result, and none caches a failure.

Every accessor follows one shape -- cache hit, no-client result, call, error
guard, store, return -- and none of them extracts. A check receives the client's
response dict and reads its keys after testing for ``"Error"``.

:meth:`detector_id_of` is a pure helper over a success dict, which is what keeps
its ``None`` unambiguous: it can only mean "GuardDuty is not enabled in this
Region", because a failure could not have reached it.
"""
from typing import Any, ClassVar, List, Mapping, Optional

from sraverify.core.aws_errors import (
    NotConfigured,
    NotConfiguredTable,
    is_error,
    no_client_result,
)
from sraverify.core.check import SecurityCheck
from sraverify.core.logging import logger
from sraverify.services.guardduty.client import GuardDutyClient


class GuardDutyCheck(SecurityCheck):
    """Base class for all GuardDuty security checks."""

    # All cached AWS-API responses for GuardDuty are stored under this
    # namespace on the per-scan ``ScanContext``. Cache keys are simple
    # service-internal strings (e.g., ``"detector_id:us-east-1"``) since the
    # ``ScanContext`` itself is per-scan and per-session, so there is no
    # need to disambiguate by session region anymore.
    NAMESPACE = "guardduty"

    #: The (operation, code) pairs that mean "the control is not configured" for
    #: GuardDuty.
    #:
    #: One entry, and it is the pair that motivated keying this table by
    #: operation in the first place. ``BadRequestException`` is returned by two
    #: GuardDuty operations with two different meanings:
    #:
    #: * from ``DescribeOrganizationConfiguration`` it means no delegated
    #:   administrator has been enabled -- the control is genuinely absent, so a
    #:   FAIL is correct;
    #: * from ``ListOrganizationAdminAccounts`` it means "not the master account"
    #:   -- the scan is being run from the wrong place, which is an ERROR and is
    #:   deliberately **not** declared here. ``SRA-GUARDDUTY-14`` keeps its own
    #:   remediation for that case.
    #:
    #: A table keyed by code alone would have to pick one meaning and be wrong
    #: about the other.
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {
        "DescribeOrganizationConfiguration": {
            "BadRequestException": NotConfigured(
                evidence=(
                    "https://docs.aws.amazon.com/guardduty/latest/APIReference/"
                    "API_DescribeOrganizationConfiguration.html -- BadRequestException "
                    "is returned when the request is rejected because it is not "
                    "valid for the account's state; observed in the 2026-09-12 "
                    "CodeBuild log (build 82c0c298, us-west-1) as 'The request "
                    "failed because a delegated administrator account has not "
                    "been enabled.'"
                ),
            ),
        },
    }

    def _setup_clients(self):
        """Set up GuardDuty clients for each region.

        The underlying boto3 clients held by :class:`GuardDutyClient` are
        obtained from ``self._ctx.get_client(...)`` so they share the
        per-scan bounded ``Client_Config`` and the ``(service, region)``
        client cache.
        """
        # Clear existing clients
        self._clients.clear()
        # Set up new clients only if regions are initialized
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = GuardDutyClient(region, ctx=self._ctx)

    @staticmethod
    def detector_id_of(response: Mapping[str, Any]) -> Optional[str]:
        """
        Read the detector ID out of a successful ``ListDetectors`` response.

        A pure helper over a **success dict**, never over an accessor's raw
        return: handing it an error result would re-introduce a function that has
        to cope with both shapes. Call it only after ``"Error" in response`` is
        False.

        Args:
            response: A successful ``get_detector_id`` response.

        Returns:
            The first detector ID, or ``None`` when the Region has none. Here
            ``None`` means exactly one thing -- GuardDuty is not enabled in this
            Region -- because a failure could not have reached this far.
        """
        detector_ids = response.get("DetectorIds", [])
        return detector_ids[0] if detector_ids else None

    def get_detector_id(self, region: str) -> Mapping[str, Any]:
        """
        Get the ``ListDetectors`` response for a Region, with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"DetectorIds": [...]}`` on success, or an error result. Use
            :meth:`detector_id_of` to read the ID after testing for ``"Error"``.
        """
        cache_key = f"detector_id:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"GuardDuty: Using cached detector ID for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if client is None:
            logger.warning(
                f"GuardDuty: No GuardDuty client available for region {region}"
            )
            return no_client_result(service="GuardDuty", region=region)

        logger.debug(f"GuardDuty: Fetching detector ID for {region}")
        result = client.get_detector_id()

        if is_error(result):
            # Never cached: a retry has to be able to re-issue the call. This is
            # the line that stops one denied ListDetectors from being replayed to
            # every later GuardDuty check in the Region.
            return result

        self._ctx._set(self.NAMESPACE, cache_key, result)
        return result

    def get_detector_details(self, region: str) -> Mapping[str, Any]:
        """
        Get detector details for a specific region.

        Args:
            region: AWS region name

        Returns:
            The ``GetDetector`` response on success, or an error result.

            When the detector lookup itself fails, **that** error result is
            returned unchanged rather than one describing ``GetDetector``: the
            check should report the operation that actually failed.
        """
        cache_key = f"detector_details:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"GuardDuty: Using cached detector details for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        detectors = self.get_detector_id(region)
        if is_error(detectors):
            return detectors

        detector_id = self.detector_id_of(detectors)
        if not detector_id:
            # A real answer: AWS says there is no detector here. Returned as an
            # empty success dict rather than an error result, because nothing failed --
            # the caller distinguishes it with `detector_id_of`.
            logger.debug(f"GuardDuty: No detector ID found for region {region}")
            return {}

        client = self.get_client(region)
        if client is None:
            logger.warning(
                f"GuardDuty: No GuardDuty client available for region {region}"
            )
            return no_client_result(service="GuardDuty", region=region)

        logger.debug(
            f"GuardDuty: Getting detector details for {detector_id} in {region}"
        )
        result = client.get_detector_details(detector_id)

        if is_error(result):
            return result

        self._ctx._set(self.NAMESPACE, cache_key, result)
        return result

    def get_organization_configuration(self, region: str) -> Mapping[str, Any]:
        """
        Get organization configuration for a specific region.

        Args:
            region: AWS region name

        Returns:
            The ``DescribeOrganizationConfiguration`` response on success, or an
            error result -- including the detector lookup's own error result when
            that is what failed.
        """
        cache_key = f"org_config:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(
                f"GuardDuty: Using cached organization configuration for {region}"
            )
            return self._ctx._get(self.NAMESPACE, cache_key)

        detectors = self.get_detector_id(region)
        if is_error(detectors):
            return detectors

        detector_id = self.detector_id_of(detectors)
        if not detector_id:
            logger.debug(f"GuardDuty: No detector ID found for region {region}")
            return {}

        client = self.get_client(region)
        if client is None:
            logger.warning(
                f"GuardDuty: No GuardDuty client available for region {region}"
            )
            return no_client_result(service="GuardDuty", region=region)

        logger.debug(
            f"GuardDuty: Getting organization configuration for {detector_id} "
            f"in {region}"
        )
        result = client.describe_organization_configuration(detector_id)

        if is_error(result):
            return result

        self._ctx._set(self.NAMESPACE, cache_key, result)
        return result

    def list_organization_admin_accounts(self, region: str) -> Mapping[str, Any]:
        """
        List organization admin accounts for GuardDuty.

        Args:
            region: AWS region name

        Returns:
            The ``ListOrganizationAdminAccounts`` response on success, or an error
            error result.
        """
        cache_key = f"admin_accounts:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(
                f"GuardDuty: Using cached organization admin accounts for {region}"
            )
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if client is None:
            logger.warning(
                f"GuardDuty: No GuardDuty client available for region {region}"
            )
            return no_client_result(service="GuardDuty", region=region)

        logger.debug(f"GuardDuty: Listing organization admin accounts in {region}")
        result = client.list_organization_admin_accounts()

        if is_error(result):
            return result

        self._ctx._set(self.NAMESPACE, cache_key, result)
        return result

    def get_enabled_regions(self) -> List[str]:
        """
        Get list of regions where GuardDuty is enabled.

        Returns:
            List of region names where GuardDuty is enabled. A Region whose
            detector lookup **failed** is not included -- the scanner does not
            know whether GuardDuty is enabled there, and guessing either way
            would be worse than omitting it. The failure is reported by whichever
            check consumed the error result.
        """
        enabled_regions: List[str] = []
        for region in self.regions:
            result = self.get_detector_id(region)
            if is_error(result):
                continue
            if self.detector_id_of(result):
                enabled_regions.append(region)
        return enabled_regions
