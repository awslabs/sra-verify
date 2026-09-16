"""
Offline regional availability from botocore's bundled endpoint data.

No AWS call, no credentials. Lifted from ``WAFCheck.region_supports_service``
and given two things it lacked: a process-lifetime cache, and an explicit rule
for services whose regional endpoint list is empty.

Why this exists at all: a Region with no endpoint for a service and a Region
behind a broken network raise the *same* exception, so a check cannot infer the
first from a transport failure (Requirement 5.6). Asking the bundled endpoint
data before issuing the call is the only way to tell them apart, and it costs
nothing -- the data ships with botocore and the answer cannot change while the
process runs.

Measured against botocore 1.43.6's ``aws`` partition (34 Regions), the services
this scanner consults with uneven coverage are ``apprunner`` (11), ``auditmanager``
(12), ``securitylake`` (17), ``amplify`` (20), ``macie2`` (22), ``appsync`` (31),
and ``inspector2`` (32). ``accessanalyzer`` is 34/34, so the lookup would never
suppress a row for it -- which is why the Access Analyzer live probe is deleted
outright rather than replaced by a call to this function.
"""
from __future__ import annotations

from functools import lru_cache

import boto3

from sraverify.core.logging import logger


@lru_cache(maxsize=None)
def service_available_in_region(service_id: str, region: str) -> bool:
    """
    Return ``True`` unless botocore positively says ``service_id`` has no
    endpoint in ``region``.

    **Every uncertain outcome is** ``True``. The asymmetry is deliberate and it
    decides every edge case the same way: a false "available" costs one honest
    ERROR row for one Region, while a false "unavailable" suppresses a Region
    silently and could hide a real finding forever. So the only path that
    returns ``False`` is a recognized service with a non-empty regional list for
    the right partition that does not contain the Region.

    Three uncertain outcomes, each handled explicitly:

    * **Unknown service id** -> ``True`` and a ``warning``.
      ``get_available_regions`` answers ``[]`` for a name botocore has never
      heard of rather than raising, so a typo would otherwise read as
      "supported nowhere" and silently disable the calling check in every
      Region with no diagnostic at all.
    * **Empty regional list for a recognized service** -> ``True``, no warning.
      An empty list means "not resolvable per Region", never "reachable from
      nowhere". Two quite different inputs produce it and they cannot be told
      apart: ``shield``, ``account``, ``organizations``, ``iam``, and
      ``cloudfront`` are non-regionalized and declare only a partition endpoint
      (``aws-global``), while botocore 1.43.6 ships no endpoint data for
      ``security-ir`` at all. Reading either as "absent" would suppress every
      Shield row in the catalog. This is the one input on which a fail-closed
      reading would be wrong for every Region at once.
    * **Any exception** -> ``True`` and a ``debug``. Includes an unparseable
      Region name, which ``get_partition_for_region`` raises on.

    The partition is derived from ``region`` rather than defaulting to ``aws``,
    so a GovCloud or China scan is not measured against the commercial Region
    list.

    There is **no session parameter**. The endpoint data is process-global and
    shipped with botocore, so the answer cannot depend on which session asks; a
    parameter the implementation ignored would tell a reader otherwise. A fresh
    credential-free ``boto3.Session()`` is built inside the cached call and
    discarded, so nothing here holds a reference to the scan's session -- which
    also keeps this function usable from a check whose context has already been
    torn down.

    Cached for the life of the process on ``(service_id, region)``: a
    full-organization scan asks the same question once per check per Region, and
    the bundled data cannot change under it.

    Args:
        service_id: boto3/botocore service id, e.g. ``"apprunner"``. Passed as a
            string literal at every call site so the set of checks relying on
            Region suppression stays greppable (Requirement 5.7).
        region: AWS Region name.

    Returns:
        ``False`` only on a positive, partition-correct absence. ``True``
        otherwise, including every uncertain case.
    """
    try:
        # Credential-free: only bundled endpoint data is read, and Session()
        # does not touch the network or resolve credentials to answer these
        # three questions. Constructed inside the try because a broken botocore
        # install would raise here, and criterion 4 has to hold for the whole
        # function rather than for part of it.
        session = boto3.Session()

        if service_id not in session.get_available_services():
            logger.warning(
                f"availability: {service_id!r} is not a known boto3 service id; "
                f"treating it as available in {region} rather than suppressing "
                f"the Region"
            )
            return True

        partition = session.get_partition_for_region(region)
        regional = session.get_available_regions(
            service_id, partition_name=partition
        )

        if not regional:
            # Non-regionalized, or no endpoint data at all. Either way the
            # per-Region question has no answer, and "no answer" is not "no".
            return True

        return region in regional
    except Exception as e:  # noqa: BLE001 -- fail open, deliberately
        logger.debug(
            f"availability: could not determine {service_id} in {region} "
            f"({type(e).__name__}: {e}); treating it as available"
        )
        return True
