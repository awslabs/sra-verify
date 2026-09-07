"""Security Lake client for interacting with AWS Security Lake service."""

from typing import Dict, List, Any
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)
from sraverify.core.logging import logger
from sraverify.core.scan_context import ScanContext


class SecurityLakeClient:
    """Client for interacting with AWS Security Lake service."""

    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize Security Lake client.

        Args:
            region: AWS region name
            ctx: The per-scan ``ScanContext`` that owns the boto3 session,
                ``Client_Config``, and per-scan boto3 client cache. Underlying
                boto3 clients are obtained via ``ctx.get_client(...)`` so the
                bounded timeouts and retry policy are applied and the same
                client instance is reused across all wrappers in this scan.
        """
        self.region = region
        self.ctx = ctx
        self.client = ctx.get_client('securitylake', region=region)
        self.org_client = ctx.get_client('organizations', region=region)

    def _log_aws_failure(self, operation: str, e: Exception) -> None:
        """Classify a botocore exception and log it at the right severity.

        Centralizes the "is this an opt-in / unreachable region (debug),
        a missing IAM permission (warning), or a real service issue (error)"
        decision so every Security Lake API call site uses the same
        contract:

        * ``EndpointConnectionError`` / ``ConnectTimeoutError`` /
          ``ReadTimeoutError`` / other ``BotoCoreError`` — the Security
          Lake endpoint isn't reachable in this region (commonly an
          opt-in region where Security Lake is unavailable, or a
          transient network issue). Logged at debug.
        * ``ClientError`` with ``UnauthorizedException`` — Security Lake
          isn't enabled in this region/account. Routine for a
          multi-region sweep, logged at debug.
        * ``ClientError`` with ``AccessDeniedException`` — the calling
          IAM principal is genuinely missing a Security Lake permission.
          A security verification tool silently returning empty here
          would produce false negatives, so this is logged at warning
          to surface the misconfiguration to the operator.
        * Any other ``ClientError`` — throttling, validation errors,
          service issues. Logged at error.
        * Any other ``Exception`` (defensive fallback) — logged at
          error.

        The caller is responsible for returning whatever empty value
        (``[]``, ``{}``, ``None``, ``False``) is appropriate for the
        method.
        """
        if isinstance(e, (EndpointConnectionError, ConnectTimeoutError, ReadTimeoutError)):
            logger.debug(
                f"Security Lake endpoint unreachable in {self.region} during {operation}: {e}"
            )
        elif isinstance(e, ClientError):
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'UnauthorizedException':
                logger.debug(
                    f"Security Lake not enabled in {self.region} ({operation}): {e}"
                )
            elif error_code == 'AccessDeniedException':
                logger.warning(
                    f"Access denied during {operation} in {self.region} "
                    f"(scan results for SecurityLake checks in this region "
                    f"will be incomplete): {e}"
                )
            else:
                logger.error(f"Error during {operation} in {self.region}: {e}")
        elif isinstance(e, BotoCoreError):
            logger.debug(
                f"Botocore error during {operation} in {self.region}: {e}"
            )
        else:
            logger.error(f"Unexpected error during {operation} in {self.region}: {e}")

    def is_security_lake_enabled(self):
        """
        Check if Security Lake is enabled in the region.

        Returns:
            True if enabled, False otherwise
        """
        try:
            response = self.client.list_data_lakes(regions=[self.region])
            data_lakes = response.get('dataLakes', [])
            return len(data_lakes) > 0
        except (BotoCoreError, ClientError) as e:
            self._log_aws_failure("checking Security Lake status", e)
            return False

    def get_organization_configuration(self):
        """
        Get Security Lake organization configuration.

        Returns:
            Organization configuration or empty dict if error
        """
        try:
            response = self.client.get_data_lake_organization_configuration()
            return response
        except self.client.exceptions.ResourceNotFoundException:
            logger.debug(f"No organization configuration found in region {self.region}")
            return {}
        except (BotoCoreError, ClientError) as e:
            self._log_aws_failure("getting organization configuration", e)
            return {}

    def list_data_lakes(self):
        """
        List Security Lake data lakes.

        Returns:
            List of data lakes or empty list if error
        """
        try:
            response = self.client.list_data_lakes(regions=[self.region])
            return response.get("dataLakes", [])
        except self.client.exceptions.ResourceNotFoundException:
            logger.debug(f"No data lakes found in region {self.region}")
            return []
        except (BotoCoreError, ClientError) as e:
            self._log_aws_failure("listing data lakes", e)
            return []

    def list_log_sources(self, regions=None, accounts=None):
        """
        List enabled log sources with pagination support.

        Args:
            regions: List of regions to filter (optional)
            accounts: List of account IDs to filter (optional)

        Returns:
            List of log sources or empty list if error
        """
        try:
            params = {}
            if regions:
                params['regions'] = regions
            if accounts:
                params['accounts'] = accounts

            response = self.client.list_log_sources(**params)
            log_sources = response.get("sources", [])

            # Handle pagination
            while response.get('nextToken'):
                params['nextToken'] = response['nextToken']
                response = self.client.list_log_sources(**params)
                log_sources.extend(response.get("sources", []))

            return log_sources
        except self.client.exceptions.ResourceNotFoundException:
            logger.debug(f"No log sources found in region {self.region}")
            return []
        except (BotoCoreError, ClientError) as e:
            self._log_aws_failure("listing log sources", e)
            return []

    def list_subscribers(self):
        """
        List Security Lake subscribers with pagination support.

        Returns:
            List of subscribers or empty list if error
        """
        try:
            response = self.client.list_subscribers()
            subscribers = response.get("subscribers", [])

            # Handle pagination
            while response.get('nextToken'):
                response = self.client.list_subscribers(nextToken=response['nextToken'])
                subscribers.extend(response.get("subscribers", []))

            return subscribers
        except self.client.exceptions.ResourceNotFoundException:
            logger.debug(f"No subscribers found in region {self.region}")
            return []
        except (BotoCoreError, ClientError) as e:
            self._log_aws_failure("listing subscribers", e)
            return []

    def get_delegated_admin(self):
        """
        Get Security Lake delegated admin account.

        Returns:
            Delegated admin info or None if error
        """
        try:
            response = self.org_client.list_delegated_administrators(ServicePrincipal="securitylake.amazonaws.com")
            admins = response.get("DelegatedAdministrators", [])
            return admins[0] if admins else None
        except ClientError as e:
            logger.error(f"Error getting delegated admin: {e}")
            return None

    def list_delegated_administrators(self, service_principal: str = "securitylake.amazonaws.com") -> List[Dict[str, Any]]:
        """
        List delegated administrators for SecurityLake.

        Args:
            service_principal: Service principal to check for delegated administrators

        Returns:
            List of delegated administrators or empty list if error
        """
        try:
            response = self.org_client.list_delegated_administrators(ServicePrincipal=service_principal)
            delegated_admins = response.get("DelegatedAdministrators", [])

            logger.debug(f"Found {len(delegated_admins)} delegated administrators for {service_principal}")
            for admin in delegated_admins:
                logger.debug(f"Delegated admin: {admin.get('Id')} - {admin.get('Name')}")
            return delegated_admins
        except ClientError as e:
            logger.error(f"Error listing delegated administrators for {service_principal}: {e}")
            return []

    def get_sqs_queue_encryption(self, queue_url):
        """
        Get SQS queue encryption settings.

        Args:
            queue_url: SQS queue URL

        Returns:
            KMS key ID or None if error
        """
        try:
            sqs = self.ctx.get_client('sqs', region=self.region)
            response = sqs.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=["KmsMasterKeyId"]
            )
            return response.get("Attributes", {}).get("KmsMasterKeyId")
        except (BotoCoreError, ClientError) as e:
            self._log_aws_failure(f"getting SQS queue encryption for {queue_url}", e)
            return None

    def list_organization_accounts(self) -> List[Dict[str, Any]]:
        """
        List all accounts in the organization.

        Returns:
            List of organization accounts or empty list if error
        """
        try:
            response = self.org_client.list_accounts()
            accounts = response.get('Accounts', [])

            # Handle pagination
            while response.get('NextToken'):
                response = self.org_client.list_accounts(NextToken=response['NextToken'])
                accounts.extend(response.get('Accounts', []))

            logger.debug(f"Found {len(accounts)} organization accounts")
            return accounts
        except ClientError as e:
            logger.error(f"Error listing organization accounts: {e}")
            return []

    def get_data_lake_sources(self, account_id: str = None):
        """
        Get data lake sources for a specific account.

        Args:
            account_id: AWS account ID string to check sources for

        Returns:
            List of data lake sources or empty list if error
        """
        try:
            request_body = {}
            if account_id:
                # Ensure account_id is a string (extract ID if it's a dict like SecurityHub pattern)
                if isinstance(account_id, dict):
                    if 'Id' in account_id:
                        account_id = account_id['Id']
                    else:
                        logger.error(f"Cannot extract account ID from dict: {account_id}")
                        return []

                request_body["accounts"] = [account_id]

            response = self.client.get_data_lake_sources(**request_body)
            return response.get("dataLakeSources", [])
        except self.client.exceptions.ResourceNotFoundException:
            logger.debug(f"No data lake sources found in region {self.region}")
            return []
        except (BotoCoreError, ClientError) as e:
            self._log_aws_failure("getting data lake sources", e)
            return []
