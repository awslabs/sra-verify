"""Security Lake client wrapper."""

from typing import Dict, List, Optional, Any
import boto3
from botocore.exceptions import ClientError
from sraverify.core.logging import logger



class SecurityLakeClient:
    """Security Lake client wrapper."""

    def __init__(self, region: str, session: Optional[boto3.Session] = None):
        """Initialize Security Lake client.

        Args:
            session: boto3 session
            region: AWS region
        """
        
        self.region = region
        self.session = session or boto3.Session()
        self.client = self.session.client('securitylake', region_name=region)
        self.org_client = self.session.client('organizations', region_name=region)

    def _handle_api_error(self, e, operation_name, default_return=None):
        """
        Handle common API errors with consistent logging and return values.
        
        Args:
            e: The exception that was caught
            operation_name: Name of the operation being performed (for logging)
            default_return: Default value to return on error
            
        Returns:
            Error indicator dict for status checks, default_return for other operations
        """
        if isinstance(e, ClientError):
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = str(e)
            
            # Check for specific error types
            if "AccessDeniedException" in error_code:
                logger.debug(f"Access denied during {operation_name} in region {self.region}: {error_message}")
                return {"Error": {"Code": "ACCESS_DENIED", "Message": error_message}}
            elif "ResourceNotFoundException" in error_code:
                logger.debug(f"Resource not found during {operation_name} in region {self.region}: {error_message}")
                return {"Error": {"Code": "NOT_FOUND", "Message": error_message}}
            else:
                logger.debug(f"Error during {operation_name} in region {self.region}: {error_code} - {error_message}")
                return {"Error": {"Code": error_code, "Message": error_message}}
        else:
            error_message = str(e)
            logger.debug(f"Unexpected error during {operation_name} in region {self.region}: {error_message}")
            return {"Error": {"Code": "UNEXPECTED", "Message": error_message}}

    def is_security_lake_enabled(self):
        """
        Check if Security Lake is enabled in the region.
        
        Returns:
            True if Security Lake is enabled, False otherwise
        """
        try:
            response = self.client.list_data_lakes(regions=[self.region])
            data_lakes = response.get('dataLakes', [])
            return len(data_lakes) > 0
        except Exception as e:
            logger.debug(f"Error checking Security Lake status in {self.region}: {e}")
            return False

    def get_organization_configuration(self):
        """
        Get Security Lake organization configuration.
        
        Returns:
            Organization configuration or error indicator if there was an error
        """
        try:
            response = self.client.get_data_lake_organization_configuration()
            return response
        except self.client.exceptions.ResourceNotFoundException:
            logger.debug(f"No organization configuration found in region {self.region}")
            return {}
        except Exception as e:
            error_response = self._handle_api_error(e, "get_organization_configuration", {})
            # If it's an error dict, return empty dict for compatibility
            if isinstance(error_response, dict) and "Error" in error_response:
                logger.debug(f"Error getting organization configuration: {error_response}")
                return {}
            return error_response
   
    def list_data_lakes(self):
        """
        List Security Lake data lakes.
        
        Returns:
            List of data lakes or empty list if there was an error
        """
        try:
            response = self.client.list_data_lakes(regions=[self.region])
            return response.get("dataLakes", [])
        except self.client.exceptions.ResourceNotFoundException:
            logger.debug(f"No data lakes found in region {self.region}")
            return []
        except Exception as e:
            error_response = self._handle_api_error(e, "list_data_lakes", [])
            # If it's an error dict, return empty list for compatibility
            if isinstance(error_response, dict) and "Error" in error_response:
                logger.debug(f"Error listing data lakes: {error_response}")
                return []
            return error_response

    def list_log_sources(self):
        """
        List enabled log sources with pagination support.
        
        Returns:
            List of log sources or empty list if there was an error
        """
        try:
            response = self.client.list_log_sources()
            log_sources = response.get("sources", [])
            
            # Handle pagination
            while response.get('nextToken'):
                response = self.client.list_log_sources(nextToken=response['nextToken'])
                log_sources.extend(response.get("sources", []))
            
            return log_sources
        except self.client.exceptions.ResourceNotFoundException:
            logger.debug(f"No log sources found in region {self.region}")
            return []
        except Exception as e:
            error_response = self._handle_api_error(e, "list_log_sources", [])
            # If it's an error dict, return empty list for compatibility
            if isinstance(error_response, dict) and "Error" in error_response:
                logger.debug(f"Error listing log sources: {error_response}")
                return []
            return error_response

    def list_subscribers(self):
        """
        List Security Lake subscribers with pagination support.
        
        Returns:
            List of subscribers or empty list if there was an error
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
        except Exception as e:
            error_response = self._handle_api_error(e, "list_subscribers", [])
            # If it's an error dict, return empty list for compatibility
            if isinstance(error_response, dict) and "Error" in error_response:
                logger.debug(f"Error listing subscribers: {error_response}")
                return []
            return error_response

    def get_delegated_admin(self):
        """
        Get Security Lake delegated admin account.
        
        Returns:
            Delegated admin account info or None if not found/error
        """
        try:
            response = self.org_client.list_delegated_administrators(ServicePrincipal="securitylake.amazonaws.com")
            admins = response.get("DelegatedAdministrators", [])
            return admins[0] if admins else None
        except Exception as e:
            error_response = self._handle_api_error(e, "get_delegated_admin", None)
            if isinstance(error_response, dict) and "Error" in error_response:
                return None
            return error_response

    def list_delegated_administrators(self, service_principal: str = "securitylake.amazonaws.com") -> List[Dict[str, Any]]:
        """
        List delegated administrators for SecurityLake.
        
        Args:
            service_principal: Service principal to check for delegated administrators
            
        Returns:
            List of delegated administrators or empty list if there was an error
        """
        try:
            logger.debug(f"Listing delegated administrators for {service_principal} in {self.region}")
            response = self.org_client.list_delegated_administrators(ServicePrincipal=service_principal)
            delegated_admins = response.get('DelegatedAdministrators', [])
            
            # Handle pagination
            while response.get('NextToken'):
                response = self.org_client.list_delegated_administrators(
                    ServicePrincipal=service_principal,
                    NextToken=response['NextToken']
                )
                delegated_admins.extend(response.get('DelegatedAdministrators', []))
                
            logger.debug(f"Found {len(delegated_admins)} delegated administrators for {service_principal}")
            for admin in delegated_admins:
                logger.debug(f"Delegated admin: {admin.get('Id')} - {admin.get('Name')}")
            return delegated_admins
        except Exception as e:
            error_response = self._handle_api_error(e, f"list_delegated_administrators({service_principal})", [])
            # If it's an error dict, return empty list for compatibility
            if isinstance(error_response, dict) and "Error" in error_response:
                logger.debug(f"Error listing delegated administrators: {error_response}")
                return []
            return error_response

    def get_sqs_queue_encryption(self, queue_url):
        """
        Get SQS queue encryption settings.
        
        Args:
            queue_url: URL of the SQS queue
            
        Returns:
            KMS key ID used for encryption or None if not encrypted/error
        """
        sqs = self.session.client("sqs", region_name=self.region)
        try:
            response = sqs.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=["KmsMasterKeyId"]
            )
            return response.get("Attributes", {}).get("KmsMasterKeyId")
        except Exception as e:
            error_response = self._handle_api_error(e, f"get_sqs_queue_encryption({queue_url})", None)
            if isinstance(error_response, dict) and "Error" in error_response:
                return None
            return error_response
            
    def list_organization_accounts(self) -> List[Dict[str, Any]]:
        """
        List all accounts in the organization.
        
        Returns:
            List of organization accounts or empty list if there was an error
        """
        try:
            logger.debug(f"Listing organization accounts in {self.region}")
            response = self.org_client.list_accounts()
            accounts = response.get('Accounts', [])
            
            # Handle pagination
            while response.get('NextToken'):
                response = self.org_client.list_accounts(NextToken=response['NextToken'])
                accounts.extend(response.get('Accounts', []))
                
            logger.debug(f"Found {len(accounts)} organization accounts")
            return accounts
        except Exception as e:
            error_response = self._handle_api_error(e, "list_organization_accounts", [])
            # If it's an error dict, return empty list for compatibility
            if isinstance(error_response, dict) and "Error" in error_response:
                logger.debug(f"Error listing organization accounts: {error_response}")
                return []
            return error_response
