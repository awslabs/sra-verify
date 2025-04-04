"""
IAM Access Analyzer client for interacting with AWS IAM Access Analyzer service.
"""
from typing import Dict, List, Optional, Any
import boto3
from botocore.exceptions import ClientError, EndpointConnectionError
from sraverify.core.logging import logger


class AccessAnalyzerClient:
    """Client for interacting with AWS IAM Access Analyzer service."""
    
    def __init__(self, region: str, session: Optional[boto3.Session] = None):
        """
        Initialize IAM Access Analyzer client for a specific region.
        
        Args:
            region: AWS region name
            session: AWS session to use (if None, a new session will be created)
        """
        self.region = region
        self.session = session or boto3.Session()
        self.client = self.session.client('accessanalyzer', region_name=region)
        self.org_client = self.session.client('organizations', region_name=region)
        logger.debug(f"Initialized AccessAnalyzerClient for region {region}")
    
    def is_access_analyzer_available(self) -> bool:
        """Check if Access Analyzer is available in the region."""
        try:
            logger.debug(f"Checking if Access Analyzer is available in {self.region}")
            self.client.list_analyzers(maxResults=1)
            logger.debug(f"Access Analyzer is available in {self.region}")
            return True
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'AccessDeniedException':
                # If we get an access denied, the service exists but we don't have permissions
                logger.debug(f"Access Analyzer exists in {self.region} but access is denied")
                return True
            logger.debug(f"Access Analyzer not available in {self.region}: {error_code}")
            return False
        except EndpointConnectionError:
            # Service not available in this region
            logger.debug(f"Access Analyzer endpoint not available in {self.region}")
            return False
        except Exception as e:
            # Any other error, assume service is not available
            logger.debug(f"Error checking Access Analyzer availability in {self.region}: {str(e)}")
            return False
    
    def list_analyzers(self) -> List[Dict[str, Any]]:
        """
        List all analyzers in the region.
        
        Returns:
            List of analyzer details
        """
        try:
            analyzers = []
            paginator = self.client.get_paginator('list_analyzers')
            
            logger.debug(f"Listing analyzers in {self.region}")
            for page in paginator.paginate():
                analyzers.extend(page.get('analyzers', []))
            
            logger.debug(f"Found {len(analyzers)} analyzers in {self.region}")
            return analyzers
        except ClientError as e:
            logger.warning(f"Error listing analyzers in {self.region}: {e}")
            return []
        except Exception as e:
            logger.warning(f"Unexpected error listing analyzers in {self.region}: {e}")
            return []
    
    def get_analyzer_details(self, analyzer_arn: str) -> Dict[str, Any]:
        """
        Get details for a specific analyzer.
        
        Args:
            analyzer_arn: ARN of the analyzer
            
        Returns:
            Analyzer details
        """
        try:
            logger.debug(f"Getting details for analyzer {analyzer_arn}")
            response = self.client.get_analyzer(analyzerArn=analyzer_arn)
            return response
        except ClientError as e:
            logger.warning(f"Error getting analyzer details for {analyzer_arn}: {e}")
            return {}
        except Exception as e:
            logger.warning(f"Unexpected error getting analyzer details for {analyzer_arn}: {e}")
            return {}
    
    def get_delegated_admin(self) -> Dict[str, Any]:
        """
        Get the delegated administrator for IAM Access Analyzer.
        
        Returns:
            Dictionary containing delegated administrator details or empty dict if none
        """
        try:
            logger.debug("Getting delegated administrator for IAM Access Analyzer")
            response = self.org_client.list_delegated_administrators(ServicePrincipal='access-analyzer.amazonaws.com')
            delegated_admins = response.get('DelegatedAdministrators', [])
            
            if delegated_admins:
                logger.debug(f"Found delegated administrator for IAM Access Analyzer: {delegated_admins[0].get('Id')}")
                return delegated_admins[0]
            else:
                logger.debug("No delegated administrator found for IAM Access Analyzer")
                return {}
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'AWSOrganizationsNotInUseException':
                logger.debug("AWS Organizations not in use")
            else:
                logger.warning(f"Error getting delegated administrator: {e}")
            return {}
        except Exception as e:
            logger.warning(f"Unexpected error getting delegated administrator: {e}")
            return {}
