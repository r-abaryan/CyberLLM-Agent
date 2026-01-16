"""
Microsoft Sentinel Connector
Azure Sentinel SIEM integration via REST API
"""

import requests
import json
from typing import List, Dict, Optional, Any
from datetime import datetime

from ..utils.logger import get_logger
from ..utils.exceptions import ConnectionError, APIError, AuthenticationError
from ..utils.retry import retry_with_backoff

logger = get_logger(__name__)


class SentinelConnector:
    """
    Connect to Microsoft Sentinel for threat assessment integration.
    
    Features:
    - Fetch incidents
    - Update incident status/comments
    - Create threat indicators
    - Query logs via KQL
    """
    
    def __init__(
        self,
        workspace_id: str,
        subscription_id: str,
        resource_group: str,
        tenant_id: str,
        client_id: str,
        client_secret: str
    ):
        """
        Initialize Sentinel connector.
        
        Args:
            workspace_id: Log Analytics workspace ID
            subscription_id: Azure subscription ID
            resource_group: Resource group name
            tenant_id: Azure AD tenant ID
            client_id: Service principal client ID
            client_secret: Service principal secret
        
        Raises:
            ValueError: If required parameters are missing
        """
        # Validate required parameters
        required_params = {
            "workspace_id": workspace_id,
            "subscription_id": subscription_id,
            "resource_group": resource_group,
            "tenant_id": tenant_id,
            "client_id": client_id,
            "client_secret": client_secret
        }
        
        missing = [k for k, v in required_params.items() if not v]
        if missing:
            raise ValueError(f"Missing required Sentinel parameters: {', '.join(missing)}")
        
        self.workspace_id = workspace_id
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        
        self.base_url = (
            f"https://management.azure.com/subscriptions/{subscription_id}/"
            f"resourceGroups/{resource_group}/providers/"
            f"Microsoft.OperationalInsights/workspaces/{workspace_id}"
        )
        
        self.access_token = None
        logger.debug("Sentinel connector initialized")
    
    @retry_with_backoff(max_retries=2, initial_delay=1.0)
    def _get_access_token(self) -> bool:
        """
        Authenticate and get Azure AD access token.
        
        Returns:
            True if authentication successful
        
        Raises:
            AuthenticationError: If authentication fails
        """
        try:
            logger.debug("Authenticating with Azure AD")
            token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
            
            data = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "https://management.azure.com/.default"
            }
            
            response = requests.post(token_url, data=data, timeout=30)
            
            if response.status_code == 200:
                self.access_token = response.json().get("access_token")
                logger.info("Successfully authenticated with Azure AD")
                return True
            
            error_msg = f"Azure AD authentication failed: {response.text}"
            logger.error(error_msg)
            raise AuthenticationError(error_msg)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error during authentication: {str(e)}")
            raise ConnectionError(f"Failed to connect to Azure AD: {str(e)}") from e
        except AuthenticationError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error during authentication: {str(e)}", exc_info=True)
            raise AuthenticationError(f"Authentication error: {str(e)}") from e
    
    def _get_headers(self) -> Dict[str, str]:
        """Get authorization headers"""
        if not self.access_token:
            self._get_access_token()
        
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
    
    def test_connection(self) -> bool:
        """
        Test connectivity to Sentinel.
        
        Returns:
            True if connection successful
        
        Raises:
            ConnectionError: If connection fails
        """
        try:
            if not self._get_access_token():
                raise ConnectionError("Failed to obtain access token")
            
            # Test by listing workspace
            url = f"{self.base_url}?api-version=2021-06-01"
            response = requests.get(
                url,
                headers=self._get_headers(),
                timeout=30
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully connected to Sentinel workspace: {self.workspace_id}")
                return True
            else:
                error_msg = f"Sentinel connection test failed with status {response.status_code}"
                logger.error(error_msg)
                raise ConnectionError(error_msg)
            
        except (ConnectionError, AuthenticationError):
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error testing Sentinel connection: {str(e)}")
            raise ConnectionError(f"Network error: {str(e)}") from e
        except Exception as e:
            logger.error(f"Unexpected error testing connection: {str(e)}", exc_info=True)
            raise ConnectionError(f"Connection test failed: {str(e)}") from e
    
    def get_incidents(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        max_results: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Fetch incidents from Sentinel.
        
        Args:
            severity: Filter by severity (High, Medium, Low, Informational)
            status: Filter by status (New, Active, Closed)
            max_results: Maximum incidents to return
        
        Returns:
            List of incident dictionaries
        """
        try:
            url = f"{self.base_url}/providers/Microsoft.SecurityInsights/incidents?api-version=2021-10-01"
            
            response = requests.get(
                url,
                headers=self._get_headers(),
                timeout=60
            )
            
            if response.status_code != 200:
                error_msg = f"Failed to fetch incidents: {response.text}"
                logger.error(error_msg)
                raise APIError(error_msg, status_code=response.status_code)
            
            incidents = response.json().get("value", [])
            
            # Apply filters
            if severity:
                incidents = [i for i in incidents if i.get("properties", {}).get("severity") == severity]
            
            if status:
                incidents = [i for i in incidents if i.get("properties", {}).get("status") == status]
            
            incidents = incidents[:max_results]
            logger.info(f"Retrieved {len(incidents)} incidents from Sentinel")
            return incidents
            
        except (APIError, ConnectionError, AuthenticationError):
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error fetching incidents: {str(e)}")
            raise ConnectionError(f"Network error: {str(e)}") from e
        except Exception as e:
            logger.error(f"Unexpected error fetching incidents: {str(e)}", exc_info=True)
            raise APIError(f"Unexpected error: {str(e)}") from e
    
    def update_incident(
        self,
        incident_id: str,
        comment: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None
    ) -> bool:
        """
        Update a Sentinel incident.
        
        Args:
            incident_id: Incident identifier
            comment: Comment to add
            status: New status (New, Active, Closed)
            severity: New severity (High, Medium, Low, Informational)
        
        Returns:
            Success status
        """
        try:
            # Add comment if provided
            if comment:
                comment_url = (
                    f"{self.base_url}/providers/Microsoft.SecurityInsights/"
                    f"incidents/{incident_id}/comments/{datetime.now().timestamp()}?"
                    f"api-version=2021-10-01"
                )
                
                comment_data = {
                    "properties": {
                        "message": comment
                    }
                }
                
                response = requests.put(
                    comment_url,
                    headers=self._get_headers(),
                    json=comment_data,
                    timeout=30
                )
                
                if response.status_code not in [200, 201]:
                    error_msg = f"Failed to add comment: {response.text}"
                    logger.error(error_msg)
                    raise APIError(error_msg, status_code=response.status_code)
            
            # Update status/severity if provided
            if status or severity:
                update_url = (
                    f"{self.base_url}/providers/Microsoft.SecurityInsights/"
                    f"incidents/{incident_id}?api-version=2021-10-01"
                )
                
                # Get current incident first
                current = requests.get(update_url, headers=self._get_headers(), timeout=30)
                if current.status_code != 200:
                    return False
                
                incident_data = current.json()
                
                # Update fields
                if status:
                    incident_data["properties"]["status"] = status
                if severity:
                    incident_data["properties"]["severity"] = severity
                
                response = requests.put(
                    update_url,
                    headers=self._get_headers(),
                    json=incident_data,
                    timeout=30
                )
                
                if response.status_code not in [200, 201]:
                    error_msg = f"Failed to update incident: {response.text}"
                    logger.error(error_msg)
                    raise APIError(error_msg, status_code=response.status_code)
                
                logger.info(f"Successfully updated incident: {incident_id}")
                return True
            
            return True
            
        except (APIError, ConnectionError, AuthenticationError):
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error updating incident: {str(e)}")
            raise ConnectionError(f"Network error: {str(e)}") from e
        except Exception as e:
            logger.error(f"Unexpected error updating incident: {str(e)}", exc_info=True)
            raise APIError(f"Unexpected error: {str(e)}") from e
    
    def create_threat_indicator(
        self,
        ioc_value: str,
        ioc_type: str,
        confidence: int = 50,
        description: str = ""
    ) -> bool:
        """
        Create a threat indicator in Sentinel.
        
        Args:
            ioc_value: Indicator value (IP, domain, hash, etc.)
            ioc_type: Type (ipv4, domain-name, file, etc.)
            confidence: Confidence score (0-100)
            description: Indicator description
        
        Returns:
            Success status
        """
        try:
            url = (
                f"{self.base_url}/providers/Microsoft.SecurityInsights/"
                f"threatIntelligence/main/indicators/{datetime.now().timestamp()}?"
                f"api-version=2021-10-01"
            )
            
            indicator_data = {
                "kind": "indicator",
                "properties": {
                    "pattern": f"[{ioc_type}:value = '{ioc_value}']",
                    "patternType": "stix",
                    "source": "CyberXP Agent",
                    "confidence": confidence,
                    "description": description or f"IOC extracted by CyberXP: {ioc_value}",
                    "threatTypes": ["malicious-activity"],
                    "validFrom": datetime.now().isoformat(),
                }
            }
            
            response = requests.put(
                url,
                headers=self._get_headers(),
                json=indicator_data,
                timeout=30
            )
            
            if response.status_code in [200, 201]:
                logger.info(f"Successfully created threat indicator: {ioc_value}")
                return True
            else:
                error_msg = f"Failed to create threat indicator: {response.text}"
                logger.error(error_msg)
                raise APIError(error_msg, status_code=response.status_code)
            
        except (APIError, ConnectionError, AuthenticationError):
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error creating threat indicator: {str(e)}")
            raise ConnectionError(f"Network error: {str(e)}") from e
        except Exception as e:
            logger.error(f"Unexpected error creating threat indicator: {str(e)}", exc_info=True)
            raise APIError(f"Unexpected error: {str(e)}") from e


# Example usage
if __name__ == "__main__":
    import os
    
    try:
        # Test connection
        sentinel = SentinelConnector(
            workspace_id=os.getenv("SENTINEL_WORKSPACE_ID", "your-workspace-id"),
            subscription_id=os.getenv("SENTINEL_SUBSCRIPTION_ID", "your-subscription-id"),
            resource_group=os.getenv("SENTINEL_RESOURCE_GROUP", "your-resource-group"),
            tenant_id=os.getenv("SENTINEL_TENANT_ID", "your-tenant-id"),
            client_id=os.getenv("SENTINEL_CLIENT_ID", "your-client-id"),
            client_secret=os.getenv("SENTINEL_CLIENT_SECRET", "your-client-secret")
        )
        
        if sentinel.test_connection():
            logger.info("✓ Connected to Sentinel")
            
            # Fetch high severity incidents
            incidents = sentinel.get_incidents(severity="High", max_results=10)
            logger.info(f"✓ Found {len(incidents)} high-severity incidents")
            
            # Create test threat indicator
            if sentinel.create_threat_indicator(
                ioc_value="192.168.1.100",
                ioc_type="ipv4-addr",
                confidence=80,
                description="Test IOC from CyberXP"
            ):
                logger.info("✓ Threat indicator created")
    except Exception as e:
        logger.error(f"✗ Connection failed: {str(e)}", exc_info=True)

