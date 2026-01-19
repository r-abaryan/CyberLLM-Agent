"""
Splunk SIEM Connector
Simple REST API integration for alert ingestion and result export
"""

import requests
import json
import warnings
from typing import List, Dict, Optional, Any
from datetime import datetime
import urllib3

from ..utils.logger import get_logger
from ..utils.exceptions import ConnectionError, APIError, AuthenticationError
from ..utils.retry import retry_with_backoff

logger = get_logger(__name__)


class SplunkConnector:
    """
    Connect to Splunk for bidirectional threat assessment integration.
    
    Features:
    - Fetch notable events/alerts
    - Push assessment results
    - Search for IOC context
    - Update incident status
    """
    
    def __init__(
        self,
        host: str,
        port: int = 8089,
        username: str = "",
        password: str = "",
        token: str = "",
        verify_ssl: bool = True  # SECURITY: Default to True
    ):
        """
        Initialize Splunk connector.
        
        Args:
            host: Splunk server hostname/IP
            port: Management port (default 8089)
            username: Splunk username (if not using token)
            password: Splunk password (if not using token)
            token: API token (preferred over username/password)
            verify_ssl: Verify SSL certificates (default: True for security)
        
        Raises:
            AuthenticationError: If no authentication method provided
        """
        if not host:
            raise ValueError("Splunk host is required")
        
        self.host = host
        self.port = port
        self.base_url = f"https://{host}:{port}"
        self.verify_ssl = verify_ssl
        
        # Security warning if SSL verification is disabled
        if not verify_ssl:
            logger.warning(
                "SECURITY WARNING: SSL verification is disabled for Splunk connection. "
                "This is insecure and should only be used in development environments."
            )
            warnings.warn(
                "SSL verification disabled for Splunk - security risk!",
                UserWarning,
                stacklevel=2
            )
            # Only disable warnings if explicitly disabled
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Authentication
        if token:
            if not token:
                raise AuthenticationError("Splunk token provided but is empty")
            self.headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            self.auth = None
            logger.debug("Using token-based authentication for Splunk")
        elif username and password:
            self.headers = {"Content-Type": "application/json"}
            self.auth = (username, password)
            logger.debug("Using username/password authentication for Splunk")
        else:
            raise AuthenticationError(
                "Splunk authentication required: provide either token or username/password"
            )
    
    @retry_with_backoff(max_retries=2, initial_delay=1.0)
    def test_connection(self) -> bool:
        """
        Test connectivity to Splunk.
        
        Returns:
            True if connection successful
        
        Raises:
            ConnectionError: If connection fails
            AuthenticationError: If authentication fails
        """
        try:
            url = f"{self.base_url}/services/server/info"
            response = requests.get(
                url,
                headers=self.headers,
                auth=self.auth,
                verify=self.verify_ssl,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully connected to Splunk at {self.host}:{self.port}")
                return True
            elif response.status_code == 401:
                logger.error("Splunk authentication failed - check credentials")
                raise AuthenticationError("Splunk authentication failed")
            else:
                logger.error(f"Splunk connection test failed with status {response.status_code}")
                raise ConnectionError(f"Splunk returned status {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Splunk connection test failed: {str(e)}")
            raise ConnectionError(f"Failed to connect to Splunk: {str(e)}") from e
    
    @retry_with_backoff(max_retries=2)
    def fetch_notable_events(
        self,
        search_query: str = 'search index=notable',
        max_results: int = 100,
        earliest_time: str = '-1h'
    ) -> List[Dict[str, Any]]:
        """
        Fetch notable events from Splunk.
        
        Args:
            search_query: SPL search query
            max_results: Maximum results to return
            earliest_time: Time range (e.g., '-1h', '-24h')
        
        Returns:
            List of event dictionaries
        
        Raises:
            APIError: If API call fails
        """
        try:
            logger.debug(f"Fetching notable events with query: {search_query[:100]}...")
            
            # Create search job
            search_url = f"{self.base_url}/services/search/jobs"
            search_data = {
                "search": search_query,
                "earliest_time": earliest_time,
                "output_mode": "json",
                "count": max_results
            }
            
            response = requests.post(
                search_url,
                headers=self.headers,
                auth=self.auth,
                data=search_data,
                verify=self.verify_ssl,
                timeout=30
            )
            
            if response.status_code != 201:
                error_msg = f"Search creation failed: {response.text}"
                logger.error(error_msg)
                raise APIError(error_msg, status_code=response.status_code)
            
            job_sid = response.json().get("sid")
            logger.debug(f"Created Splunk search job: {job_sid}")
            
            # Wait for results
            results_url = f"{self.base_url}/services/search/jobs/{job_sid}/results"
            results_response = requests.get(
                results_url,
                headers=self.headers,
                auth=self.auth,
                params={"output_mode": "json"},
                verify=self.verify_ssl,
                timeout=60
            )
            
            if results_response.status_code == 200:
                results = results_response.json().get("results", [])
                logger.info(f"Retrieved {len(results)} notable events from Splunk")
                return results
            else:
                error_msg = f"Failed to retrieve results: {results_response.text}"
                logger.error(error_msg)
                raise APIError(error_msg, status_code=results_response.status_code)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error fetching notable events: {str(e)}")
            raise ConnectionError(f"Network error: {str(e)}") from e
        except APIError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error fetching notable events: {str(e)}", exc_info=True)
            raise APIError(f"Unexpected error: {str(e)}") from e
    
    @retry_with_backoff(max_retries=2)
    def push_assessment(
        self,
        assessment: Dict[str, Any],
        iocs: Optional[Dict] = None,
        index: str = "cyberxp_assessments"
    ) -> bool:
        """
        Push assessment results to Splunk via HEC.
        
        Args:
            assessment: Assessment dictionary
            iocs: Extracted IOCs
            index: Target Splunk index
        
        Returns:
            True if successful
        
        Raises:
            APIError: If push fails
        """
        try:
            logger.debug(f"Pushing assessment to Splunk index: {index}")
            
            # Format for HEC
            event_data = {
                "time": datetime.now().timestamp(),
                "index": index,
                "sourcetype": "cyberxp:assessment",
                "event": {
                    "assessment": assessment,
                    "iocs": iocs or {},
                    "timestamp": datetime.now().isoformat()
                }
            }
            
            # Note: HEC endpoint is usually on port 8088
            hec_url = f"https://{self.host}:8088/services/collector/event"
            
            response = requests.post(
                hec_url,
                headers=self.headers,
                json=event_data,
                verify=self.verify_ssl,
                timeout=30
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully pushed assessment to Splunk index: {index}")
                return True
            else:
                error_msg = f"Failed to push assessment: {response.text}"
                logger.error(error_msg)
                raise APIError(error_msg, status_code=response.status_code)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error pushing assessment: {str(e)}")
            raise ConnectionError(f"Network error: {str(e)}") from e
        except APIError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error pushing assessment: {str(e)}", exc_info=True)
            raise APIError(f"Unexpected error: {str(e)}") from e
    
    def search_ioc_context(self, ioc: str, ioc_type: str) -> List[Dict]:
        """
        Search Splunk for historical context about an IOC.
        
        Args:
            ioc: Indicator value (IP, domain, hash, etc.)
            ioc_type: Type of indicator
        
        Returns:
            List of related events
        """
        try:
            logger.debug(f"Searching Splunk for IOC context: {ioc_type}={ioc}")
            
            # Build search query based on IOC type
            if ioc_type == "ip":
                search_query = f'search (src_ip="{ioc}" OR dest_ip="{ioc}" OR ip="{ioc}")'
            elif ioc_type == "domain":
                search_query = f'search (domain="{ioc}" OR url="*{ioc}*")'
            elif ioc_type == "hash":
                search_query = f'search (md5="{ioc}" OR sha1="{ioc}" OR sha256="{ioc}")'
            else:
                search_query = f'search "{ioc}"'
            
            return self.fetch_notable_events(
                search_query=search_query,
                max_results=50,
                earliest_time='-7d'
            )
            
        except Exception as e:
            logger.error(f"Error searching IOC context: {str(e)}", exc_info=True)
            return []


# Example usage
if __name__ == "__main__":
    import os
    
    # Test connection
    try:
        splunk = SplunkConnector(
            host=os.getenv("SPLUNK_HOST", "splunk.example.com"),
            token=os.getenv("SPLUNK_TOKEN", "your-splunk-token"),
            verify_ssl=True  # Use proper SSL verification
        )
        
        if splunk.test_connection():
            logger.info("✓ Connected to Splunk")
            
            # Fetch recent alerts
            events = splunk.fetch_notable_events(max_results=10)
            logger.info(f"✓ Found {len(events)} notable events")
            
            # Push test assessment
            test_assessment = {
                "threat": "Test threat",
                "severity": "Medium",
                "recommendation": "Investigate further"
            }
            
            if splunk.push_assessment(test_assessment):
                logger.info("✓ Assessment pushed successfully")
    except Exception as e:
        logger.error(f"✗ Connection failed: {str(e)}", exc_info=True)

