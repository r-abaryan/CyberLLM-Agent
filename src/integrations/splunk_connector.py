"""
Splunk SIEM Connector
Simple REST API integration for alert ingestion and result export
"""

import requests
import json
from typing import List, Dict, Optional, Any
from datetime import datetime
import urllib3

# Disable SSL warnings for self-signed certs (production: use proper certs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
        verify_ssl: bool = False
    ):
        """
        Initialize Splunk connector.
        
        Args:
            host: Splunk server hostname/IP
            port: Management port (default 8089)
            username: Splunk username (if not using token)
            password: Splunk password (if not using token)
            token: API token (preferred over username/password)
            verify_ssl: Verify SSL certificates
        """
        self.host = host
        self.port = port
        self.base_url = f"https://{host}:{port}"
        self.verify_ssl = verify_ssl
        
        # Authentication
        if token:
            self.headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
        else:
            self.headers = {"Content-Type": "application/json"}
            self.auth = (username, password)
    
    def test_connection(self) -> bool:
        """Test connectivity to Splunk"""
        try:
            url = f"{self.base_url}/services/server/info"
            response = requests.get(
                url,
                headers=self.headers,
                auth=getattr(self, 'auth', None),
                verify=self.verify_ssl,
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            print(f"Connection test failed: {e}")
            return False
    
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
        """
        try:
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
                auth=getattr(self, 'auth', None),
                data=search_data,
                verify=self.verify_ssl,
                timeout=30
            )
            
            if response.status_code != 201:
                print(f"Search creation failed: {response.text}")
                return []
            
            job_sid = response.json().get("sid")
            
            # Wait for results
            results_url = f"{self.base_url}/services/search/jobs/{job_sid}/results"
            results_response = requests.get(
                results_url,
                headers=self.headers,
                auth=getattr(self, 'auth', None),
                params={"output_mode": "json"},
                verify=self.verify_ssl,
                timeout=60
            )
            
            if results_response.status_code == 200:
                return results_response.json().get("results", [])
            
            return []
            
        except Exception as e:
            print(f"Error fetching notable events: {e}")
            return []
    
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
            Success status
        """
        try:
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
            
            return response.status_code == 200
            
        except Exception as e:
            print(f"Error pushing assessment: {e}")
            return False
    
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
            print(f"Error searching IOC context: {e}")
            return []


# Example usage
if __name__ == "__main__":
    # Test connection
    splunk = SplunkConnector(
        host="splunk.example.com",
        token="your-splunk-token"
    )
    
    if splunk.test_connection():
        print("✓ Connected to Splunk")
        
        # Fetch recent alerts
        events = splunk.fetch_notable_events(max_results=10)
        print(f"✓ Found {len(events)} notable events")
        
        # Push test assessment
        test_assessment = {
            "threat": "Test threat",
            "severity": "Medium",
            "recommendation": "Investigate further"
        }
        
        if splunk.push_assessment(test_assessment):
            print("✓ Assessment pushed successfully")
    else:
        print("✗ Connection failed")

