"""
VirusTotal API Connector
Enrich IOCs with threat intelligence from VirusTotal
"""

import requests
import time
from typing import Dict, List, Optional, Any
from datetime import datetime

from ..utils.logger import get_logger
from ..utils.exceptions import APIError, RateLimitError, AuthenticationError
from ..utils.retry import retry_with_backoff

logger = get_logger(__name__)


class VirusTotalConnector:
    """
    Connect to VirusTotal API for IOC enrichment.
    
    Features:
    - IP address reputation lookup
    - Domain reputation lookup
    - File hash analysis
    - URL scanning
    - Rate limit handling
    
    API Tiers:
    - Free: 4 requests/minute, 500/day
    - Premium: Higher limits
    """
    
    def __init__(self, api_key: str, rate_limit: int = 4):
        """
        Initialize VirusTotal connector.
        
        Args:
            api_key: VirusTotal API key
            rate_limit: Requests per minute (4 for free tier)
        
        Raises:
            ValueError: If API key is empty
        """
        if not api_key:
            raise ValueError("VirusTotal API key is required")
        
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": api_key,
            "Accept": "application/json"
        }
        
        # Rate limiting
        self.rate_limit = rate_limit
        self.request_times = []
        logger.debug(f"VirusTotal connector initialized with rate limit: {rate_limit}/min")
    
    def _rate_limit_wait(self):
        """Implement rate limiting"""
        now = time.time()
        
        # Remove requests older than 60 seconds
        self.request_times = [t for t in self.request_times if now - t < 60]
        
        # If at limit, wait
        if len(self.request_times) >= self.rate_limit:
            wait_time = 60 - (now - self.request_times[0])
            if wait_time > 0:
                logger.warning(f"VirusTotal rate limit reached. Waiting {wait_time:.1f}s...")
                time.sleep(wait_time)
                self.request_times = []
        
        self.request_times.append(now)
    
    def test_connection(self) -> bool:
        """
        Test API key validity.
        
        Returns:
            True if API key is valid
        
        Raises:
            AuthenticationError: If API key is invalid
        """
        try:
            logger.debug("Testing VirusTotal API key validity")
            # Simple endpoint to verify key
            response = requests.get(
                f"{self.base_url}/users/{self.api_key}",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info("VirusTotal API key is valid")
                return True
            elif response.status_code == 401:
                logger.error("VirusTotal API key is invalid")
                raise AuthenticationError("Invalid VirusTotal API key")
            else:
                logger.error(f"VirusTotal connection test failed with status {response.status_code}")
                raise APIError(f"API returned status {response.status_code}", status_code=response.status_code)
                
        except (AuthenticationError, APIError):
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error testing VirusTotal connection: {str(e)}")
            raise APIError(f"Network error: {str(e)}") from e
        except Exception as e:
            logger.error(f"Unexpected error testing connection: {str(e)}", exc_info=True)
            raise APIError(f"Connection test failed: {str(e)}") from e
    
    def enrich_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Get IP address reputation and context.
        
        Args:
            ip_address: IPv4 address to check
        
        Returns:
            Enrichment data dictionary
        """
        try:
            self._rate_limit_wait()
            
            url = f"{self.base_url}/ip_addresses/{ip_address}"
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 429:
                logger.warning(f"VirusTotal rate limit exceeded for {ip_address}")
                raise RateLimitError(f"Rate limit exceeded: {response.status_code}")
            elif response.status_code != 200:
                logger.warning(f"VirusTotal API returned status {response.status_code} for {ip_address}")
                return {"error": f"API returned {response.status_code}"}
            
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            return {
                "ioc": ip_address,
                "type": "ip",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()),
                "country": attributes.get("country", "Unknown"),
                "asn": attributes.get("asn", "Unknown"),
                "as_owner": attributes.get("as_owner", "Unknown"),
                "reputation": attributes.get("reputation", 0),
                "last_analysis_date": attributes.get("last_analysis_date", "Unknown"),
                "source": "VirusTotal"
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error enriching IP {ip_address}: {str(e)}")
            return {"error": f"Network error: {str(e)}"}
        except Exception as e:
            logger.error(f"Unexpected error enriching IP {ip_address}: {str(e)}", exc_info=True)
            return {"error": str(e)}
    
    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """
        Get domain reputation and context.
        
        Args:
            domain: Domain name to check
        
        Returns:
            Enrichment data dictionary
        """
        try:
            self._rate_limit_wait()
            
            url = f"{self.base_url}/domains/{domain}"
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 429:
                logger.warning(f"VirusTotal rate limit exceeded for {ip_address}")
                raise RateLimitError(f"Rate limit exceeded: {response.status_code}")
            elif response.status_code != 200:
                logger.warning(f"VirusTotal API returned status {response.status_code} for {ip_address}")
                return {"error": f"API returned {response.status_code}"}
            
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            return {
                "ioc": domain,
                "type": "domain",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()),
                "categories": attributes.get("categories", {}),
                "reputation": attributes.get("reputation", 0),
                "creation_date": attributes.get("creation_date", "Unknown"),
                "last_analysis_date": attributes.get("last_analysis_date", "Unknown"),
                "source": "VirusTotal"
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error enriching IP {ip_address}: {str(e)}")
            return {"error": f"Network error: {str(e)}"}
        except Exception as e:
            logger.error(f"Unexpected error enriching IP {ip_address}: {str(e)}", exc_info=True)
            return {"error": str(e)}
    
    def enrich_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Get file hash analysis results.
        
        Args:
            file_hash: MD5, SHA1, or SHA256 hash
        
        Returns:
            Enrichment data dictionary
        """
        try:
            self._rate_limit_wait()
            
            url = f"{self.base_url}/files/{file_hash}"
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 429:
                logger.warning(f"VirusTotal rate limit exceeded for {ip_address}")
                raise RateLimitError(f"Rate limit exceeded: {response.status_code}")
            elif response.status_code != 200:
                logger.warning(f"VirusTotal API returned status {response.status_code} for {ip_address}")
                return {"error": f"API returned {response.status_code}"}
            
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            return {
                "ioc": file_hash,
                "type": "hash",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()),
                "file_type": attributes.get("type_description", "Unknown"),
                "file_size": attributes.get("size", 0),
                "names": attributes.get("names", [])[:5],  # Top 5 names
                "first_seen": attributes.get("first_submission_date", "Unknown"),
                "last_analysis_date": attributes.get("last_analysis_date", "Unknown"),
                "source": "VirusTotal"
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error enriching IP {ip_address}: {str(e)}")
            return {"error": f"Network error: {str(e)}"}
        except Exception as e:
            logger.error(f"Unexpected error enriching IP {ip_address}: {str(e)}", exc_info=True)
            return {"error": str(e)}
    
    def enrich_url(self, url: str) -> Dict[str, Any]:
        """
        Get URL reputation and context.
        
        Args:
            url: URL to check
        
        Returns:
            Enrichment data dictionary
        """
        try:
            self._rate_limit_wait()
            
            # URL needs to be base64 encoded without padding
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            api_url = f"{self.base_url}/urls/{url_id}"
            response = requests.get(api_url, headers=self.headers, timeout=30)
            
            if response.status_code == 429:
                logger.warning(f"VirusTotal rate limit exceeded for {ip_address}")
                raise RateLimitError(f"Rate limit exceeded: {response.status_code}")
            elif response.status_code != 200:
                logger.warning(f"VirusTotal API returned status {response.status_code} for {ip_address}")
                return {"error": f"API returned {response.status_code}"}
            
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            return {
                "ioc": url,
                "type": "url",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()),
                "categories": attributes.get("categories", {}),
                "last_analysis_date": attributes.get("last_analysis_date", "Unknown"),
                "source": "VirusTotal"
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error enriching IP {ip_address}: {str(e)}")
            return {"error": f"Network error: {str(e)}"}
        except Exception as e:
            logger.error(f"Unexpected error enriching IP {ip_address}: {str(e)}", exc_info=True)
            return {"error": str(e)}
    
    def bulk_enrich_iocs(self, iocs: Dict[str, List[str]]) -> Dict[str, List[Dict]]:
        """
        Enrich multiple IOCs with rate limiting.
        
        Args:
            iocs: Dictionary with keys: ips, domains, hashes, urls
        
        Returns:
            Dictionary with enriched IOCs
        """
        enriched = {
            "ips": [],
            "domains": [],
            "hashes": [],
            "urls": []
        }
        
        # Enrich IPs
        for ip in iocs.get("ips", []):
            result = self.enrich_ip(ip)
            enriched["ips"].append(result)
        
        # Enrich domains
        for domain in iocs.get("domains", []):
            result = self.enrich_domain(domain)
            enriched["domains"].append(result)
        
        # Enrich hashes
        for hash_val in iocs.get("hashes", []):
            result = self.enrich_hash(hash_val)
            enriched["hashes"].append(result)
        
        # Enrich URLs
        for url in iocs.get("urls", []):
            result = self.enrich_url(url)
            enriched["urls"].append(result)
        
        return enriched
    
    def get_summary(self, enriched_ioc: Dict[str, Any]) -> str:
        """
        Get human-readable summary of enrichment.
        
        Args:
            enriched_ioc: Enriched IOC dictionary
        
        Returns:
            Summary string
        """
        if "error" in enriched_ioc:
            return f"❌ Error: {enriched_ioc['error']}"
        
        ioc = enriched_ioc.get("ioc", "Unknown")
        malicious = enriched_ioc.get("malicious", 0)
        total = enriched_ioc.get("total_engines", 0)
        
        if malicious == 0:
            status = "✅ Clean"
        elif malicious < 5:
            status = "⚠️ Suspicious"
        else:
            status = "🚨 Malicious"
        
        return f"{status} {ioc}: {malicious}/{total} engines flagged as malicious"


# Example usage
if __name__ == "__main__":
    import os
    
    try:
        # Initialize connector
        vt = VirusTotalConnector(
            api_key=os.getenv("VIRUSTOTAL_API_KEY", "your-api-key-here")
        )
        
        # Test connection
        if vt.test_connection():
            logger.info("✅ Connected to VirusTotal\n")
        else:
            logger.error("❌ Connection failed - check API key\n")
            exit(1)
    except Exception as e:
        logger.error(f"❌ Connection failed: {str(e)}", exc_info=True)
        exit(1)
    
    # Test IP enrichment
    print("=" * 60)
    print("IP Address Enrichment")
    print("=" * 60)
    
    ip_result = vt.enrich_ip("8.8.8.8")  # Google DNS (should be clean)
    print(vt.get_summary(ip_result))
    print(f"Country: {ip_result.get('country')}")
    print(f"ASN: {ip_result.get('asn')}")
    print("")
        
    # Test domain enrichment
    print("=" * 60)
    print("Domain Enrichment")
    print("=" * 60)
        
    domain_result = vt.enrich_domain("google.com")  # Should be clean
    print(vt.get_summary(domain_result))
    print(f"Reputation: {domain_result.get('reputation')}")
    print("")
        
        # Test hash enrichment (example malware hash)
    logger.info("=" * 60)
    print("File Hash Enrichment")
    print("=" * 60)
        
    hash_result = vt.enrich_hash("44d88612fea8a8f36de82e1278abb02f")  # EICAR test file
    print(vt.get_summary(hash_result))
    print(f"File type: {hash_result.get('file_type')}")
    print("")
        
        # Bulk enrichment
    print("=" * 60)
    print("Bulk IOC Enrichment")
    print("=" * 60)
        
    test_iocs = {
            "ips": ["8.8.8.8", "1.1.1.1"],
            "domains": ["google.com", "github.com"],
            "hashes": [],
            "urls": []
        }
        
    enriched = vt.bulk_enrich_iocs(test_iocs)
        
    print(f"\nEnriched {len(enriched['ips'])} IPs")
    for ip_data in enriched['ips']:
        print(f"  {vt.get_summary(ip_data)}")
        
    print(f"\nEnriched {len(enriched['domains'])} domains")
    for domain_data in enriched['domains']:
        print(f"  {vt.get_summary(domain_data)}")
        
    print(f"\nEnriched {len(enriched['hashes'])} hashes")
    for hash_data in enriched['hashes']:
        print(f"  {vt.get_summary(hash_data)}")
        
    print(f"\nEnriched {len(enriched['urls'])} URLs")
    for url_data in enriched['urls']:
        print(f"  {vt.get_summary(url_data)}")
        
