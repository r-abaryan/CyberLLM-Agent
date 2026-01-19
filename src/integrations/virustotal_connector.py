"""
VirusTotal API Connector
Enrich IOCs with threat intelligence from VirusTotal
"""

import requests
import time
import re
from typing import Dict, List, Optional, Any
from datetime import datetime

from ..utils.logger import get_logger
from ..utils.exceptions import APIError, RateLimitError, AuthenticationError, ValidationError, ConnectionError
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
    
    def _validate_ip_address(self, ip_address: str) -> bool:
        """
        Validate IPv4 address format.
        
        Args:
            ip_address: IP address to validate
        
        Returns:
            True if valid IPv4 address
        
        Raises:
            ValidationError: If IP address is invalid
        """
        if not ip_address:
            raise ValidationError("IP address cannot be empty")
        
        # IPv4 pattern
        ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        
        if not re.match(ipv4_pattern, ip_address):
            raise ValidationError(f"Invalid IPv4 address format: {ip_address}")
        
        return True
    
    @retry_with_backoff(max_retries=3, initial_delay=1.0, retryable_exceptions=(APIError, RateLimitError, ConnectionError))
    def enrich_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Get IP address reputation and context.
        
        Args:
            ip_address: IPv4 address to check
        
        Returns:
            Enrichment data dictionary
        
        Raises:
            ValidationError: If IP address format is invalid
            RateLimitError: If rate limit is exceeded
            APIError: If API call fails
        """
        # Validate IP address format
        self._validate_ip_address(ip_address)
        
        try:
            self._rate_limit_wait()
            logger.debug(f"Enriching IP address: {ip_address}")
            
            url = f"{self.base_url}/ip_addresses/{ip_address}"
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 429:
                logger.warning(f"VirusTotal rate limit exceeded for {ip_address}")
                raise RateLimitError(f"Rate limit exceeded: {response.status_code}")
            elif response.status_code != 200:
                error_msg = f"VirusTotal API returned status {response.status_code} for {ip_address}"
                logger.warning(error_msg)
                raise APIError(error_msg, status_code=response.status_code)
            
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            result = {
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
            
            logger.debug(f"Successfully enriched IP {ip_address}")
            return result
            
        except (ValidationError, RateLimitError, APIError):
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error enriching IP {ip_address}: {str(e)}")
            raise APIError(f"Network error: {str(e)}") from e
        except Exception as e:
            logger.error(f"Unexpected error enriching IP {ip_address}: {str(e)}", exc_info=True)
            raise APIError(f"Unexpected error: {str(e)}") from e
    
    def _validate_domain(self, domain: str) -> bool:
        """
        Validate domain name format.
        
        Args:
            domain: Domain name to validate
        
        Returns:
            True if valid domain format
        
        Raises:
            ValidationError: If domain format is invalid
        """
        if not domain:
            raise ValidationError("Domain cannot be empty")
        
        # Basic domain pattern
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        
        if not re.match(domain_pattern, domain):
            raise ValidationError(f"Invalid domain format: {domain}")
        
        return True
    
    @retry_with_backoff(max_retries=3, initial_delay=1.0, retryable_exceptions=(APIError, RateLimitError, ConnectionError))
    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """
        Get domain reputation and context.
        
        Args:
            domain: Domain name to check
        
        Returns:
            Enrichment data dictionary
        
        Raises:
            ValidationError: If domain format is invalid
            RateLimitError: If rate limit is exceeded
            APIError: If API call fails
        """
        # Validate domain format
        self._validate_domain(domain)
        
        try:
            self._rate_limit_wait()
            logger.debug(f"Enriching domain: {domain}")
            
            url = f"{self.base_url}/domains/{domain}"
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 429:
                logger.warning(f"VirusTotal rate limit exceeded for {domain}")
                raise RateLimitError(f"Rate limit exceeded: {response.status_code}")
            elif response.status_code != 200:
                error_msg = f"VirusTotal API returned status {response.status_code} for {domain}"
                logger.warning(error_msg)
                raise APIError(error_msg, status_code=response.status_code)
            
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            result = {
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
            
            logger.debug(f"Successfully enriched domain {domain}")
            return result
            
        except (ValidationError, RateLimitError, APIError):
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error enriching domain {domain}: {str(e)}")
            raise APIError(f"Network error: {str(e)}") from e
        except Exception as e:
            logger.error(f"Unexpected error enriching domain {domain}: {str(e)}", exc_info=True)
            raise APIError(f"Unexpected error: {str(e)}") from e
    
    def _validate_hash(self, file_hash: str) -> bool:
        """
        Validate file hash format (MD5, SHA1, or SHA256).
        
        Args:
            file_hash: Hash to validate
        
        Returns:
            True if valid hash format
        
        Raises:
            ValidationError: If hash format is invalid
        """
        if not file_hash:
            raise ValidationError("File hash cannot be empty")
        
        # MD5: 32 hex chars, SHA1: 40 hex chars, SHA256: 64 hex chars
        hash_pattern = r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$'
        
        if not re.match(hash_pattern, file_hash):
            raise ValidationError(f"Invalid hash format (must be MD5, SHA1, or SHA256): {file_hash}")
        
        return True
    
    @retry_with_backoff(max_retries=3, initial_delay=1.0, retryable_exceptions=(APIError, RateLimitError, ConnectionError))
    def enrich_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Get file hash analysis results.
        
        Args:
            file_hash: MD5, SHA1, or SHA256 hash
        
        Returns:
            Enrichment data dictionary
        
        Raises:
            ValidationError: If hash format is invalid
            RateLimitError: If rate limit is exceeded
            APIError: If API call fails
        """
        # Validate hash format
        self._validate_hash(file_hash)
        
        try:
            self._rate_limit_wait()
            logger.debug(f"Enriching file hash: {file_hash[:16]}...")
            
            url = f"{self.base_url}/files/{file_hash}"
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 429:
                logger.warning(f"VirusTotal rate limit exceeded for hash {file_hash[:16]}...")
                raise RateLimitError(f"Rate limit exceeded: {response.status_code}")
            elif response.status_code != 200:
                error_msg = f"VirusTotal API returned status {response.status_code} for hash {file_hash[:16]}..."
                logger.warning(error_msg)
                raise APIError(error_msg, status_code=response.status_code)
            
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            result = {
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
            
            logger.debug(f"Successfully enriched hash {file_hash[:16]}...")
            return result
            
        except (ValidationError, RateLimitError, APIError):
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error enriching hash {file_hash[:16]}...: {str(e)}")
            raise APIError(f"Network error: {str(e)}") from e
        except Exception as e:
            logger.error(f"Unexpected error enriching hash {file_hash[:16]}...: {str(e)}", exc_info=True)
            raise APIError(f"Unexpected error: {str(e)}") from e
    
    def _validate_url(self, url: str) -> bool:
        """
        Validate URL format.
        
        Args:
            url: URL to validate
        
        Returns:
            True if valid URL format
        
        Raises:
            ValidationError: If URL format is invalid
        """
        if not url:
            raise ValidationError("URL cannot be empty")
        
        # Basic URL pattern
        url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        
        if not re.match(url_pattern, url):
            raise ValidationError(f"Invalid URL format: {url}")
        
        return True
    
    @retry_with_backoff(max_retries=3, initial_delay=1.0, retryable_exceptions=(APIError, RateLimitError, ConnectionError))
    def enrich_url(self, url: str) -> Dict[str, Any]:
        """
        Get URL reputation and context.
        
        Args:
            url: URL to check
        
        Returns:
            Enrichment data dictionary
        
        Raises:
            ValidationError: If URL format is invalid
            RateLimitError: If rate limit is exceeded
            APIError: If API call fails
        """
        # Validate URL format
        self._validate_url(url)
        
        try:
            self._rate_limit_wait()
            logger.debug(f"Enriching URL: {url[:50]}...")
            
            # URL needs to be base64 encoded without padding
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            api_url = f"{self.base_url}/urls/{url_id}"
            response = requests.get(api_url, headers=self.headers, timeout=30)
            
            if response.status_code == 429:
                logger.warning(f"VirusTotal rate limit exceeded for URL {url[:50]}...")
                raise RateLimitError(f"Rate limit exceeded: {response.status_code}")
            elif response.status_code != 200:
                error_msg = f"VirusTotal API returned status {response.status_code} for URL {url[:50]}..."
                logger.warning(error_msg)
                raise APIError(error_msg, status_code=response.status_code)
            
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            result = {
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
            
            logger.debug(f"Successfully enriched URL {url[:50]}...")
            return result
            
        except (ValidationError, RateLimitError, APIError):
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error enriching URL {url[:50]}...: {str(e)}")
            raise APIError(f"Network error: {str(e)}") from e
        except Exception as e:
            logger.error(f"Unexpected error enriching URL {url[:50]}...: {str(e)}", exc_info=True)
            raise APIError(f"Unexpected error: {str(e)}") from e
    
    def bulk_enrich_iocs(self, iocs: Dict[str, List[str]]) -> Dict[str, List[Dict]]:
        """
        Enrich multiple IOCs with rate limiting.
        
        Args:
            iocs: Dictionary with keys: ips, domains, hashes, urls
        
        Returns:
            Dictionary with enriched IOCs (includes error dicts for failed enrichments)
        """
        enriched = {
            "ips": [],
            "domains": [],
            "hashes": [],
            "urls": []
        }
        
        # Enrich IPs
        for ip in iocs.get("ips", []):
            try:
                result = self.enrich_ip(ip)
                enriched["ips"].append(result)
            except (ValidationError, RateLimitError, APIError) as e:
                logger.warning(f"Failed to enrich IP {ip}: {str(e)}")
                enriched["ips"].append({"ioc": ip, "type": "ip", "error": str(e)})
            except Exception as e:
                logger.error(f"Unexpected error enriching IP {ip}: {str(e)}", exc_info=True)
                enriched["ips"].append({"ioc": ip, "type": "ip", "error": str(e)})
        
        # Enrich domains
        for domain in iocs.get("domains", []):
            try:
                result = self.enrich_domain(domain)
                enriched["domains"].append(result)
            except (ValidationError, RateLimitError, APIError) as e:
                logger.warning(f"Failed to enrich domain {domain}: {str(e)}")
                enriched["domains"].append({"ioc": domain, "type": "domain", "error": str(e)})
            except Exception as e:
                logger.error(f"Unexpected error enriching domain {domain}: {str(e)}", exc_info=True)
                enriched["domains"].append({"ioc": domain, "type": "domain", "error": str(e)})
        
        # Enrich hashes
        for hash_val in iocs.get("hashes", []):
            try:
                result = self.enrich_hash(hash_val)
                enriched["hashes"].append(result)
            except (ValidationError, RateLimitError, APIError) as e:
                logger.warning(f"Failed to enrich hash {hash_val[:16]}...: {str(e)}")
                enriched["hashes"].append({"ioc": hash_val, "type": "hash", "error": str(e)})
            except Exception as e:
                logger.error(f"Unexpected error enriching hash {hash_val[:16]}...: {str(e)}", exc_info=True)
                enriched["hashes"].append({"ioc": hash_val, "type": "hash", "error": str(e)})
        
        # Enrich URLs
        for url in iocs.get("urls", []):
            try:
                result = self.enrich_url(url)
                enriched["urls"].append(result)
            except (ValidationError, RateLimitError, APIError) as e:
                logger.warning(f"Failed to enrich URL {url[:50]}...: {str(e)}")
                enriched["urls"].append({"ioc": url, "type": "url", "error": str(e)})
            except Exception as e:
                logger.error(f"Unexpected error enriching URL {url[:50]}...: {str(e)}", exc_info=True)
                enriched["urls"].append({"ioc": url, "type": "url", "error": str(e)})
        
        logger.info(
            f"Bulk enrichment completed: "
            f"{len(enriched['ips'])} IPs, {len(enriched['domains'])} domains, "
            f"{len(enriched['hashes'])} hashes, {len(enriched['urls'])} URLs"
        )
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
            return f" Error: {enriched_ioc['error']}"
        
        ioc = enriched_ioc.get("ioc", "Unknown")
        malicious = enriched_ioc.get("malicious", 0)
        total = enriched_ioc.get("total_engines", 0)
        
        if malicious == 0:
            status = " Clean"
        elif malicious < 5:
            status = " Suspicious"
        else:
            status = " Malicious"
        
        return f"{status} {ioc}: {malicious}/{total} engines flagged as malicious"


if __name__ == "__main__":
    import os
    
    try:
        # Initialize connector
        vt = VirusTotalConnector(
            api_key=os.getenv("VIRUSTOTAL_API_KEY", "your-api-key-here")
        )
        
        # Test connection
        if vt.test_connection():
            logger.info(" Connected to VirusTotal\n")
        else:
            logger.error(" Connection failed - check API key\n")
            exit(1)
    except Exception as e:
        logger.error(f" Connection failed: {str(e)}", exc_info=True)
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
        
