"""
VirusTotal API Connector
Enrich IOCs with threat intelligence from VirusTotal
"""

import requests
import time
from typing import Dict, List, Optional, Any
from datetime import datetime


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
        """
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": api_key,
            "Accept": "application/json"
        }
        
        # Rate limiting
        self.rate_limit = rate_limit
        self.request_times = []
    
    def _rate_limit_wait(self):
        """Implement rate limiting"""
        now = time.time()
        
        # Remove requests older than 60 seconds
        self.request_times = [t for t in self.request_times if now - t < 60]
        
        # If at limit, wait
        if len(self.request_times) >= self.rate_limit:
            wait_time = 60 - (now - self.request_times[0])
            if wait_time > 0:
                print(f"Rate limit reached. Waiting {wait_time:.1f}s...")
                time.sleep(wait_time)
                self.request_times = []
        
        self.request_times.append(now)
    
    def test_connection(self) -> bool:
        """Test API key validity"""
        try:
            # Simple endpoint to verify key
            response = requests.get(
                f"{self.base_url}/users/{self.api_key}",
                headers=self.headers,
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            print(f"Connection test failed: {e}")
            return False
    
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
            
            if response.status_code != 200:
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
            
        except Exception as e:
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
            
            if response.status_code != 200:
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
            
        except Exception as e:
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
            
            if response.status_code != 200:
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
            
        except Exception as e:
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
            
            if response.status_code != 200:
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
            
        except Exception as e:
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
    
    # Initialize connector
    vt = VirusTotalConnector(
        api_key=os.getenv("VIRUSTOTAL_API_KEY", "your-api-key-here")
    )
    
    # Test connection
    if vt.test_connection():
        print("✅ Connected to VirusTotal\n")
    else:
        print("❌ Connection failed - check API key\n")
        exit(1)
    
    # Test IP enrichment
    print("=" * 60)
    print("IP Address Enrichment")
    print("=" * 60)
    
    ip_result = vt.enrich_ip("8.8.8.8")  # Google DNS (should be clean)
    print(vt.get_summary(ip_result))
    print(f"Country: {ip_result.get('country')}")
    print(f"ASN: {ip_result.get('asn')}")
    print()
    
    # Test domain enrichment
    print("=" * 60)
    print("Domain Enrichment")
    print("=" * 60)
    
    domain_result = vt.enrich_domain("google.com")  # Should be clean
    print(vt.get_summary(domain_result))
    print(f"Reputation: {domain_result.get('reputation')}")
    print()
    
    # Test hash enrichment (example malware hash)
    print("=" * 60)
    print("File Hash Enrichment")
    print("=" * 60)
    
    hash_result = vt.enrich_hash("44d88612fea8a8f36de82e1278abb02f")  # EICAR test file
    print(vt.get_summary(hash_result))
    print(f"File type: {hash_result.get('file_type')}")
    print()
    
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

