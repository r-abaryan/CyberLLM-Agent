#!/usr/bin/env python3
"""
IOC (Indicators of Compromise) Extraction Utility

Extracts common IOCs from text using regex patterns:
- IP addresses (IPv4)
- Domain names
- File hashes (MD5, SHA1, SHA256)
- File paths (Windows and Unix)
- Usernames
"""

import re
from typing import Dict, List, Set


def extract_iocs(text: str) -> Dict[str, List[str]]:
    """
    Extract IOCs from text using regex patterns.
    
    Args:
        text: Text to extract IOCs from
        
    Returns:
        Dictionary with keys: ips, domains, hashes, paths, users
    """
    if not text:
        return {
            "ips": [],
            "domains": [],
            "hashes": [],
            "paths": [],
            "users": []
        }
    
    # IP addresses (IPv4)
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ips = list(set(re.findall(ip_pattern, text)))
    
    # Domain names (basic pattern)
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    domains = list(set(re.findall(domain_pattern, text)))
    
    # Filter out common false positives for domains
    domains = [d for d in domains if not any(fp in d.lower() for fp in ['example.com', 'localhost', 'test.com'])]
    
    # File hashes (MD5, SHA1, SHA256)
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    
    hashes = list(set(
        re.findall(md5_pattern, text) +
        re.findall(sha1_pattern, text) +
        re.findall(sha256_pattern, text)
    ))
    
    # File paths (Windows and Unix)
    windows_path_pattern = r'[a-zA-Z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\\\/:*?"<>|\r\n]*'
    unix_path_pattern = r'/(?:[^/\s]+/)*[^/\s]+'
    
    windows_paths = re.findall(windows_path_pattern, text)
    unix_paths = re.findall(unix_path_pattern, text)
    
    # Filter paths to reduce noise
    paths = []
    for p in windows_paths + unix_paths:
        if len(p) > 5 and any(ext in p.lower() for ext in ['.exe', '.dll', '.bat', '.ps1', '.sh', '.py', '.log', '.txt', '.dat']):
            paths.append(p)
    
    paths = list(set(paths))
    
    # Usernames (basic pattern: @username or mentioned users)
    user_pattern = r'(?:user|account|username)[\s:]+([a-zA-Z0-9_\-\.]+)'
    users = list(set(re.findall(user_pattern, text, re.IGNORECASE)))
    
    return {
        "ips": sorted(ips),
        "domains": sorted(domains),
        "hashes": sorted(hashes),
        "paths": sorted(paths),
        "users": sorted(users)
    }


def format_iocs_json(iocs: Dict[str, List[str]]) -> str:
    """
    Format IOCs as pretty-printed JSON string.
    
    Args:
        iocs: IOC dictionary
        
    Returns:
        JSON string
    """
    import json
    return json.dumps(iocs, indent=2)


def iocs_to_text(iocs: Dict[str, List[str]]) -> str:
    """
    Format IOCs as human-readable text.
    
    Args:
        iocs: IOC dictionary
        
    Returns:
        Formatted text string
    """
    lines = []
    
    if iocs.get("ips"):
        lines.append("IP Addresses:")
        for ip in iocs["ips"]:
            lines.append(f"  - {ip}")
        lines.append("")
    
    if iocs.get("domains"):
        lines.append("Domains:")
        for domain in iocs["domains"]:
            lines.append(f"  - {domain}")
        lines.append("")
    
    if iocs.get("hashes"):
        lines.append("File Hashes:")
        for hash_val in iocs["hashes"]:
            lines.append(f"  - {hash_val}")
        lines.append("")
    
    if iocs.get("paths"):
        lines.append("File Paths:")
        for path in iocs["paths"]:
            lines.append(f"  - {path}")
        lines.append("")
    
    if iocs.get("users"):
        lines.append("Users:")
        for user in iocs["users"]:
            lines.append(f"  - {user}")
        lines.append("")
    
    return "\n".join(lines).strip()


if __name__ == "__main__":
    # Test the IOC extraction
    test_text = """
    Suspicious activity detected from IP 192.168.1.100 connecting to malicious-domain.com.
    File hash: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
    Executed: C:\\Users\\Admin\\AppData\\Local\\Temp\\malware.exe
    Username: admin
    """
    
    iocs = extract_iocs(test_text)
    print("Extracted IOCs:")
    print(iocs_to_text(iocs))
    print("\nJSON format:")
    print(format_iocs_json(iocs))

