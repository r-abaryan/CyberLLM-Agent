"""
Example: SIEM & Threat Intelligence Integration with CyberXP
Demonstrates how to connect CyberXP with Splunk, Sentinel, and VirusTotal
"""

import os
from src.integrations import SplunkConnector, SentinelConnector, VirusTotalConnector
from src.agents import AgentRouter
from src.config import FeatureConfig

def example_splunk_workflow():
    """Example workflow with Splunk"""
    print("=" * 60)
    print("SPLUNK INTEGRATION EXAMPLE")
    print("=" * 60)
    
    # Initialize Splunk connector
    splunk = SplunkConnector(
        host=os.getenv("SPLUNK_HOST", "splunk.example.com"),
        token=os.getenv("SPLUNK_TOKEN", "your-token-here")
    )
    
    # Test connection
    if not splunk.test_connection():
        print("❌ Failed to connect to Splunk")
        return
    
    print("✅ Connected to Splunk\n")
    
    # 1. Fetch notable events
    print("📥 Fetching notable events...")
    events = splunk.fetch_notable_events(
        search_query='search index=notable severity=high',
        max_results=5
    )
    print(f"✅ Found {len(events)} high-severity events\n")
    
    # 2. Process each event with CyberXP
    # (Assuming you have initialized the agent router)
    # router = AgentRouter(llm=your_llm)
    
    for idx, event in enumerate(events[:1], 1):  # Process first event as example
        threat = event.get("_raw", "Unknown threat")
        print(f"🔍 Processing event {idx}: {threat[:100]}...")
        
        # Simulate assessment
        assessment = {
            "threat": threat,
            "severity": "High",
            "agent": "analysis",
            "immediate_actions": ["Isolate affected systems", "Block C2 domains"],
            "recovery": ["Restore from backup", "Patch vulnerabilities"],
            "preventive": ["Update IDS signatures", "Enhance monitoring"]
        }
        
        iocs = {
            "ips": ["192.168.1.100", "10.0.0.50"],
            "domains": ["malicious.com"],
            "hashes": []
        }
        
        # 3. Push assessment back to Splunk
        print(f"📤 Pushing assessment to Splunk...")
        if splunk.push_assessment(assessment, iocs):
            print(f"✅ Assessment {idx} pushed successfully\n")
        else:
            print(f"❌ Failed to push assessment {idx}\n")
    
    # 4. Search for IOC context
    print("🔎 Searching for IOC context...")
    ioc_context = splunk.search_ioc_context("192.168.1.100", "ip")
    print(f"✅ Found {len(ioc_context)} related events for IOC\n")
    
    print("=" * 60)


def example_sentinel_workflow():
    """Example workflow with Microsoft Sentinel"""
    print("=" * 60)
    print("MICROSOFT SENTINEL INTEGRATION EXAMPLE")
    print("=" * 60)
    
    # Initialize Sentinel connector
    sentinel = SentinelConnector(
        workspace_id=os.getenv("SENTINEL_WORKSPACE_ID", "your-workspace-id"),
        subscription_id=os.getenv("SENTINEL_SUBSCRIPTION_ID", "your-sub-id"),
        resource_group=os.getenv("SENTINEL_RESOURCE_GROUP", "your-rg"),
        tenant_id=os.getenv("SENTINEL_TENANT_ID", "your-tenant-id"),
        client_id=os.getenv("SENTINEL_CLIENT_ID", "your-client-id"),
        client_secret=os.getenv("SENTINEL_CLIENT_SECRET", "your-secret")
    )
    
    # Test connection
    if not sentinel.test_connection():
        print("❌ Failed to connect to Sentinel")
        return
    
    print("✅ Connected to Microsoft Sentinel\n")
    
    # 1. Fetch high-severity incidents
    print("📥 Fetching high-severity incidents...")
    incidents = sentinel.get_incidents(severity="High", status="Active", max_results=5)
    print(f"✅ Found {len(incidents)} active high-severity incidents\n")
    
    # 2. Process incidents
    for idx, incident in enumerate(incidents[:1], 1):  # Process first incident
        incident_id = incident.get("name")
        title = incident.get("properties", {}).get("title", "Unknown")
        
        print(f"🔍 Processing incident {idx}: {title}")
        
        # Simulate CyberXP assessment
        assessment_comment = """
CyberXP AI Assessment:

Severity: Critical
Agent: Analysis

Immediate Actions:
1. Isolate affected endpoints immediately
2. Block identified C2 domains at firewall
3. Disable compromised user accounts

Recovery:
1. Wipe and reimage affected systems
2. Restore data from last clean backup
3. Reset all user credentials

Preventive Measures:
1. Deploy EDR to all endpoints
2. Implement application whitelisting
3. Enhanced monitoring for lateral movement
"""
        
        # 3. Update incident with assessment
        print(f"📤 Updating incident with CyberXP assessment...")
        if sentinel.update_incident(
            incident_id=incident_id,
            comment=assessment_comment,
            status="Active"  # Keep active for SOC review
        ):
            print(f"✅ Incident {idx} updated successfully\n")
        else:
            print(f"❌ Failed to update incident {idx}\n")
    
    # 4. Create threat indicators for extracted IOCs
    print("📍 Creating threat indicators...")
    iocs = [
        ("192.168.1.100", "ipv4-addr", 85, "C2 server identified by CyberXP"),
        ("malicious.com", "domain-name", 90, "Malicious domain from assessment"),
    ]
    
    for ioc_value, ioc_type, confidence, description in iocs:
        if sentinel.create_threat_indicator(ioc_value, ioc_type, confidence, description):
            print(f"✅ Created indicator: {ioc_value}")
        else:
            print(f"❌ Failed to create indicator: {ioc_value}")
    
    print("\n" + "=" * 60)


def example_virustotal_workflow():
    """Example workflow with VirusTotal"""
    print("=" * 60)
    print("VIRUSTOTAL THREAT INTELLIGENCE EXAMPLE")
    print("=" * 60)
    
    # Initialize VirusTotal connector
    vt = VirusTotalConnector(
        api_key=os.getenv("VIRUSTOTAL_API_KEY", ""),
        rate_limit=4  # Free tier limit
    )
    
    # Test connection
    if not vt.test_connection():
        print("❌ Failed to connect to VirusTotal")
        print("   Get free API key from: https://www.virustotal.com/gui/join-us")
        return
    
    print("✅ Connected to VirusTotal (Free tier: 4 req/min)\n")
    
    # Simulate extracted IOCs from CyberXP assessment
    print("📊 Enriching IOCs extracted from threat assessment...\n")
    
    extracted_iocs = {
        "ips": ["8.8.8.8", "1.1.1.1"],
        "domains": ["google.com", "suspicious-domain.xyz"],
        "hashes": ["44d88612fea8a8f36de82e1278abb02f"],  # EICAR test file
        "urls": []
    }
    
    # Bulk enrich all IOCs
    enriched = vt.bulk_enrich_iocs(extracted_iocs)
    
    # Display results
    print("IP Addresses:")
    for ip_data in enriched['ips']:
        print(f"  {vt.get_summary(ip_data)}")
        if ip_data.get('malicious', 0) > 0:
            print(f"    ⚠️ Country: {ip_data.get('country')}, ASN: {ip_data.get('asn')}")
    
    print("\nDomains:")
    for domain_data in enriched['domains']:
        print(f"  {vt.get_summary(domain_data)}")
        if domain_data.get('malicious', 0) > 0:
            print(f"    ⚠️ Reputation: {domain_data.get('reputation')}")
    
    print("\nFile Hashes:")
    for hash_data in enriched['hashes']:
        print(f"  {vt.get_summary(hash_data)}")
        if hash_data.get('malicious', 0) > 0:
            print(f"    🚨 {hash_data.get('malicious')}/{hash_data.get('total_engines')} engines detected as malicious")
            print(f"    File type: {hash_data.get('file_type')}")
    
    print("\n" + "=" * 60)


def main():
    """Run SIEM and Threat Intelligence integration examples"""
    print("\n🔨 CyberXP Integration Examples\n")
    
    # Check configuration
    if FeatureConfig.INTEGRATIONS.get("splunk"):
        example_splunk_workflow()
    else:
        print("ℹ️  Splunk integration disabled in config")
        print("   Set INTEGRATIONS['splunk'] = True and configure credentials\n")
    
    print()
    
    if FeatureConfig.INTEGRATIONS.get("sentinel"):
        example_sentinel_workflow()
    else:
        print("ℹ️  Sentinel integration disabled in config")
        print("   Set INTEGRATIONS['sentinel'] = True and configure credentials\n")
    
    print()
    
    if FeatureConfig.INTEGRATIONS.get("virustotal"):
        example_virustotal_workflow()
    else:
        print("ℹ️  VirusTotal integration disabled in config")
        print("   Set INTEGRATIONS['virustotal'] = True and get API key\n")
    
    print("\n" + "=" * 60)
    print("SETUP INSTRUCTIONS")
    print("=" * 60)
    print("""
To enable integrations:

1. Get API keys/credentials:
   
   VirusTotal (FREE):
   - Sign up: https://www.virustotal.com/gui/join-us
   - Get API key from account settings
   - Free tier: 4 requests/min, 500/day
   
   Splunk (Enterprise/Free):
   - Get HEC token from Splunk admin
   - Or use Splunk Free (500MB/day)
   
   Sentinel (Azure):
   - Create service principal in Azure AD
   - Get workspace ID and credentials

2. Set environment variables:
   
   export VIRUSTOTAL_API_KEY="your-api-key"
   export SPLUNK_HOST="splunk.company.com"
   export SPLUNK_TOKEN="your-splunk-token"
   export SENTINEL_WORKSPACE_ID="your-workspace-id"
   # ... (see config.py for all options)

3. Enable integrations in src/config.py:
   INTEGRATIONS['virustotal'] = True
   INTEGRATIONS['splunk'] = True
   INTEGRATIONS['sentinel'] = True

4. Run this script:
   python example_siem_integration.py

PRICING:
- VirusTotal: FREE (4 req/min) or Premium ($$$)
- CyberXP: FREE (open source)
- Splunk/Sentinel: Enterprise products (companies usually have them)
""")


if __name__ == "__main__":
    main()

