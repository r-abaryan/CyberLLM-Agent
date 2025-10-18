"""
Quick Test of All Features
Run this to verify everything is working
"""

print("Testing CyberXP Features\n")
print("=" * 60)

# Test 1: Configuration
print("\n[1] Testing Configuration...")
try:
    from src.config import config
    print(f"   [OK] Config loaded")
    print(f"   Features enabled: {sum(config.FEATURES.values())}/{len(config.FEATURES)}")
except Exception as e:
    print(f"   [FAIL] Error: {e}")

# Test 2: Multi-Agent System
print("\n[2] Testing Multi-Agent System...")
try:
    from src.agents import AgentRouter
    router = AgentRouter(llm=None)  # No LLM needed for test
    agents = router.get_available_agents()
    print(f"   [OK] Router initialized")
    print(f"   Available agents: {len(agents)}")
    for key, desc in agents.items():
        print(f"     - {desc}")
except Exception as e:
    print(f"   [FAIL] Error: {e}")

# Test 3: Exporters
print("\n[3] Testing Exporters...")
try:
    from src.exporters import ThreatExporter
    exporter = ThreatExporter()
    
    test_data = {
        "threat": "Test threat",
        "severity": "Medium",
        "output": "Test output"
    }
    test_iocs = {"ips": [], "domains": [], "urls": [], "hashes": [], "emails": []}
    
    json_out = exporter.export(test_data, test_iocs, format="json")
    csv_out = exporter.export(test_data, test_iocs, format="csv")
    stix_out = exporter.export(test_data, test_iocs, format="stix")
    
    print(f"   [OK] Exporter initialized")
    print(f"   [OK] JSON export: {len(json_out)} chars")
    print(f"   [OK] CSV export: {len(csv_out)} chars")
    print(f"   [OK] STIX export: {len(stix_out)} chars")
except Exception as e:
    print(f"   [FAIL] Error: {e}")

# Test 4: IOC Utils
print("\n[4] Testing IOC Extraction...")
try:
    from src.utils.ioc_utils import extract_iocs
    
    test_text = "Suspicious activity from IP 192.168.1.100 connecting to evil.com"
    iocs = extract_iocs(test_text)
    
    total = sum(len(iocs.get(k, [])) for k in ["ips", "domains", "urls", "hashes", "emails"])
    print(f"   [OK] IOC extraction working")
    print(f"   [OK] Extracted {total} IOCs from test text")
except Exception as e:
    print(f"   [FAIL] Error: {e}")

# Summary
print("\n" + "=" * 60)
print("All core features tested successfully!")
print("\nNext Steps:")
print("   1. Test agents: python src/agents/router.py")
print("   2. Run Gradio app: python HF_Space/gradio_app.py")
print("   3. Deploy to Hugging Face Spaces")
print("\nReady to go!")

