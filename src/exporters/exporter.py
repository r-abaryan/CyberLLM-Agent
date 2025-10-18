"""
Unified Exporter
Export assessments to multiple formats from one module
"""

import csv
import json
from datetime import datetime
from typing import Dict, Any, Literal
from io import StringIO
import uuid


ExportFormat = Literal["json", "csv", "stix"]


class ThreatExporter:
    """Unified exporter for threat assessments"""
    
    def __init__(self):
        self.timestamp = datetime.now().isoformat()
    
    def export(self, 
               assessment: Dict[str, Any], 
               iocs: Dict[str, Any], 
               format: ExportFormat = "json",
               pretty: bool = True) -> str:
        """
        Export assessment to specified format
        
        Args:
            assessment: Threat assessment dict
            iocs: IOCs dict from extract_iocs()
            format: 'json', 'csv', or 'stix'
            pretty: Pretty-print output (for JSON/STIX)
        
        Returns:
            Formatted string
        """
        
        if format == "json":
            return self._export_json(assessment, iocs, pretty)
        elif format == "csv":
            return self._export_csv(assessment, iocs)
        elif format == "stix":
            return self._export_stix(assessment, iocs, pretty)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def save(self, 
             assessment: Dict[str, Any], 
             iocs: Dict[str, Any], 
             filepath: str,
             format: ExportFormat = None):
        """
        Save assessment to file
        
        Args:
            assessment: Threat assessment dict
            iocs: IOCs dict
            filepath: Output file path
            format: Export format (auto-detected from extension if None)
        """
        
        if format is None:
            if filepath.endswith(".json"):
                format = "json"
            elif filepath.endswith(".csv"):
                format = "csv"
            elif filepath.endswith(".stix") or filepath.endswith(".stix2"):
                format = "stix"
            else:
                format = "json"
        
        content = self.export(assessment, iocs, format)
        
        with open(filepath, "w", encoding="utf-8", newline="" if format == "csv" else None) as f:
            f.write(content)
    
    def _export_json(self, assessment: Dict[str, Any], iocs: Dict[str, Any], pretty: bool = True) -> str:
        """Export to JSON format"""
        
        export_data = {
            "metadata": {
                "generated_at": self.timestamp,
                "format_version": "1.0",
                "source": "CyberXP Threat Assessment",
                "format": "json"
            },
            "assessment": {
                "threat": assessment.get("threat", ""),
                "context": assessment.get("context", ""),
                "severity": assessment.get("severity", "Unknown"),
                "output": assessment.get("output", ""),
                "agent": assessment.get("agent", "Unknown")
            },
            "indicators_of_compromise": {
                "ips": iocs.get("ips", []),
                "domains": iocs.get("domains", []),
                "urls": iocs.get("urls", []),
                "hashes": iocs.get("hashes", []),
                "emails": iocs.get("emails", []),
                "summary": {
                    "total_iocs": (
                        len(iocs.get("ips", [])) +
                        len(iocs.get("domains", [])) +
                        len(iocs.get("urls", [])) +
                        len(iocs.get("hashes", [])) +
                        len(iocs.get("emails", []))
                    ),
                    "by_type": {
                        "ips": len(iocs.get("ips", [])),
                        "domains": len(iocs.get("domains", [])),
                        "urls": len(iocs.get("urls", [])),
                        "hashes": len(iocs.get("hashes", [])),
                        "emails": len(iocs.get("emails", []))
                    }
                }
            }
        }
        
        if pretty:
            return json.dumps(export_data, indent=2, ensure_ascii=False)
        else:
            return json.dumps(export_data, ensure_ascii=False)
    
    def _export_csv(self, assessment: Dict[str, Any], iocs: Dict[str, Any]) -> str:
        """Export to CSV format"""
        
        output = StringIO()
        writer = csv.writer(output)
        
        writer.writerow(["=== THREAT ASSESSMENT ==="])
        writer.writerow(["Field", "Value"])
        writer.writerow(["Timestamp", self.timestamp])
        writer.writerow(["Threat", assessment.get("threat", "N/A")])
        writer.writerow(["Severity", assessment.get("severity", "Unknown")])
        writer.writerow(["Context", assessment.get("context", "N/A")])
        writer.writerow(["Agent", assessment.get("agent", "Unknown")])
        
        ip_count = len(iocs.get("ips", []))
        domain_count = len(iocs.get("domains", []))
        url_count = len(iocs.get("urls", []))
        hash_count = len(iocs.get("hashes", []))
        email_count = len(iocs.get("emails", []))
        total_count = ip_count + domain_count + url_count + hash_count + email_count
        
        writer.writerow([])
        writer.writerow(["=== IOC SUMMARY ==="])
        writer.writerow(["IOC Type", "Count"])
        writer.writerow(["IPs", ip_count])
        writer.writerow(["Domains", domain_count])
        writer.writerow(["URLs", url_count])
        writer.writerow(["Hashes", hash_count])
        writer.writerow(["Emails", email_count])
        writer.writerow(["Total", total_count])
        
        if total_count > 0:
            writer.writerow([])
            writer.writerow(["=== INDICATORS OF COMPROMISE ==="])
            writer.writerow(["Type", "Value", "Context", "Enrichment Status"])
            
            for ioc in iocs.get("ips", []):
                enrichment = ioc.get("enrichment", {})
                status = "Malicious" if enrichment.get("is_malicious") else "Clean" if enrichment.get("status") == "success" else "Not checked"
                writer.writerow(["IP", ioc.get("value", ""), ioc.get("context", ""), status])
            
            for ioc in iocs.get("domains", []):
                enrichment = ioc.get("enrichment", {})
                status = "Malicious" if enrichment.get("is_malicious") else "Clean" if enrichment.get("status") == "success" else "Not checked"
                writer.writerow(["Domain", ioc.get("value", ""), ioc.get("context", ""), status])
            
            for ioc in iocs.get("urls", []):
                enrichment = ioc.get("enrichment", {})
                status = "Malicious" if enrichment.get("is_malicious") else "Clean" if enrichment.get("status") == "success" else "Not checked"
                writer.writerow(["URL", ioc.get("value", ""), ioc.get("context", ""), status])
            
            for ioc in iocs.get("hashes", []):
                hash_type = ioc.get("hash_type", "unknown")
                enrichment = ioc.get("enrichment", {})
                status = "Malicious" if enrichment.get("is_malicious") else "Clean" if enrichment.get("status") == "success" else "Not checked"
                writer.writerow([f"Hash-{hash_type.upper()}", ioc.get("value", ""), ioc.get("context", ""), status])
            
            for ioc in iocs.get("emails", []):
                writer.writerow(["Email", ioc.get("value", ""), ioc.get("context", ""), "N/A"])
        
        writer.writerow([])
        writer.writerow(["=== ASSESSMENT OUTPUT ==="])
        output_lines = assessment.get("output", "").split("\n")
        for line in output_lines[:50]:
            writer.writerow([line])
        
        return output.getvalue()
    
    def _export_stix(self, assessment: Dict[str, Any], iocs: Dict[str, Any], pretty: bool = True) -> str:
        """Export to STIX 2.1 format"""
        
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        bundle_id = f"bundle--{uuid.uuid4()}"
        
        objects = []
        
        threat_actor_id = f"threat-actor--{uuid.uuid4()}"
        objects.append({
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": threat_actor_id,
            "created": timestamp,
            "modified": timestamp,
            "name": "Unknown Threat Actor",
            "description": assessment.get("threat", ""),
            "threat_actor_types": ["unknown"],
            "sophistication": "unknown",
            "resource_level": "unknown",
            "primary_motivation": "unknown"
        })
        
        incident_id = f"incident--{uuid.uuid4()}"
        objects.append({
            "type": "incident",
            "spec_version": "2.1",
            "id": incident_id,
            "created": timestamp,
            "modified": timestamp,
            "name": assessment.get("threat", "Security Incident")[:100],
            "description": assessment.get("output", "")[:500],
        })
        
        for ioc in iocs.get("ips", []):
            indicator_id = f"indicator--{uuid.uuid4()}"
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": timestamp,
                "modified": timestamp,
                "name": f"Malicious IP: {ioc['value']}",
                "description": ioc.get("context", ""),
                "pattern": f"[ipv4-addr:value = '{ioc['value']}']",
                "pattern_type": "stix",
                "valid_from": timestamp,
                "indicator_types": ["malicious-activity"]
            })
        
        for ioc in iocs.get("domains", []):
            indicator_id = f"indicator--{uuid.uuid4()}"
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": timestamp,
                "modified": timestamp,
                "name": f"Malicious Domain: {ioc['value']}",
                "description": ioc.get("context", ""),
                "pattern": f"[domain-name:value = '{ioc['value']}']",
                "pattern_type": "stix",
                "valid_from": timestamp,
                "indicator_types": ["malicious-activity"]
            })
        
        for ioc in iocs.get("urls", []):
            indicator_id = f"indicator--{uuid.uuid4()}"
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": timestamp,
                "modified": timestamp,
                "name": f"Malicious URL: {ioc['value'][:50]}",
                "description": ioc.get("context", ""),
                "pattern": f"[url:value = '{ioc['value']}']",
                "pattern_type": "stix",
                "valid_from": timestamp,
                "indicator_types": ["malicious-activity"]
            })
        
        for ioc in iocs.get("hashes", []):
            hash_type = ioc.get("hash_type", "MD5").upper()
            indicator_id = f"indicator--{uuid.uuid4()}"
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": timestamp,
                "modified": timestamp,
                "name": f"Malicious File Hash: {ioc['value'][:16]}...",
                "description": ioc.get("context", ""),
                "pattern": f"[file:hashes.{hash_type} = '{ioc['value']}']",
                "pattern_type": "stix",
                "valid_from": timestamp,
                "indicator_types": ["malicious-activity"]
            })
        
        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects
        }
        
        if pretty:
            return json.dumps(bundle, indent=2)
        else:
            return json.dumps(bundle)


if __name__ == "__main__":
    exporter = ThreatExporter()
    
    test_assessment = {
        "threat": "Ransomware attack detected on file server",
        "severity": "Critical",
        "context": "Files encrypted with .locked extension",
        "output": "Immediate isolation and backup recovery recommended",
        "agent": "Triage & Containment Agent"
    }
    
    test_iocs = {
        "ips": [
            {"value": "10.0.0.50", "context": "Infected server"},
            {"value": "192.168.1.100", "context": "C2 server"}
        ],
        "domains": [{"value": "ransom-pay.onion", "context": "Payment site"}],
        "urls": [],
        "hashes": [{"value": "d41d8cd98f00b204e9800998ecf8427e", "hash_type": "md5", "context": "Ransomware executable"}],
        "emails": [{"value": "attacker@evil.com", "context": "Contact email"}]
    }
    
    print("=" * 60)
    print("JSON Export")
    print("=" * 60)
    print(exporter.export(test_assessment, test_iocs, format="json")[:300])
    print("...\n")
    
    print("=" * 60)
    print("CSV Export")
    print("=" * 60)
    print(exporter.export(test_assessment, test_iocs, format="csv")[:500])
    print("...\n")
    
    print("=" * 60)
    print("STIX Export")
    print("=" * 60)
    print(exporter.export(test_assessment, test_iocs, format="stix")[:400])
    print("...")

