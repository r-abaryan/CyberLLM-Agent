"""
Triage Agent
Quick severity assessment and initial response recommendations
"""

from typing import Dict, Any
from .base_agent import BaseAgent


class TriageAgent(BaseAgent):
    """
    Dual responsibility:
    1. Fast severity classification
    2. Immediate containment recommendations
    """
    
    def __init__(self, llm=None):
        super().__init__(
            name="Triage & Containment Agent",
            role="First Responder",
            llm=llm
        )
    
    def get_system_prompt(self) -> str:
        return """You are a first responder performing triage and containment.

Your dual responsibility:
1. Quickly assess severity
2. Provide immediate containment steps

Output Format:

**SEVERITY:** [Critical/High/Medium/Low/Info]

**IMMEDIATE CONTAINMENT:**
- Specific action to stop/limit the threat NOW
- Example: "Isolate host X from network"
- Example: "Disable user account Y"
- Keep it actionable (commands if possible)

**ESCALATE TO:** [Analysis Team / Security Manager / CISO / None]

**REASONING:**
- Why this severity?
- Why these containment steps?

Be direct and actionable. Speed is critical."""
    
    def process(self, threat: str, context: str = "") -> Dict[str, Any]:
        """Quick triage assessment"""
        
        prompt = self.format_prompt(threat, context)
        
        if self.llm:
            response = self.llm.invoke(prompt)
            output = response if isinstance(response, str) else response.get("output", str(response))
        else:
            output = self._fallback_triage(threat)
        
        severity = self._extract_severity(output)
        
        return {
            "agent": self.name,
            "severity": severity,
            "output": output,
            "agent_type": "triage"
        }
    
    def _extract_severity(self, text: str) -> str:
        """Extract severity from response"""
        text_lower = text.lower()
        
        if "critical" in text_lower:
            return "Critical"
        elif "high" in text_lower:
            return "High"
        elif "medium" in text_lower:
            return "Medium"
        elif "low" in text_lower:
            return "Low"
        else:
            return "Info"
    
    def _fallback_triage(self, threat: str) -> str:
        """Fallback when no LLM available"""
        keywords_critical = ["ransomware", "data breach", "root access", "domain admin"]
        keywords_high = ["malware", "exploit", "unauthorized access", "lateral movement"]
        keywords_medium = ["suspicious", "anomaly", "unusual", "phishing"]
        
        threat_lower = threat.lower()
        
        if any(k in threat_lower for k in keywords_critical):
            severity = "Critical"
            escalate = "CISO"
            containment = "- Isolate affected systems immediately\n- Block related network connections\n- Preserve evidence for forensics"
        elif any(k in threat_lower for k in keywords_high):
            severity = "High"
            escalate = "Security Manager"
            containment = "- Isolate compromised host\n- Disable affected user accounts\n- Check for lateral movement"
        elif any(k in threat_lower for k in keywords_medium):
            severity = "Medium"
            escalate = "Analysis Team"
            containment = "- Monitor affected systems\n- Collect additional logs\n- Verify suspicious activity"
        else:
            severity = "Low"
            escalate = "None"
            containment = "- Document findings\n- Continue monitoring\n- Update detection rules if needed"
        
        return f"""**SEVERITY:** {severity}

**IMMEDIATE CONTAINMENT:**
{containment}

**ESCALATE TO:** {escalate}

**REASONING:**
Pattern matching indicates {severity.lower()} severity threat. Containment steps aim to limit impact while preserving evidence."""

