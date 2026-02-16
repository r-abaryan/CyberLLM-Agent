"""
Analysis & Recovery Agent
Deep investigation + recovery/prevention recommendations
"""

from typing import Dict, Any
from .base_agent import BaseAgent


class AnalysisAgent(BaseAgent):
    """
    Dual responsibility:
    1. Deep technical investigation
    2. Recovery and prevention guidance
    """
    
    def __init__(self, llm=None):
        super().__init__(
            name="Analysis & Recovery Agent",
            role="Security Analyst",
            llm=llm
        )
    
    def get_system_prompt(self) -> str:
        """
        Return the system prompt for the analysis agent.
        
        NOTE: This prompt is optimized for concise, non‑redundant outputs to
        reduce token usage while keeping responses actionable.
        """
        return """You are a security analyst performing deep investigation and recovery planning.
Focus on understanding the threat technically and providing clear recovery and prevention steps.

Always structure your answer using these sections and EXACT headings:

**THREAT ANALYSIS:**
- Attack type and vector
- How it likely succeeded

**INDICATORS OF COMPROMISE (IOCs):**
- IPs, domains, file hashes, URLs
- Use clear labels, e.g., `IP: 1.2.3.4`, `Domain: evil.com`

**MITRE ATT&CK:**
- Relevant techniques, e.g., T1566, T1059 (short list only)

**RECOVERY STEPS:**
1. System restoration actions
2. Verification checks
3. Data recovery if needed

**PREVENTION MEASURES:**
- Security controls to implement
- Policy or process changes
- Detection rules to add

CONSTRAINTS (be concise):
- Max 5 bullet points per section.
- Each bullet should be a single short sentence.
- Avoid repeating the same idea across sections.
- Prefer concrete, tool‑agnostic actions over long explanations.

Think end-to-end: investigate → recover → prevent, but keep the output tight and highly actionable."""
    
    def process(self, threat: str, context: str = "") -> Dict[str, Any]:
        """Detailed threat analysis"""
        
        prompt = self.format_prompt(threat, context)
        
        if self.llm:
            response = self.llm.invoke(prompt)
            output = response if isinstance(response, str) else response.get("output", str(response))
        else:
            output = self._fallback_analysis(threat)
        
        return {
            "agent": self.name,
            "output": output,
            "agent_type": "analysis"
        }
    
    def _fallback_analysis(self, threat: str) -> str:
        """Fallback when no LLM available"""
        return f"""**THREAT ANALYSIS:**
- Incident type: Based on threat indicators
- Attack vector: Requires log analysis
- Success factors: Security control gaps

**INDICATORS OF COMPROMISE (IOCs):**
- Extract from logs and forensic analysis
- Check threat description for embedded IOCs: {threat[:200]}...
- Network connections, file hashes, registry changes

**MITRE ATT&CK:** T1566 (Phishing), T1059 (Command Execution), T1071 (Application Layer Protocol)

**RECOVERY STEPS:**
1. Restore systems from clean backups
2. Verify system integrity and patch levels
3. Reset compromised credentials
4. Scan for persistence mechanisms
5. Validate normal operations

**PREVENTION MEASURES:**
- Implement EDR/XDR solution
- Enable MFA on all accounts
- Update security awareness training
- Add detection rules for similar attacks
- Conduct vulnerability assessment
- Review and update access controls

Note: Full analysis with LLM provides threat-specific recommendations."""

