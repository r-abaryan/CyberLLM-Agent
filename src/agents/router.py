"""
Agent Router
Automatically routes threats to the appropriate agent
"""

from typing import Dict, Any, Literal
from .triage_agent import TriageAgent
from .analysis_agent import AnalysisAgent


AgentType = Literal["triage", "analysis", "auto"]


class AgentRouter:
    """Routes threats to appropriate specialized agent"""
    
    def __init__(self, llm=None):
        self.llm = llm
        self.triage_agent = TriageAgent(llm=llm)
        self.analysis_agent = AnalysisAgent(llm=llm)
    
    def route(self, threat: str, context: str = "", agent_type: AgentType = "auto") -> Dict[str, Any]:
        """
        Route threat to appropriate agent
        
        Args:
            threat: Threat description
            context: Additional context
            agent_type: 'triage', 'analysis', or 'auto' (auto-select)
        
        Returns:
            Assessment from selected agent
        """
        
        if agent_type == "triage":
            return self.triage_agent.process(threat, context)
        elif agent_type == "analysis":
            return self.analysis_agent.process(threat, context)
        else:
            selected_agent = self._auto_route(threat, context)
            return selected_agent.process(threat, context)
    
    def _auto_route(self, threat: str, context: str = ""):
        """
        Automatically select agent based on keywords and intent
        
        Logic:
        - Use TRIAGE for: initial alerts, quick checks, severity questions
        - Use ANALYSIS for: investigation requests, IOC extraction, detailed forensics
        """
        
        combined_text = (threat + " " + context).lower()
        
        triage_keywords = [
            "alert", "severity", "urgent", "quick", "triage",
            "escalate", "contain", "immediately", "stop", "block"
        ]
        
        analysis_keywords = [
            "analyze", "investigate", "understand", "explain", "how did",
            "ioc", "indicator", "forensics", "root cause", "attack chain",
            "mitre", "technique", "recover", "restore", "prevent"
        ]
        
        triage_score = sum(1 for kw in triage_keywords if kw in combined_text)
        analysis_score = sum(1 for kw in analysis_keywords if kw in combined_text)
        
        if triage_score > analysis_score:
            selected = self.triage_agent
            reason = "triage_keywords"
        elif analysis_score > triage_score:
            selected = self.analysis_agent
            reason = "analysis_keywords"
        else:
            if len(threat) < 100:
                selected = self.triage_agent
                reason = "short_description"
            else:
                selected = self.analysis_agent
                reason = "detailed_description"
        
        print(f"🤖 Auto-routed to: {selected.name} (reason: {reason})")
        return selected
    
    def get_available_agents(self) -> Dict[str, str]:
        """Get list of available agents and their roles"""
        return {
            "triage": f"{self.triage_agent.name} - {self.triage_agent.role}",
            "analysis": f"{self.analysis_agent.name} - {self.analysis_agent.role}"
        }


if __name__ == "__main__":
    print("Testing Agent Router\n")
    router = AgentRouter()
    
    print("Available Agents:")
    for key, desc in router.get_available_agents().items():
        print(f"  - {key}: {desc}")
    
    print("\n" + "="*60)
    print("Test Case 1: Urgent alert (should route to Triage)")
    print("="*60)
    result1 = router.route(
        threat="Urgent: Suspicious login detected from unusual location",
        agent_type="auto"
    )
    print(f"Agent used: {result1['agent']}")
    print(f"Output:\n{result1['output'][:200]}...")
    
    print("\n" + "="*60)
    print("Test Case 2: Investigation request (should route to Analysis)")
    print("="*60)
    result2 = router.route(
        threat="Need to investigate ransomware attack. Extract all IOCs and understand the attack chain.",
        agent_type="auto"
    )
    print(f"Agent used: {result2['agent']}")
    print(f"Output:\n{result2['output'][:200]}...")

