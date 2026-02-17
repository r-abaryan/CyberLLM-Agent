"""
Collaborative Agent System
Agents work together in a pipeline for comprehensive threat assessment.

Optimizations:
- Optionally skip or downgrade analysis for low/medium severity to save LLM calls.
- Optionally run triage + analysis in parallel to reduce end-to-end latency.
"""

from typing import Dict, Any
from concurrent.futures import ThreadPoolExecutor

from .triage_agent import TriageAgent
from .analysis_agent import AnalysisAgent


class CollaborativeAgentSystem:
    """
    Multi-stage agent pipeline where agents work together:
    1. Triage agent assesses severity and containment
    2. Analysis agent provides deep investigation (if severity warrants it)

    Parameters
    ----------
    llm:
        Shared LLM instance used by both agents.
    min_analysis_severity:
        Minimum severity at which full analysis should be run.
        Order: Info < Low < Medium < High < Critical.
        Default is "Medium".
    enable_parallel:
        If True, triage and analysis are executed in parallel. This improves
        latency at the cost of always paying for both LLM calls.
        Default is False (sequential).
    """

    _SEVERITY_ORDER = {
        "info": 0,
        "informational": 0,
        "low": 1,
        "medium": 2,
        "moderate": 2,
        "high": 3,
        "critical": 4,
    }
    
    def __init__(
        self,
        llm,
        min_analysis_severity: str = "Medium",
        enable_parallel: bool = False,
    ):
        self.triage_agent = TriageAgent(llm=llm)
        self.analysis_agent = AnalysisAgent(llm=llm)
        self.llm = llm
        self.min_analysis_severity = min_analysis_severity
        self.enable_parallel = enable_parallel

    def _severity_rank(self, severity: str) -> int:
        """Map severity label to a comparable rank."""
        if not severity:
            return self._SEVERITY_ORDER["medium"]
        return self._SEVERITY_ORDER.get(str(severity).lower(), self._SEVERITY_ORDER["medium"])

    def _should_run_analysis(self, severity: str, force_full_analysis: bool) -> bool:
        """Decide whether to run full analysis based on severity/config."""
        if force_full_analysis:
            return True
        return self._severity_rank(severity) >= self._severity_rank(self.min_analysis_severity)
    
    def assess(
        self,
        threat: str,
        context: str = "",
        *,
        force_full_analysis: bool = False,
        run_parallel: bool | None = None,
    ) -> Dict[str, Any]:
        """
        Run collaborative assessment.

        Parameters
        ----------
        threat:
            Threat description.
        context:
            Optional additional context.
        force_full_analysis:
            If True, always run the analysis agent regardless of severity.
        run_parallel:
            If True, attempt to run triage + analysis in parallel (using threads).
            If None, fall back to the system default (self.enable_parallel).

        Returns
        -------
        dict
            Combined output from both agents, plus individual agent outputs
            and detected severity.
        """
        if run_parallel is None:
            run_parallel = self.enable_parallel

        if run_parallel and self.llm is not None:
            # Parallel mode: improves latency for high-severity cases.
            with ThreadPoolExecutor(max_workers=2) as executor:
                triage_future = executor.submit(self.triage_agent.process, threat, context)
                analysis_future = executor.submit(self.analysis_agent.process, threat, context)

                triage_result = triage_future.result()
                analysis_result = analysis_future.result()
        else:
            # Sequential mode: can skip analysis for low/medium severity.
            triage_result = self.triage_agent.process(threat, context)
            severity = triage_result.get("severity", "Medium")

            if self._should_run_analysis(severity, force_full_analysis):
                analysis_result = self.analysis_agent.process(threat, context)
            else:
                # Skipped analysis to save LLM calls
                analysis_result = {
                    "agent": self.analysis_agent.name,
                    "output": (
                        "Analysis skipped based on severity threshold "
                        f"({severity}). Adjust CollaborativeAgentSystem.min_analysis_severity "
                        "or pass force_full_analysis=True to override."
                    ),
                    "agent_type": "analysis_skipped",
                }

        triage_output = triage_result["output"]
        severity = triage_result.get("severity", "Medium")
        analysis_output = analysis_result["output"]

        # Combine outputs - Create a cohesive assessment report
        combined_output = self._combine_outputs(triage_output, analysis_output, severity)

        return {
            "agent": "Collaborative Agents (Triage + Analysis)",
            "output": combined_output,
            "triage_output": triage_output,
            "analysis_output": analysis_output,
            "severity": severity,
            "agent_type": "collaborative",
            "analysis_skipped": analysis_result.get("agent_type") == "analysis_skipped",
        }
    
    def _combine_outputs(self, triage: str, analysis: str, severity: str) -> str:
        """Combine outputs from both agents into cohesive assessment"""
        
        combined = f"""# Threat Assessment Report

## Executive Summary
{self._extract_severity_section(triage)}

## Immediate Response (Triage)
{self._extract_containment_section(triage)}

## Detailed Analysis
{self._extract_analysis_section(analysis)}

## Recovery & Prevention
{self._extract_recovery_section(analysis)}
{self._extract_prevention_section(analysis)}

---
Assessment generated by collaborative agent system (Triage + Analysis)
"""
        return combined.strip()
    
    def _extract_severity_section(self, triage_output: str) -> str:
        """Extract severity and reasoning from triage"""
        lines = []
        in_section = False
        
        for line in triage_output.split('\n'):
            line_lower = line.lower().strip()
            if 'severity' in line_lower:
                in_section = True
                lines.append(line)
            elif in_section and ('immediate' in line_lower or 'escalate' in line_lower):
                break
            elif in_section:
                lines.append(line)
        
        return '\n'.join(lines) if lines else "Severity assessment in progress..."
    
    def _extract_containment_section(self, triage_output: str) -> str:
        """Extract containment actions from triage"""
        lines = []
        in_section = False
        
        for line in triage_output.split('\n'):
            line_lower = line.lower().strip()
            if 'immediate' in line_lower or 'containment' in line_lower:
                in_section = True
                lines.append(line)
            elif in_section and ('escalate' in line_lower or 'reasoning' in line_lower):
                # Also capture escalation
                if 'escalate' in line_lower:
                    lines.append(line)
                break
            elif in_section:
                lines.append(line)
        
        return '\n'.join(lines) if lines else "Containment recommendations pending..."
    
    def _extract_analysis_section(self, analysis_output: str) -> str:
        """Extract threat analysis from analysis agent"""
        lines = []
        in_section = False
        
        for line in analysis_output.split('\n'):
            line_lower = line.lower().strip()
            if 'threat analysis' in line_lower or 'indicators of compromise' in line_lower:
                in_section = True
                lines.append(line)
            elif in_section and ('recovery' in line_lower or 'prevention' in line_lower):
                break
            elif in_section:
                lines.append(line)
        
        return '\n'.join(lines) if lines else analysis_output.split('\n\n')[0]
    
    def _extract_recovery_section(self, analysis_output: str) -> str:
        """Extract recovery steps from analysis"""
        lines = []
        in_section = False
        
        for line in analysis_output.split('\n'):
            line_lower = line.lower().strip()
            if 'recovery' in line_lower:
                in_section = True
                lines.append(line)
            elif in_section and 'prevention' in line_lower:
                break
            elif in_section:
                lines.append(line)
        
        return '\n'.join(lines) if lines else "Recovery steps to be determined..."
    
    def _extract_prevention_section(self, analysis_output: str) -> str:
        """Extract prevention measures from analysis"""
        lines = []
        in_section = False
        
        for line in analysis_output.split('\n'):
            line_lower = line.lower().strip()
            if 'prevention' in line_lower or 'preventive' in line_lower:
                in_section = True
                lines.append(line)
            elif in_section:
                lines.append(line)
        
        return '\n'.join(lines) if lines else "Prevention measures to be determined..."


if __name__ == "__main__":
    """Test collaborative agents"""
    print("Collaborative Agent System Test\n")
    print("="*60)
    
    # Without LLM, will use fallback methods
    collab_system = CollaborativeAgentSystem(llm=None)
    
    test_threat = "Ransomware detected encrypting files on file server"
    test_context = "Production environment, 50 workstations affected"
    
    result = collab_system.assess(test_threat, test_context)
    
    print(f"Agent: {result['agent']}")
    print(f"Severity: {result['severity']}")
    print("\n" + "="*60)
    print("Combined Output:")
    print("="*60)
    print(result['output'])
    print("\n" + "="*60)
    print("\nThis demonstrates how Triage + Analysis work together")
    print("In production, the LLM would generate detailed, contextual responses")

