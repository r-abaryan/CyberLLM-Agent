"""
Base Agent Class
All specialized agents inherit from this
"""

from abc import ABC, abstractmethod
from typing import Dict, Any


class BaseAgent(ABC):
    """Abstract base class for all security agents"""
    
    def __init__(self, name: str, role: str, llm=None):
        self.name = name
        self.role = role
        self.llm = llm
    
    @abstractmethod
    def get_system_prompt(self) -> str:
        """Return the specialized system prompt for this agent"""
        pass
    
    @abstractmethod
    def process(self, threat: str, context: str = "") -> Dict[str, Any]:
        """
        Process a threat and return assessment
        
        Args:
            threat: Threat description
            context: Additional context
        
        Returns:
            Dictionary with assessment results
        """
        pass
    
    def format_prompt(self, threat: str, context: str = "") -> str:
        """Format the complete prompt for the LLM"""
        system = self.get_system_prompt()
        
        user_input = f"""Threat Description: {threat}

Additional Context: {context if context else "None provided"}

Provide your assessment:"""
        
        return f"{system}\n\n{user_input}"
    
    def __str__(self):
        return f"{self.name} ({self.role})"

