"""
Custom Agent - User-defined agents with custom prompts
Safety features: Input validation, sanitization, length limits
"""

from typing import Dict, Any
from .base_agent import BaseAgent
import re


class CustomAgent(BaseAgent):
    """
    Custom agent that users can create with their own prompts.
    Includes safety checks to prevent prompt injection and resource abuse.
    """
    
    MAX_PROMPT_LENGTH = 4000
    MAX_NAME_LENGTH = 100
    MAX_ROLE_LENGTH = 200
    
    def __init__(self, name: str, role: str, system_prompt: str, llm=None, few_shot_examples: str = ""):
        """
        Initialize a custom agent with validation.
        
        Args:
            name: Agent name (max 100 chars)
            role: Agent role/specialty (max 200 chars)
            system_prompt: Custom system prompt (max 4000 chars)
            llm: Language model instance
            few_shot_examples: Optional few-shot examples
        
        Raises:
            ValueError: If inputs fail validation
        """
        # Validate and sanitize inputs
        name = self._validate_name(name)
        role = self._validate_role(role)
        system_prompt = self._validate_prompt(system_prompt)
        few_shot_examples = self._validate_prompt(few_shot_examples) if few_shot_examples else ""
        
        super().__init__(name, role, llm)
        self._system_prompt = system_prompt
        self._few_shot_examples = few_shot_examples
    
    def _validate_name(self, name: str) -> str:
        """Validate and sanitize agent name"""
        if not name or not isinstance(name, str):
            raise ValueError("Agent name must be a non-empty string")
        
        name = name.strip()
        
        if len(name) > self.MAX_NAME_LENGTH:
            raise ValueError(f"Agent name must be <= {self.MAX_NAME_LENGTH} characters")
        
        # Only allow alphanumeric, spaces, hyphens, underscores
        if not re.match(r'^[a-zA-Z0-9\s\-_]+$', name):
            raise ValueError("Agent name can only contain letters, numbers, spaces, hyphens, and underscores")
        
        return name
    
    def _validate_role(self, role: str) -> str:
        """Validate and sanitize role description"""
        if not role or not isinstance(role, str):
            raise ValueError("Agent role must be a non-empty string")
        
        role = role.strip()
        
        if len(role) > self.MAX_ROLE_LENGTH:
            raise ValueError(f"Agent role must be <= {self.MAX_ROLE_LENGTH} characters")
        
        return role
    
    def _validate_prompt(self, prompt: str) -> str:
        """Validate and sanitize system prompt"""
        if not prompt or not isinstance(prompt, str):
            raise ValueError("System prompt must be a non-empty string")
        
        prompt = prompt.strip()
        
        if len(prompt) > self.MAX_PROMPT_LENGTH:
            raise ValueError(f"System prompt must be <= {self.MAX_PROMPT_LENGTH} characters")
        
        # Check for potentially harmful patterns (basic safety)
        dangerous_patterns = [
            r'<script[^>]*>',  # Script tags
            r'javascript:',     # JavaScript protocol
            r'eval\s*\(',      # Eval calls
            r'exec\s*\(',      # Exec calls
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                raise ValueError("System prompt contains potentially unsafe patterns")
        
        return prompt
    
    def get_system_prompt(self) -> str:
        """Return the custom system prompt"""
        base_prompt = f"""You are {self.name}, a specialized cybersecurity agent.
Your role: {self.role}

{self._system_prompt}"""
        
        if self._few_shot_examples:
            base_prompt += f"\n\nExamples:\n{self._few_shot_examples}"
        
        return base_prompt
    
    def process(self, threat: str, context: str = "") -> Dict[str, Any]:
        """
        Process a threat using the custom agent's prompt.
        
        Args:
            threat: Threat description
            context: Additional context
        
        Returns:
            Dictionary with assessment and metadata
        """
        if not self.llm:
            return {
                "agent": self.name,
                "role": self.role,
                "assessment": "Error: No LLM configured for this agent",
                "success": False
            }
        
        try:
            # Build a simple prompt without few-shot contamination
            from langchain_core.prompts import ChatPromptTemplate
            from langchain_core.output_parsers import StrOutputParser
            
            # Create clean system prompt
            system_prompt = f"""You are {self.name}, a specialized cybersecurity agent.
Your role: {self.role}

{self._system_prompt}

IMPORTANT GUIDELINES:
- Be specific and avoid redundancy across sections
- Immediate Actions: ONLY urgent first-response steps (isolate, block, contain)
- Recovery: ONLY restoration and cleanup procedures (restore, verify, validate)
- Preventive Measures: ONLY long-term improvements (policy, training, architecture changes)
- Each item should appear in ONE section only
- Keep items distinct and non-overlapping

Provide a clear, concise assessment based on the threat provided."""
            
            # Build prompt template
            prompt = ChatPromptTemplate.from_messages([
                ("system", system_prompt),
                ("human", "Threat: {threat}\n\nContext: {context}\n\nProvide your assessment:")
            ])
            
            # Create chain
            chain = prompt | self.llm | StrOutputParser()
            
            # Invoke chain
            assessment = chain.invoke({
                "threat": threat.strip(),
                "context": context.strip() if context else "No additional context provided"
            })
            
            return {
                "agent": self.name,
                "role": self.role,
                "assessment": assessment.strip(),
                "success": True
            }
            
        except Exception as e:
            return {
                "agent": self.name,
                "role": self.role,
                "assessment": f"Error during processing: {str(e)}",
                "success": False
            }
    
    def to_dict(self) -> Dict[str, str]:
        """Export agent configuration to dictionary"""
        return {
            "name": self.name,
            "role": self.role,
            "system_prompt": self._system_prompt,
            "few_shot_examples": self._few_shot_examples
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, str], llm=None):
        """Create agent from dictionary"""
        return cls(
            name=data.get("name", ""),
            role=data.get("role", ""),
            system_prompt=data.get("system_prompt", ""),
            llm=llm,
            few_shot_examples=data.get("few_shot_examples", "")
        )

