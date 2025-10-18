"""
Agent Manager - Save, load, and manage custom agents
Handles persistent storage with error handling
"""

import json
import os
from pathlib import Path
from typing import List, Dict, Optional
from .custom_agent import CustomAgent


class AgentManager:
    """
    Manages custom agent lifecycle: create, save, load, list, delete.
    Uses JSON file storage with atomic writes.
    """
    
    def __init__(self, storage_dir: str = "custom_agents"):
        """
        Initialize agent manager.
        
        Args:
            storage_dir: Directory to store agent JSON files
        """
        self.storage_dir = Path(storage_dir)
        self._ensure_storage_dir()
    
    def _ensure_storage_dir(self):
        """Create storage directory if it doesn't exist"""
        try:
            self.storage_dir.mkdir(parents=True, exist_ok=True)
            
            # Create .gitignore to prevent committing user data
            gitignore_path = self.storage_dir / ".gitignore"
            if not gitignore_path.exists():
                gitignore_path.write_text("# Ignore all custom agent files\n*.json\n")
        except Exception as e:
            print(f"Warning: Could not create storage directory: {e}")
    
    def save_agent(self, agent: CustomAgent) -> bool:
        """
        Save a custom agent to disk.
        
        Args:
            agent: CustomAgent instance
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Sanitize filename
            safe_name = self._sanitize_filename(agent.name)
            file_path = self.storage_dir / f"{safe_name}.json"
            
            # Export agent data
            agent_data = agent.to_dict()
            
            # Write atomically (write to temp, then rename)
            temp_path = file_path.with_suffix('.tmp')
            with open(temp_path, 'w', encoding='utf-8') as f:
                json.dump(agent_data, f, indent=2, ensure_ascii=False)
            
            # Atomic rename
            temp_path.replace(file_path)
            
            return True
            
        except Exception as e:
            print(f"Error saving agent '{agent.name}': {e}")
            return False
    
    def load_agent(self, agent_name: str, llm=None) -> Optional[CustomAgent]:
        """
        Load a custom agent from disk.
        
        Args:
            agent_name: Name of the agent to load
            llm: LLM instance to attach to the agent
        
        Returns:
            CustomAgent instance or None if not found/invalid
        """
        try:
            safe_name = self._sanitize_filename(agent_name)
            file_path = self.storage_dir / f"{safe_name}.json"
            
            if not file_path.exists():
                print(f"Agent '{agent_name}' not found")
                return None
            
            with open(file_path, 'r', encoding='utf-8') as f:
                agent_data = json.load(f)
            
            # Create agent from data
            agent = CustomAgent.from_dict(agent_data, llm=llm)
            return agent
            
        except Exception as e:
            print(f"Error loading agent '{agent_name}': {e}")
            return None
    
    def list_agents(self) -> List[Dict[str, str]]:
        """
        List all saved custom agents.
        
        Returns:
            List of dictionaries with agent metadata (name, role)
        """
        agents = []
        
        try:
            for file_path in self.storage_dir.glob("*.json"):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        agent_data = json.load(f)
                    
                    agents.append({
                        "name": agent_data.get("name", "Unknown"),
                        "role": agent_data.get("role", "No role specified"),
                        "filename": file_path.stem
                    })
                except Exception as e:
                    print(f"Error reading {file_path.name}: {e}")
                    continue
        
        except Exception as e:
            print(f"Error listing agents: {e}")
        
        return sorted(agents, key=lambda x: x["name"].lower())
    
    def delete_agent(self, agent_name: str) -> bool:
        """
        Delete a custom agent.
        
        Args:
            agent_name: Name of the agent to delete
        
        Returns:
            True if successful, False otherwise
        """
        try:
            safe_name = self._sanitize_filename(agent_name)
            file_path = self.storage_dir / f"{safe_name}.json"
            
            if not file_path.exists():
                print(f"Agent '{agent_name}' not found")
                return False
            
            file_path.unlink()
            return True
            
        except Exception as e:
            print(f"Error deleting agent '{agent_name}': {e}")
            return False
    
    def agent_exists(self, agent_name: str) -> bool:
        """Check if an agent exists"""
        safe_name = self._sanitize_filename(agent_name)
        file_path = self.storage_dir / f"{safe_name}.json"
        return file_path.exists()
    
    def _sanitize_filename(self, name: str) -> str:
        """
        Convert agent name to safe filename.
        Removes special characters and limits length.
        """
        # Replace spaces with underscores, remove special chars
        safe_name = name.lower().strip()
        safe_name = safe_name.replace(' ', '_')
        safe_name = ''.join(c for c in safe_name if c.isalnum() or c in ('_', '-'))
        
        # Limit length
        return safe_name[:50]
    
    def export_agent(self, agent_name: str, export_path: str) -> bool:
        """
        Export an agent to a specific path (for sharing).
        
        Args:
            agent_name: Name of the agent
            export_path: Destination file path
        
        Returns:
            True if successful
        """
        try:
            agent = self.load_agent(agent_name)
            if not agent:
                return False
            
            agent_data = agent.to_dict()
            
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(agent_data, f, indent=2, ensure_ascii=False)
            
            return True
            
        except Exception as e:
            print(f"Error exporting agent: {e}")
            return False
    
    def import_agent(self, import_path: str, llm=None) -> Optional[CustomAgent]:
        """
        Import an agent from a file.
        
        Args:
            import_path: Path to agent JSON file
            llm: LLM instance
        
        Returns:
            CustomAgent instance or None
        """
        try:
            with open(import_path, 'r', encoding='utf-8') as f:
                agent_data = json.load(f)
            
            agent = CustomAgent.from_dict(agent_data, llm=llm)
            
            # Save to storage
            self.save_agent(agent)
            
            return agent
            
        except Exception as e:
            print(f"Error importing agent: {e}")
            return None

