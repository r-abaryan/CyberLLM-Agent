"""
Configuration for Advanced Features
Toggle features on/off without code changes
"""

import os
from typing import Dict, Any


class FeatureConfig:
    """Feature flags and configuration for CyberXP system"""
    
    # Feature toggles
    FEATURES: Dict[str, bool] = {
        "multi_agent": True,
        "custom_agents": True,
        "vector_rag": True,
        "ioc_extraction": True,
        "feedback_logging": True,
        "export_json": True,
        "export_csv": True,
        "export_stix": True,
        "html_reports": True,
    }
    
    # External integrations (Stage 3)
    INTEGRATIONS: Dict[str, bool] = {
        "splunk": False,
        "sentinel": False,
        "virustotal": False,
        "misp": False, 
    }
    
    # SIEM Configuration
    SPLUNK_CONFIG: Dict[str, Any] = {
        "host": os.getenv("SPLUNK_HOST", ""),
        "port": int(os.getenv("SPLUNK_PORT", "8089")),
        "token": os.getenv("SPLUNK_TOKEN", ""),
        "index": os.getenv("SPLUNK_INDEX", "cyberxp_assessments"),
        "verify_ssl": os.getenv("SPLUNK_VERIFY_SSL", "false").lower() == "true",
    }
    
    SENTINEL_CONFIG: Dict[str, Any] = {
        "workspace_id": os.getenv("SENTINEL_WORKSPACE_ID", ""),
        "subscription_id": os.getenv("SENTINEL_SUBSCRIPTION_ID", ""),
        "resource_group": os.getenv("SENTINEL_RESOURCE_GROUP", ""),
        "tenant_id": os.getenv("SENTINEL_TENANT_ID", ""),
        "client_id": os.getenv("SENTINEL_CLIENT_ID", ""),
        "client_secret": os.getenv("SENTINEL_CLIENT_SECRET", ""),
    }
    
    # Webhook configurations
    WEBHOOK_URLS: Dict[str, str] = {
        "slack": os.getenv("SLACK_WEBHOOK_URL", ""),
        "teams": os.getenv("TEAMS_WEBHOOK_URL", ""),
        "pagerduty": os.getenv("PAGERDUTY_WEBHOOK_URL", ""),
    }
    
    # Threat Intelligence Configuration
    VIRUSTOTAL_CONFIG: Dict[str, Any] = {
        "api_key": os.getenv("VIRUSTOTAL_API_KEY", ""),
        "rate_limit": int(os.getenv("VIRUSTOTAL_RATE_LIMIT", "4")),  # Free tier: 4/min
    }
    
    # API keys for other services (future)
    API_KEYS: Dict[str, str] = {
        "abuseipdb": os.getenv("ABUSEIPDB_API_KEY", ""),
        "shodan": os.getenv("SHODAN_API_KEY", ""),
    }
    
    # Model configuration
    MODEL_CONFIG: Dict[str, Any] = {
        "production_version": "v2.0",
        "model_path": "abaryan/CyberXP_Agent_Llama_3.2_1B",
        "max_tokens": 512,
        "temperature": 0.7,
        "top_p": 0.9,
    }
    
    # System limits
    LIMITS: Dict[str, int] = {
        "max_custom_agents": 50,
        "max_feedback_entries": 10000,
        "max_kb_documents": 1000,
        "max_ioc_per_assessment": 100,
    }
    
    @classmethod
    def is_enabled(cls, feature: str) -> bool:
        """Check if a feature is enabled"""
        return cls.FEATURES.get(feature, False)
    
    
    @classmethod
    def get_webhook_url(cls, service: str) -> str:
        """Get webhook URL for a service"""
        return cls.WEBHOOK_URLS.get(service, "")
    
    @classmethod
    def enable_feature(cls, feature: str):
        """Enable a feature at runtime"""
        if feature in cls.FEATURES:
            cls.FEATURES[feature] = True
    
    @classmethod
    def disable_feature(cls, feature: str):
        """Disable a feature at runtime"""
        if feature in cls.FEATURES:
            cls.FEATURES[feature] = False


config = FeatureConfig()


if __name__ == "__main__":
    print("Current Feature Configuration:")
    print("-" * 40)
    for feature, enabled in config.FEATURES.items():
        status = "[ENABLED]" if enabled else "[DISABLED]"
        print(f"{feature:25s} {status}")

