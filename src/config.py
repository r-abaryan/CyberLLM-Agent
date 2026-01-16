"""
Configuration for Advanced Features
Toggle features on/off without code changes
"""

import os
import warnings
from typing import Dict, Any, Optional

# Import utilities - handle both direct and relative imports
try:
    from .utils.logger import get_logger
    from .utils.exceptions import ConfigurationError
except ImportError:
    # Fallback for when config is imported directly
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))
    from utils.logger import get_logger
    from utils.exceptions import ConfigurationError

logger = get_logger(__name__)


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
        # SECURITY: Default to True for SSL verification in production
        "verify_ssl": os.getenv("SPLUNK_VERIFY_SSL", "true").lower() == "true",
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
    
    @classmethod
    def validate_credentials(cls) -> Dict[str, bool]:
        """
        Validate that required credentials are present.
        
        Returns:
            Dictionary mapping service names to validation status
        """
        validation_results = {}
        
        # Check Splunk credentials if enabled
        if cls.INTEGRATIONS.get("splunk", False):
            has_token = bool(cls.SPLUNK_CONFIG.get("token"))
            has_host = bool(cls.SPLUNK_CONFIG.get("host"))
            validation_results["splunk"] = has_token and has_host
            
            if not validation_results["splunk"]:
                logger.warning("Splunk integration enabled but credentials missing")
            
            # Security warning for SSL
            if not cls.SPLUNK_CONFIG.get("verify_ssl", True):
                logger.warning(
                    "SECURITY WARNING: SSL verification is disabled for Splunk. "
                    "This is insecure and should only be used in development."
                )
                warnings.warn(
                    "SSL verification disabled for Splunk - security risk!",
                    UserWarning,
                    stacklevel=2
                )
        
        # Check Sentinel credentials if enabled
        if cls.INTEGRATIONS.get("sentinel", False):
            required_fields = [
                "workspace_id", "subscription_id", "resource_group",
                "tenant_id", "client_id", "client_secret"
            ]
            has_all = all(bool(cls.SENTINEL_CONFIG.get(field)) for field in required_fields)
            validation_results["sentinel"] = has_all
            
            if not validation_results["sentinel"]:
                logger.warning("Sentinel integration enabled but credentials missing")
        
        # Check VirusTotal credentials if enabled
        if cls.INTEGRATIONS.get("virustotal", False):
            has_key = bool(cls.VIRUSTOTAL_CONFIG.get("api_key"))
            validation_results["virustotal"] = has_key
            
            if not validation_results["virustotal"]:
                logger.warning("VirusTotal integration enabled but API key missing")
        
        return validation_results
    
    @classmethod
    def mask_credentials(cls, config_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a safe copy of config with masked credentials.
        
        Args:
            config_dict: Configuration dictionary
        
        Returns:
            Dictionary with credentials masked
        """
        masked = config_dict.copy()
        sensitive_keys = ["token", "password", "client_secret", "api_key"]
        
        for key in sensitive_keys:
            if key in masked and masked[key]:
                masked[key] = "***MASKED***"
        
        return masked


config = FeatureConfig()


if __name__ == "__main__":
    logger.info("Current Feature Configuration:")
    logger.info("-" * 40)
    for feature, enabled in config.FEATURES.items():
        status = "[ENABLED]" if enabled else "[DISABLED]"
        logger.info(f"{feature:25s} {status}")
    
    # Validate credentials
    logger.info("\nCredential Validation:")
    validation = config.validate_credentials()
    for service, valid in validation.items():
        status = "✓" if valid else "✗"
        logger.info(f"  {service}: {status}")

