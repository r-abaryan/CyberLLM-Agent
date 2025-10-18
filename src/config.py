"""
Configuration for Advanced Features
Toggle features on/off without code changes
"""

import os
from typing import Dict, Any


class FeatureConfig:
    """Feature flags for advanced capabilities"""
    
    FEATURES: Dict[str, bool] = {
        "multi_agent": True,
        "export_json": True,
        "export_csv": True,
        "export_stix": True,
    }
    
    WEBHOOK_URLS: Dict[str, str] = {
        "slack": os.getenv("SLACK_WEBHOOK_URL", ""),
        "teams": os.getenv("TEAMS_WEBHOOK_URL", ""),
    }
    
    MODEL_CONFIG: Dict[str, Any] = {
        "production_version": "v1.0",
        "experimental_version": "v1.1",
        "ab_test_ratio": 0.1,
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

