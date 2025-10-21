"""
SIEM/SOAR Integration Connectors
Simple REST API integrations for enterprise platforms
"""

from .splunk_connector import SplunkConnector
from .sentinel_connector import SentinelConnector

__all__ = ["SplunkConnector", "SentinelConnector"]

