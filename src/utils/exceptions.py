"""
Custom Exception Classes for CyberXP

Provides specific exception types for different error scenarios,
enabling better error handling and recovery.
"""


class CyberXPException(Exception):
    """Base exception for all CyberXP errors."""
    pass


class ConfigurationError(CyberXPException):
    """Raised when there's a configuration issue."""
    pass


class AuthenticationError(CyberXPException):
    """Raised when authentication fails."""
    pass


class ConnectionError(CyberXPException):
    """Raised when connection to external service fails."""
    pass


class APIError(CyberXPException):
    """Raised when an API call fails."""
    
    def __init__(self, message: str, status_code: int = None, response_text: str = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text


class RateLimitError(APIError):
    """Raised when API rate limit is exceeded."""
    pass


class ValidationError(CyberXPException):
    """Raised when input validation fails."""
    pass


class ModelError(CyberXPException):
    """Raised when model loading or inference fails."""
    pass


class RAGError(CyberXPException):
    """Raised when RAG operations fail."""
    pass


class IOCExtractionError(CyberXPException):
    """Raised when IOC extraction fails."""
    pass
