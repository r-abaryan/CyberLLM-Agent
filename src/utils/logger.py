"""
Centralized Logging Configuration for CyberXP

Provides structured logging with proper levels, formatting, and security-aware
credential masking.
"""

import logging
import sys
import os
from typing import Optional
from pathlib import Path


class SecurityAwareFormatter(logging.Formatter):
    """Formatter that masks sensitive information in log messages."""
    
    # Patterns to mask (API keys, tokens, passwords, etc.)
    SENSITIVE_PATTERNS = [
        r'api[_-]?key["\']?\s*[:=]\s*["\']?([^"\'\s]+)',
        r'token["\']?\s*[:=]\s*["\']?([^"\'\s]+)',
        r'password["\']?\s*[:=]\s*["\']?([^"\'\s]+)',
        r'secret["\']?\s*[:=]\s*["\']?([^"\'\s]+)',
        r'client[_-]?secret["\']?\s*[:=]\s*["\']?([^"\'\s]+)',
        r'auth[_-]?token["\']?\s*[:=]\s*["\']?([^"\'\s]+)',
    ]
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record, masking sensitive information."""
        import re
        
        # Get the formatted message
        message = super().format(record)
        
        # Mask sensitive patterns
        for pattern in self.SENSITIVE_PATTERNS:
            message = re.sub(
                pattern,
                lambda m: m.group(0).replace(m.group(1), '***MASKED***'),
                message,
                flags=re.IGNORECASE
            )
        
        return message


def setup_logger(
    name: str = "cyberxp",
    level: Optional[int] = None,
    log_file: Optional[str] = None,
    enable_console: bool = True
) -> logging.Logger:
    """
    Set up a logger with proper formatting and handlers.
    
    Args:
        name: Logger name
        level: Logging level (defaults to INFO, or from CYBERXP_LOG_LEVEL env var)
        log_file: Optional path to log file
        enable_console: Whether to enable console output
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Set level from env var or parameter
    if level is None:
        level_str = os.getenv("CYBERXP_LOG_LEVEL", "INFO").upper()
        level = getattr(logging, level_str, logging.INFO)
    
    logger.setLevel(level)
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger
    
    # Create formatter
    formatter = SecurityAwareFormatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    Get a logger instance, creating it if necessary.
    
    Args:
        name: Logger name (defaults to 'cyberxp')
    
    Returns:
        Logger instance
    """
    logger_name = name or "cyberxp"
    logger = logging.getLogger(logger_name)
    
    # If logger has no handlers, set it up
    if not logger.handlers:
        log_file = os.getenv("CYBERXP_LOG_FILE")
        setup_logger(
            name=logger_name,
            log_file=log_file,
            enable_console=True
        )
    
    return logger


# Default logger instance
default_logger = get_logger()
