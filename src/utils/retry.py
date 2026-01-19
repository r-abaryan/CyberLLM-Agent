"""
Retry Utilities with Exponential Backoff

Provides retry decorators and functions for handling transient failures
in external API calls and network operations.
"""

import time
import functools
from typing import Callable, Type, Tuple, Optional
from .exceptions import APIError, RateLimitError, ConnectionError

try:
    import requests
    RequestException = requests.exceptions.RequestException
except ImportError:
    RequestException = Exception
from .logger import get_logger

logger = get_logger(__name__)


def retry_with_backoff(
    max_retries: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    retryable_exceptions: Tuple[Type[Exception], ...] = (APIError, ConnectionError, RateLimitError, RequestException),
    on_retry: Optional[Callable] = None
):
    """
    Decorator to retry a function with exponential backoff.
    
    Args:
        max_retries: Maximum number of retry attempts
        initial_delay: Initial delay in seconds
        max_delay: Maximum delay in seconds
        exponential_base: Base for exponential backoff
        retryable_exceptions: Tuple of exception types to retry on
        on_retry: Optional callback function called on each retry
    
    Returns:
        Decorated function
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            delay = initial_delay
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except retryable_exceptions as e:
                    last_exception = e
                    
                    if attempt < max_retries:
                        # Special handling for rate limit errors
                        if isinstance(e, RateLimitError):
                            # Use longer delay for rate limits
                            delay = min(delay * exponential_base * 2, max_delay)
                            logger.warning(
                                f"Rate limit hit for {func.__name__}. "
                                f"Retrying in {delay:.1f}s (attempt {attempt + 1}/{max_retries})"
                            )
                        else:
                            delay = min(delay * exponential_base, max_delay)
                            logger.warning(
                                f"Error in {func.__name__}: {str(e)}. "
                                f"Retrying in {delay:.1f}s (attempt {attempt + 1}/{max_retries})"
                            )
                        
                        if on_retry:
                            on_retry(attempt + 1, e)
                        
                        time.sleep(delay)
                    else:
                        logger.error(
                            f"Failed {func.__name__} after {max_retries} retries: {str(e)}"
                        )
                        raise
                except Exception as e:
                    # Don't retry on non-retryable exceptions
                    logger.error(f"Non-retryable error in {func.__name__}: {str(e)}")
                    raise
            
            # Should never reach here, but just in case
            if last_exception:
                raise last_exception
        
        return wrapper
    return decorator


def retry_on_connection_error(max_retries: int = 3):
    """Convenience decorator for connection errors only."""
    return retry_with_backoff(
        max_retries=max_retries,
        retryable_exceptions=(ConnectionError,)
    )


def retry_on_api_error(max_retries: int = 3):
    """Convenience decorator for API errors only."""
    return retry_with_backoff(
        max_retries=max_retries,
        retryable_exceptions=(APIError, RateLimitError)
    )
