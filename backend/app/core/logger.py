"""
Logging configuration for SentinelAI.

This module provides logging utilities and configuration for the
SentinelAI security scanning platform.
"""

import logging
from typing import Callable
def get_logger(name: str = __name__) -> logging.Logger:
    """
    Get a logger instance with the specified name.

    Args:
        name: The name of the logger (defaults to module name)

    Returns:
        A configured logger instance.
    """
    logger = logging.getLogger(name)

    # Add console handler if not already configured
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    logger.setLevel(logging.INFO)
    return logger
# Configure root logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Create a module-level logger for the logger module itself
logger = get_logger(__name__)