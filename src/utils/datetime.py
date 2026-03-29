"""
Datetime utility functions
"""

from datetime import datetime, timezone


def utcnow() -> datetime:
    """
    Get current UTC time (timezone-aware).

    Replacement for deprecated datetime.utcnow()

    Returns:
        Current UTC datetime with timezone info
    """
    return datetime.now(timezone.utc)