from typing import Optional, Dict
from datetime import datetime, timezone
import uuid

# Centralized logging system for ScribePilot backend
# Provides structured logging with categories (auth, chat, rag, extension, security)
# and severity levels (debug, info, warning, error, critical)


class CategoryLogger:
    """Category-specific logger (auth, chat, rag, extension, security)"""

    def __init__(self, category: str):
        self.category = category

    async def debug(
        self,
        event_type: str,
        message: str,
        user: Optional[Dict] = None,
        metadata: Optional[Dict] = None,
    ):
        await self._log("debug", event_type, message, user, None, metadata)

    async def info(
        self,
        event_type: str,
        message: str,
        user: Optional[Dict] = None,
        metadata: Optional[Dict] = None,
    ):
        await self._log("info", event_type, message, user, None, metadata)

    async def warning(
        self,
        event_type: str,
        message: str,
        user: Optional[Dict] = None,
        metadata: Optional[Dict] = None,
    ):
        await self._log("warning", event_type, message, user, None, metadata)

    async def error(
        self,
        event_type: str,
        message: str,
        error: Optional[Dict] = None,
        user: Optional[Dict] = None,
        metadata: Optional[Dict] = None,
    ):
        await self._log("error", event_type, message, user, error, metadata)

    async def critical(
        self,
        event_type: str,
        message: str,
        error: Optional[Dict] = None,
        user: Optional[Dict] = None,
        metadata: Optional[Dict] = None,
    ):
        await self._log("critical", event_type, message, user, error, metadata)

    async def _log(
        self,
        severity: str,
        event_type: str,
        message: str,
        user: Optional[Dict],
        error: Optional[Dict],
        metadata: Optional[Dict],
    ):
        # Build structured log entry with all relevant context
        log_entry = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "backend",
            "category": self.category,
            "event_type": event_type,
            "severity": severity,
            "message": message,
        }
        if user:
            log_entry["user"] = user
        if error:
            log_entry["error"] = error
        if metadata:
            log_entry["metadata"] = metadata

        # Format and output log in human-readable format
        timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        severity_upper = severity.upper()
        user_info = f" [{user.get('user_id', 'unknown')}]" if user else ""
        print(
            f"[{timestamp}] [{severity_upper}] [{self.category}]{user_info} {event_type} - {message}"
        )


class Logger:
    _instance = None

    def __init__(self):
        pass

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def get_logger(self, category: str) -> CategoryLogger:
        return CategoryLogger(category)
        
logger = Logger.get_instance()
