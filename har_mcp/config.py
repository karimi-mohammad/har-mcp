"""Configuration for HAR MCP Server — reads from environment variables."""

from __future__ import annotations

import os
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class Config:
    """Server configuration with sensible defaults."""

    allowed_root: Path | None = None
    max_file_size: int = 500 * 1024 * 1024  # 500 MB
    body_limit: int = 10_000  # chars returned to LLM
    redact_secrets: bool = True
    large_file_threshold: int = 100 * 1024 * 1024  # 100 MB → SQLite
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> Config:
        """Load configuration from environment variables."""
        allowed_root = os.environ.get("HAR_ALLOWED_ROOT")
        return cls(
            allowed_root=Path(allowed_root).resolve() if allowed_root else None,
            max_file_size=int(os.environ.get("HAR_MAX_FILE_SIZE", 500 * 1024 * 1024)),
            body_limit=int(os.environ.get("HAR_BODY_LIMIT", 10_000)),
            redact_secrets=os.environ.get("HAR_REDACT_SECRETS", "true").lower() in ("true", "1", "yes"),
            large_file_threshold=int(os.environ.get("HAR_LARGE_FILE_THRESHOLD", 100 * 1024 * 1024)),
            log_level=os.environ.get("HAR_LOG_LEVEL", "INFO"),
        )


# Global config singleton
_config: Config | None = None


def get_config() -> Config:
    global _config
    if _config is None:
        _config = Config.from_env()
    return _config


def set_config(config: Config) -> None:
    global _config
    _config = config
