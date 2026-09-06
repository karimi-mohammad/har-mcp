"""Security layer — path validation, secret redaction, content sanitization."""

from __future__ import annotations

import re
from pathlib import Path

from .config import get_config

# ── Secret patterns ─────────────────────────────────────────────────────────

_SECRET_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-csrf-token",
    "csrf-token",
    "x-xsrf-token",
    "x-auth-token",
    "proxy-authorization",
}

_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(Bearer\s+[A-Za-z0-9\-._~+/]+=*)", re.IGNORECASE),
    re.compile(r"(Basic\s+[A-Za-z0-9+/]+=*)", re.IGNORECASE),
    re.compile(r"(eyJ[A-Za-z0-9\-._]+\.eyJ[A-Za-z0-9\-._]+\.[A-Za-z0-9\-._]+)"),  # JWT
]

_BINARY_MIME_PREFIXES = (
    "image/",
    "video/",
    "audio/",
    "font/",
    "application/pdf",
    "application/octet-stream",
    "application/zip",
    "application/gzip",
    "application/x-gzip",
    "application/x-brotli",
    "application/wasm",
)

_BINARY_MIME_EXACT = {
    "application/x-protobuf",
    "application/grpc",
}


# ── Path validation ─────────────────────────────────────────────────────────

def validate_path(file_path: str, allowed_root: Path | None = None) -> Path:
    """Resolve *file_path* and verify it sits under *allowed_root*.

    Raises ``ValueError`` on path traversal or missing file.
    """
    config = get_config()
    root = allowed_root or config.allowed_root

    resolved = Path(file_path).resolve()

    if root is not None:
        try:
            resolved.relative_to(root)
        except ValueError:
            raise ValueError(
                f"Path traversal detected: {file_path} is outside allowed root {root}"
            )

    if not resolved.exists():
        raise FileNotFoundError(f"File not found: {resolved}")

    if not resolved.is_file():
        raise ValueError(f"Not a file: {resolved}")

    return resolved


# ── Secret redaction ────────────────────────────────────────────────────────

def _redact_value(value: str) -> str:
    """Apply secret patterns to a single string value."""
    result = value
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub(r"<REDACTED>", result)
    return result


def redact_header(name: str, value: str) -> str:
    """Redact a header value if the header name is sensitive."""
    if name.lower() in _SECRET_HEADER_NAMES:
        return "<REDACTED>"
    return _redact_value(value)


def redact_cookie(cookie_name: str, cookie_value: str) -> tuple[str, str]:
    """Redact cookie value if the name is sensitive."""
    sensitive_names = {"session", "sid", "token", "jwt", "auth", "csrf", "xsrf", "access_token", "refresh_token"}
    if cookie_name.lower() in sensitive_names or any(p in cookie_name.lower() for p in ("token", "auth", "session", "csrf")):
        return cookie_name, "<REDACTED>"
    return cookie_name, _redact_value(cookie_value)


def redact_text(text: str) -> str:
    """Redact secrets found in arbitrary text (e.g. request/response body)."""
    result = text
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub("<REDACTED>", result)
    return result


def redact_headers(headers: list[dict[str, str]]) -> list[dict[str, str]]:
    """Return a copy of headers with sensitive values redacted."""
    return [{"name": h["name"], "value": redact_header(h["name"], h["value"])} for h in headers]


def redact_cookies(cookies: list[dict[str, str]]) -> list[dict[str, str]]:
    """Return a copy of cookies with sensitive values redacted."""
    result = []
    for c in cookies:
        name, value = redact_cookie(c.get("name", ""), c.get("value", ""))
        result.append({**c, "name": name, "value": value})
    return result


# ── Content detection ───────────────────────────────────────────────────────

def is_binary_content(mime_type: str) -> bool:
    """Return True if *mime_type* represents binary (non-text) content."""
    mime = mime_type.lower().split(";")[0].strip()
    if mime in _BINARY_MIME_EXACT:
        return True
    return any(mime.startswith(prefix) for prefix in _BINARY_MIME_PREFIXES)


def is_text_content(mime_type: str) -> bool:
    """Return True if *mime_type* is safe to return as text."""
    if not mime_type:
        return True  # unknown → assume text
    return not is_binary_content(mime_type)


# ── Log sanitization ────────────────────────────────────────────────────────

_SENSITIVE_LOG_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(Bearer\s+)[^\s,;]+", re.IGNORECASE),
    re.compile(r"(Basic\s+)[^\s,;]+", re.IGNORECASE),
    re.compile(r"(eyJ[A-Za-z0-9\-._]+\.eyJ[A-Za-z0-9\-._]+\.[A-Za-z0-9\-._]+)"),
]


def sanitize_for_log(value: str, max_len: int = 200) -> str:
    """Strip secrets from a value before logging. Truncate to *max_len*."""
    result = value
    for pattern in _SENSITIVE_LOG_PATTERNS:
        result = pattern.sub(r"\1<REDACTED>", result)
    if len(result) > max_len:
        result = result[:max_len] + "…"
    return result
