"""HAR 1.2 parser — reads, validates, and normalizes HTTP Archive files."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import re
import uuid
import zlib
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urljoin
from typing import Any

from .models import (
    HARFile, HARLog, HAREntry, HARRequest, HARResponse,
    HARContent, HARHeader, HARCookie, HARQueryParameter,
    HARPostData, HARTiming, HARCreator,
)
from .security import validate_path, is_binary_content


# ── Decompression ───────────────────────────────────────────────────────────

def _decompress(text: str, encoding: str, mime_type: str) -> str:
    """Decode content based on encoding flag."""
    encoding = encoding.lower().strip()

    if encoding == "base64":
        raw = base64.b64decode(text)
        if is_binary_content(mime_type):
            return text  # keep base64 for binary
        # Try gzip
        try:
            return gzip.decompress(raw).decode("utf-8", errors="replace")
        except (gzip.BadGzipFile, OSError):
            pass
        # Try deflate
        try:
            return zlib.decompress(raw, -zlib.MAX_WBITS).decode("utf-8", errors="replace")
        except zlib.error:
            pass
        # Try raw deflate
        try:
            return zlib.decompress(raw).decode("utf-8", errors="replace")
        except zlib.error:
            pass
        # Plain text decoded as base64
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return text

    return text


def _decode_content(content: HARContent) -> str:
    """Decode response content, handling encoding and compression."""
    if not content.text:
        return ""

    if is_binary_content(content.mimeType):
        return ""  # don't return binary to caller

    text = content.text
    encoding = content.encoding.lower() if content.encoding else ""

    if encoding == "base64":
        return _decompress(text, "base64", content.mimeType)

    # Check for gzip magic bytes
    if text[:2] == "H4sI" or text[:2] == "\x1f\x8b":
        try:
            raw = base64.b64decode(text)
            return gzip.decompress(raw).decode("utf-8", errors="replace")
        except Exception:
            pass

    return text


# ── URL normalization ───────────────────────────────────────────────────────

_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)
_NUMERIC_ID_RE = re.compile(r"\b\d{2,}\b")


def normalize_url(url: str) -> str:
    """Extract path from URL, strip query string."""
    parsed = urlparse(url)
    return parsed.path or "/"


def normalize_path(path: str) -> str:
    """Replace dynamic path segments with {id} placeholders.

    E.g. /api/users/12345 → /api/users/{id}
         /api/items/550e8400-e29b-41d4-a716-446655440000 → /api/items/{id}
    """
    segments = path.split("/")
    result = []
    for seg in segments:
        if _UUID_RE.fullmatch(seg):
            result.append("{id}")
        elif _NUMERIC_ID_RE.fullmatch(seg):
            result.append("{id}")
        else:
            result.append(seg)
    return "/".join(result)


def extract_domain(url: str) -> str:
    """Extract hostname from URL."""
    parsed = urlparse(url)
    return parsed.hostname or ""


def extract_query_params(url: str) -> dict[str, str]:
    """Extract query parameters as a flat dict (last value wins)."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    return {k: v[-1] if len(v) == 1 else ",".join(v) for k, v in params.items()}


# ── HAR parsing ─────────────────────────────────────────────────────────────

def _safe_get(d: dict | None, key: str, default: Any = None) -> Any:
    """Safe dictionary access."""
    if d is None:
        return default
    return d.get(key, default)


def _parse_header(raw: dict) -> HARHeader:
    return HARHeader(
        name=str(_safe_get(raw, "name", "")),
        value=str(_safe_get(raw, "value", "")),
    )


def _parse_cookie(raw: dict) -> HARCookie:
    return HARCookie(
        name=str(_safe_get(raw, "name", "")),
        value=str(_safe_get(raw, "value", "")),
        path=str(_safe_get(raw, "path", "")),
        domain=str(_safe_get(raw, "domain", "")),
        expires=str(_safe_get(raw, "expires", "")),
        httpOnly=bool(_safe_get(raw, "httpOnly", False)),
        secure=bool(_safe_get(raw, "secure", False)),
        comment=str(_safe_get(raw, "comment", "")),
    )


def _parse_query_param(raw: dict) -> HARQueryParameter:
    return HARQueryParameter(
        name=str(_safe_get(raw, "name", "")),
        value=str(_safe_get(raw, "value", "")),
        comment=str(_safe_get(raw, "comment", "")),
    )


def _parse_post_data(raw: dict | None) -> HARPostData | None:
    if raw is None:
        return None
    return HARPostData(
        mimeType=str(_safe_get(raw, "mimeType", "")),
        text=str(_safe_get(raw, "text", "")),
        params=list(_safe_get(raw, "params", [])),
        comment=str(_safe_get(raw, "comment", "")),
    )


def _parse_request(raw: dict) -> HARRequest:
    return HARRequest(
        method=str(_safe_get(raw, "method", "GET")),
        url=str(_safe_get(raw, "url", "")),
        httpVersion=str(_safe_get(raw, "httpVersion", "")),
        cookies=[_parse_cookie(c) for c in _safe_get(raw, "cookies", []) or []],
        headers=[_parse_header(h) for h in _safe_get(raw, "headers", []) or []],
        queryString=[_parse_query_param(q) for q in _safe_get(raw, "queryString", []) or []],
        postData=_parse_post_data(_safe_get(raw, "postData")),
        headersSize=int(_safe_get(raw, "headersSize", -1)),
        bodySize=int(_safe_get(raw, "bodySize", -1)),
        comment=str(_safe_get(raw, "comment", "")),
    )


def _parse_content(raw: dict | None) -> HARContent:
    if raw is None:
        return HARContent()
    return HARContent(
        size=int(_safe_get(raw, "size", 0)),
        mimeType=str(_safe_get(raw, "mimeType", "")),
        text=str(_safe_get(raw, "text", "")),
        encoding=str(_safe_get(raw, "encoding", "")),
        comment=str(_safe_get(raw, "comment", "")),
    )


def _parse_response(raw: dict) -> HARResponse:
    return HARResponse(
        status=int(_safe_get(raw, "status", 0)),
        statusText=str(_safe_get(raw, "statusText", "")),
        httpVersion=str(_safe_get(raw, "httpVersion", "")),
        cookies=[_parse_cookie(c) for c in _safe_get(raw, "cookies", []) or []],
        headers=[_parse_header(h) for h in _safe_get(raw, "headers", []) or []],
        content=_parse_content(_safe_get(raw, "content")),
        redirectURL=str(_safe_get(raw, "redirectURL", "")),
        headersSize=int(_safe_get(raw, "headersSize", -1)),
        bodySize=int(_safe_get(raw, "bodySize", -1)),
        comment=str(_safe_get(raw, "comment", "")),
    )


def _parse_timings(raw: dict | None) -> HARTiming:
    if raw is None:
        return HARTiming()
    return HARTiming(
        blocked=float(_safe_get(raw, "blocked", -1)),
        dns=float(_safe_get(raw, "dns", -1)),
        connect=float(_safe_get(raw, "connect", -1)),
        send=float(_safe_get(raw, "send", 0)),
        wait=float(_safe_get(raw, "wait", 0)),
        receive=float(_safe_get(raw, "receive", 0)),
        ssl=float(_safe_get(raw, "ssl", -1)),
        comment=str(_safe_get(raw, "comment", "")),
    )


def _parse_entry(raw: dict) -> HAREntry:
    return HAREntry(
        startedDateTime=str(_safe_get(raw, "startedDateTime", "")),
        time=float(_safe_get(raw, "time", 0)),
        request=_parse_request(_safe_get(raw, "request", {})),
        response=_parse_response(_safe_get(raw, "response", {})),
        cache=_safe_get(raw, "cache", {}) or {},
        timings=_parse_timings(_safe_get(raw, "timings")),
        serverIPAddress=str(_safe_get(raw, "serverIPAddress", "")),
        connection=str(_safe_get(raw, "connection", "")),
        comment=str(_safe_get(raw, "comment", "")),
    )


def parse_har(file_path: Path) -> HARFile:
    """Parse a HAR file from disk.

    Returns a fully parsed HARFile model. Raises on invalid JSON or structure.
    Missing fields are filled with defaults — never crashes on incomplete data.
    """
    raw = json.loads(file_path.read_text(encoding="utf-8"))

    log_raw = _safe_get(raw, "log", {})
    if not log_raw:
        raise ValueError("Invalid HAR: missing 'log' key")

    creator_raw = _safe_get(log_raw, "creator", {})
    creator = HARCreator(
        name=str(_safe_get(creator_raw, "name", "")),
        version=str(_safe_get(creator_raw, "version", "")),
        comment=str(_safe_get(creator_raw, "comment", "")),
    )

    entries_raw = _safe_get(log_raw, "entries", []) or []
    entries = [_parse_entry(e) for e in entries_raw]

    log = HARLog(
        version=str(_safe_get(log_raw, "version", "")),
        creator=creator,
        entries=entries,
        comment=str(_safe_get(log_raw, "comment", "")),
    )

    return HARFile(log=log)


def compute_har_id(file_path: Path, content: bytes | None = None) -> str:
    """Generate a deterministic short ID for a HAR file."""
    if content is None:
        content = file_path.read_bytes()
    return hashlib.sha256(content).hexdigest()[:12]


def decode_entry_body(entry: HAREntry) -> str:
    """Decode and return the response body text (handles compression/encoding)."""
    return _decode_content(entry.response.content)


def get_request_body_text(entry: HAREntry) -> str:
    """Return request body text if present."""
    if entry.request.postData and entry.request.postData.text:
        return entry.request.postData.text
    return ""
