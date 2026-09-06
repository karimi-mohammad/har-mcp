"""HAR Analysis MCP Server — entry point with all tool registrations."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from .config import get_config, Config
from .models import HARFile
from .har_parser import parse_har, compute_har_id, decode_entry_body, get_request_body_text, extract_domain, normalize_url, normalize_path
from .storage import MemoryStorage
from .security import validate_path, is_binary_content, redact_headers, redact_cookies, redact_text
from . import analyzer

# ── Logging ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("har-mcp")

# ── MCP Server ──────────────────────────────────────────────────────────────

mcp = FastMCP(
    "HAR Analysis",
    instructions="Local, read-only HTTP Archive (HAR) analysis server for AI agents.",
)

# ── In-memory store of loaded HARs ──────────────────────────────────────────

_loaded_hars: dict[str, MemoryStorage] = {}


def _get_storage(har_id: str) -> MemoryStorage:
    """Get storage for a loaded HAR, or raise."""
    if har_id not in _loaded_hars:
        raise KeyError(f"HAR {har_id} not loaded. Use load_har first.")
    return _loaded_hars[har_id]


def _error(code: str, message: str) -> dict[str, Any]:
    return {"error": True, "code": code, "message": message}


# ═══════════════════════════════════════════════════════════════════════════
# Phase 1 — Essential Tools
# ═══════════════════════════════════════════════════════════════════════════

@mcp.tool()
def load_har(path: str) -> dict[str, Any]:
    """Load a HAR file from disk and return a summary.

    Args:
        path: Absolute path to the .har file.

    Returns:
        Summary with har_id, version, request_count, domains.
    """
    try:
        resolved = validate_path(path)
    except (ValueError, FileNotFoundError) as e:
        return _error("INVALID_PATH", str(e))

    try:
        file_bytes = resolved.read_bytes()
        har_id = compute_har_id(resolved, file_bytes)
        har = parse_har(resolved)
    except Exception as e:
        return _error("PARSE_ERROR", f"Failed to parse HAR: {e}")

    storage = MemoryStorage(har_id, har)
    _loaded_hars[har_id] = storage

    domains = list({extract_domain(e.request.url) for e in har.log.entries})
    logger.info("Loaded HAR %s with %d requests from %d domains", har_id, storage.entry_count, len(domains))

    return {
        "har_id": har_id,
        "version": har.log.version,
        "request_count": storage.entry_count,
        "domains": sorted(domains),
    }


@mcp.tool()
def list_requests(
    har_id: str,
    method: str | None = None,
    domain: str | None = None,
    path: str | None = None,
    status: int | None = None,
    content_type: str | None = None,
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> Any:
    """List requests in a loaded HAR with optional filters. Returns summaries without body content.

    Args:
        har_id: ID from load_har.
        method: Filter by HTTP method (GET, POST, etc.).
        domain: Filter by domain.
        path: Filter by URL path substring.
        status: Filter by status code.
        content_type: Filter by response content type substring.
        search: Filter by URL/header substring search.
        limit: Max results (default 50).
        offset: Pagination offset.
    """
    try:
        storage = _get_storage(har_id)
    except KeyError as e:
        return _error("HAR_NOT_LOADED", str(e))

    results = storage.list_requests(
        method=method, domain=domain, path=path, status=status,
        content_type=content_type, search=search, limit=limit, offset=offset,
    )
    return [r.model_dump() for r in results]


@mcp.tool()
def get_request(
    har_id: str,
    request_id: int,
    redact_secrets: bool = True,
) -> dict[str, Any]:
    """Get full details of a specific request.

    Args:
        har_id: ID from load_har.
        request_id: 1-based request ID from list_requests.
        redact_secrets: Whether to redact sensitive headers/cookies (default true).
    """
    try:
        storage = _get_storage(har_id)
    except KeyError as e:
        return _error("HAR_NOT_LOADED", str(e))

    entry = storage.get_entry_by_id(request_id)
    if entry is None:
        return _error("REQUEST_NOT_FOUND", f"Request ID {request_id} does not exist")

    req = entry.request
    headers = [h.model_dump() for h in req.headers]
    cookies = [c.model_dump() for c in req.cookies]
    query = [q.model_dump() for q in req.queryString]

    if redact_secrets:
        headers = redact_headers(headers)
        cookies = redact_cookies(cookies)

    post_data = None
    if req.postData:
        post_data = {
            "mime_type": req.postData.mimeType,
            "text": req.postData.text[:get_config().body_limit] if req.postData.text else "",
            "truncated": len(req.postData.text or "") > get_config().body_limit,
            "original_size": len(req.postData.text or ""),
        }
        if redact_secrets and post_data["text"]:
            post_data["text"] = redact_text(post_data["text"])

    return {
        "id": request_id,
        "method": req.method,
        "url": req.url,
        "http_version": req.httpVersion,
        "query": query,
        "headers": headers,
        "cookies": cookies,
        "post_data": post_data,
        "request_size": req.bodySize,
        "response": {
            "status": entry.response.status,
            "status_text": entry.response.statusText,
            "headers": redact_headers([h.model_dump() for h in entry.response.headers]) if redact_secrets else [h.model_dump() for h in entry.response.headers],
        },
        "timings": entry.timings.model_dump(),
        "started_at": entry.startedDateTime,
        "duration_ms": entry.time,
    }


@mcp.tool()
def get_response(
    har_id: str,
    request_id: int,
    redact_secrets: bool = True,
) -> dict[str, Any]:
    """Get full details of a response.

    Args:
        har_id: ID from load_har.
        request_id: 1-based request ID.
        redact_secrets: Whether to redact sensitive headers/cookies (default true).
    """
    try:
        storage = _get_storage(har_id)
    except KeyError as e:
        return _error("HAR_NOT_LOADED", str(e))

    entry = storage.get_entry_by_id(request_id)
    if entry is None:
        return _error("REQUEST_NOT_FOUND", f"Request ID {request_id} does not exist")

    resp = entry.response
    content = resp.content

    # Handle binary content
    if content.mimeType and is_binary_content(content.mimeType):
        return {
            "request_id": request_id,
            "status": resp.status,
            "status_text": resp.statusText,
            "headers": redact_headers([h.model_dump() for h in resp.headers]) if redact_secrets else [h.model_dump() for h in resp.headers],
            "cookies": redact_cookies([c.model_dump() for c in resp.cookies]) if redact_secrets else [c.model_dump() for c in resp.cookies],
            "content": {
                "is_binary": True,
                "mime_type": content.mimeType,
                "size": content.size,
            },
            "redirect_url": resp.redirectURL,
            "timings": entry.timings.model_dump(),
        }

    # Text content with truncation
    body_limit = get_config().body_limit
    body_text = decode_entry_body(entry)
    truncated = len(body_text) > body_limit

    if truncated:
        body_text = body_text[:body_limit]

    if redact_secrets and body_text:
        body_text = redact_text(body_text)

    return {
        "request_id": request_id,
        "status": resp.status,
        "status_text": resp.statusText,
        "headers": redact_headers([h.model_dump() for h in resp.headers]) if redact_secrets else [h.model_dump() for h in resp.headers],
        "cookies": redact_cookies([c.model_dump() for c in resp.cookies]) if redact_secrets else [c.model_dump() for c in resp.cookies],
        "content": {
            "mime_type": content.mimeType,
            "size": content.size,
            "text": body_text,
            "truncated": truncated,
            "original_size": len(decode_entry_body(entry)),
        },
        "redirect_url": resp.redirectURL,
        "timings": entry.timings.model_dump(),
    }


@mcp.tool()
def search_requests(
    har_id: str,
    query: str,
    scope: str = "all",
    limit: int = 50,
) -> Any:
    """Search across all requests and responses in a HAR file.

    Args:
        har_id: ID from load_har.
        query: Search string.
        scope: Where to search — "url", "headers", "request_body", "response_body", or "all".
        limit: Max results.
    """
    try:
        storage = _get_storage(har_id)
    except KeyError as e:
        return _error("HAR_NOT_LOADED", str(e))

    results = storage.search_entries(query, scope=scope, limit=limit)
    return [r.model_dump() for r in results]


@mcp.tool()
def list_endpoints(har_id: str) -> Any:
    """List unique API endpoints (method + normalized path) with request counts.

    Args:
        har_id: ID from load_har.
    """
    try:
        storage = _get_storage(har_id)
    except KeyError as e:
        return _error("HAR_NOT_LOADED", str(e))

    endpoints = storage.get_endpoints()
    return [e.model_dump() for e in endpoints]


@mcp.tool()
def list_domains(har_id: str) -> Any:
    """List all domains in the HAR with request counts.

    Args:
        har_id: ID from load_har.
    """
    try:
        storage = _get_storage(har_id)
    except KeyError as e:
        return _error("HAR_NOT_LOADED", str(e))

    domains = storage.get_domains()
    return [d.model_dump() for d in domains]


@mcp.tool()
def get_statistics(har_id: str) -> dict[str, Any]:
    """Get aggregate statistics for the loaded HAR.

    Args:
        har_id: ID from load_har.
    """
    try:
        storage = _get_storage(har_id)
    except KeyError as e:
        return _error("HAR_NOT_LOADED", str(e))

    return analyzer.get_statistics(storage)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 2 — Analysis Tools
# ═══════════════════════════════════════════════════════════════════════════

@mcp.tool()
def analyze_endpoint(
    har_id: str,
    method: str,
    url_pattern: str,
) -> dict[str, Any]:
    """Deep analysis of a specific endpoint — param classification, header patterns, etc.

    Args:
        har_id: ID from load_har.
        method: HTTP method (GET, POST, etc.).
        url_pattern: URL path pattern to analyze (e.g., /api/login).
    """
    try:
        storage = _get_storage(har_id)
    except KeyError as e:
        return _error("HAR_NOT_LOADED", str(e))

    return analyzer.analyze_endpoint(storage, method, url_pattern)


@mcp.tool()
def compare_requests(
    har_id: str,
    request_a: int,
    request_b: int,
) -> dict[str, Any]:
    """Compare two requests side by side across all dimensions.

    Args:
        har_id: ID from load_har.
        request_a: First request ID.
        request_b: Second request ID.
    """
    try:
        storage = _get_storage(har_id)
    except KeyError as e:
        return _error("HAR_NOT_LOADED", str(e))

    return analyzer.compare_requests(storage, request_a, request_b)


@mcp.tool()
def find_errors(har_id: str) -> Any:
    """Find requests with 4xx/5xx status codes or failures.

    Args:
        har_id: ID from load_har.
    """
    try:
        storage = _get_storage(har_id)
    except KeyError as e:
        return _error("HAR_NOT_LOADED", str(e))

    return analyzer.find_errors(storage)


@mcp.tool()
def find_slow_requests(
    har_id: str,
    threshold_ms: float = 1000,
    limit: int = 20,
) -> Any:
    """Find requests that exceed a time threshold.

    Args:
        har_id: ID from load_har.
        threshold_ms: Minimum duration in ms to consider "slow" (default 1000).
        limit: Max results.
    """
    try:
        storage = _get_storage(har_id)
    except KeyError as e:
        return _error("HAR_NOT_LOADED", str(e))

    return analyzer.find_slow_requests(storage, threshold_ms=threshold_ms, limit=limit)


@mcp.tool()
def trace_value(
    har_id: str,
    value: str,
    limit: int = 50,
) -> Any:
    """Trace where a specific value appears across all requests/responses.

    Args:
        har_id: ID from load_har.
        value: The value to search for (e.g., a token, session ID, JWT).
        limit: Max results.
    """
    try:
        storage = _get_storage(har_id)
    except KeyError as e:
        return _error("HAR_NOT_LOADED", str(e))

    traces = analyzer.trace_value(storage, value, limit=limit)
    return [t.model_dump() for t in traces]


@mcp.tool()
def analyze_auth(har_id: str) -> dict[str, Any]:
    """Extract authentication mechanisms from the HAR (Bearer, Basic, cookies, JWT, OAuth, etc.).

    Args:
        har_id: ID from load_har.
    """
    try:
        storage = _get_storage(har_id)
    except KeyError as e:
        return _error("HAR_NOT_LOADED", str(e))

    return analyzer.analyze_auth(storage)


@mcp.tool()
def get_request_chain(
    har_id: str,
    start_request_id: int,
    max_depth: int = 10,
) -> dict[str, Any]:
    """Infer request relationships (e.g., login → profile → order) based on timing, cookies, tokens.

    Args:
        har_id: ID from load_har.
        start_request_id: Starting request ID to trace from.
        max_depth: Maximum chain length.
    """
    try:
        storage = _get_storage(har_id)
    except KeyError as e:
        return _error("HAR_NOT_LOADED", str(e))

    return analyzer.get_request_chain(storage, start_request_id, max_depth=max_depth)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 3 — Advanced Tools
# ═══════════════════════════════════════════════════════════════════════════

@mcp.tool()
def detect_api_patterns(har_id: str) -> Any:
    """Detect API patterns (REST, GraphQL, JSON API, WebSocket, SSE, etc.).

    Args:
        har_id: ID from load_har.
    """
    try:
        storage = _get_storage(har_id)
    except KeyError as e:
        return _error("HAR_NOT_LOADED", str(e))

    patterns = analyzer.detect_api_patterns(storage)
    return [p.model_dump() for p in patterns]


@mcp.tool()
def get_page_flow(har_id: str) -> dict[str, Any]:
    """Get a browser page flow overview — group requests by page, separate API from static assets.

    Args:
        har_id: ID from load_har.
    """
    try:
        storage = _get_storage(har_id)
    except KeyError as e:
        return _error("HAR_NOT_LOADED", str(e))

    return analyzer.get_page_flow(storage)


@mcp.tool()
def export_request_as_curl(
    har_id: str,
    request_id: int,
    redact_secrets: bool = True,
) -> dict[str, Any]:
    """Convert a request to a cURL command. Secrets are redacted by default.

    Args:
        har_id: ID from load_har.
        request_id: 1-based request ID.
        redact_secrets: Whether to redact secrets (default true).
    """
    try:
        storage = _get_storage(har_id)
    except KeyError as e:
        return _error("HAR_NOT_LOADED", str(e))

    return analyzer.export_as_curl(storage, request_id, redact_secrets=redact_secrets)


# ═══════════════════════════════════════════════════════════════════════════
# Resources & Prompts
# ═══════════════════════════════════════════════════════════════════════════

@mcp.resource("har://{har_id}/overview")
def har_overview(har_id: str) -> str:
    """Overview of a loaded HAR file — summary stats, endpoints, auth, errors."""
    try:
        storage = _get_storage(har_id)
    except KeyError:
        return f"HAR {har_id} not loaded."

    stats = analyzer.get_statistics(storage)
    auth = analyzer.analyze_auth(storage)
    errors = analyzer.find_errors(storage)
    endpoints = storage.get_endpoints()

    lines = [
        f"# HAR Overview: {har_id}",
        f"Requests: {stats['total_requests']}",
        f"Domains: {len(stats['domains'])}",
        f"Endpoints: {len(endpoints)}",
        f"Average response time: {stats['average_response_time_ms']}ms",
        f"Errors: {len(errors)}",
        "",
        "## Methods",
    ]
    for method, count in stats["methods"].items():
        lines.append(f"  {method}: {count}")

    lines.append("\n## Status Codes")
    for code, count in stats["status_codes"].items():
        lines.append(f"  {code}: {count}")

    if auth.get("authentication"):
        lines.append("\n## Authentication")
        for a in auth["authentication"]:
            lines.append(f"  {a['type']}: {a.get('details', '')}")

    if errors:
        lines.append(f"\n## Errors ({len(errors)})")
        for e in errors[:10]:
            lines.append(f"  #{e['request_id']} {e['method']} {e['url']}: {e['reason']}")

    return "\n".join(lines)


@mcp.prompt()
def analyze_har() -> str:
    """Prompt to guide HAR analysis and reverse engineering."""
    return """You have access to a HAR (HTTP Archive) analysis server. To analyze HTTP traffic:

1. First, load a HAR file: use `load_har` with the file path
2. Get an overview: use `list_domains` and `list_endpoints` to understand the API surface
3. Find specific flows: use `search_requests` or `trace_value` to follow tokens/cookies
4. Analyze endpoints: use `analyze_endpoint` for deep parameter analysis
5. Compare requests: use `compare_requests` to find what changed between calls
6. Check auth: use `analyze_auth` to understand the authentication flow
7. Find issues: use `find_errors` and `find_slow_requests` for problems

Key tips:
- All request IDs are 1-based (from list_requests output)
- Use `get_request` and `get_response` for full details (they're separate to save context)
- `search_requests` supports scope: url, headers, request_body, response_body, all
- `trace_value` is great for following tokens, session IDs, or any value across the traffic
- Secrets are redacted by default for safety
"""


# ═══════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════

def main():
    """Run the HAR MCP server via stdio."""
    config = get_config()
    logger.setLevel(config.log_level)
    logger.info("Starting HAR Analysis MCP Server (stdio)")
    mcp.run()


if __name__ == "__main__":
    main()
