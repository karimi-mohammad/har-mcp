"""Smart analysis functions for HAR traffic data."""

from __future__ import annotations

import base64
import json
import re
from collections import defaultdict
from typing import Any

from .models import (
    HAREntry, HARHeader, HARCookie, AuthInfo, ChainEntry, ValueTrace,
    APIPattern, HAROverview, RequestSummary, SearchResult,
)
from .har_parser import (
    extract_domain, normalize_url, normalize_path, decode_entry_body,
    get_request_body_text, extract_query_params,
)
from .storage import MemoryStorage
from .security import is_binary_content


# ── Endpoint analysis ───────────────────────────────────────────────────────

def analyze_endpoint(
    storage: MemoryStorage,
    method: str,
    url_pattern: str,
) -> dict[str, Any]:
    """Deep analysis of an endpoint — param classification, header patterns, etc."""
    entries = storage.get_entries_for_endpoint(method, url_pattern)
    if not entries:
        return {"error": True, "code": "ENDPOINT_NOT_FOUND", "message": f"No requests found for {method} {url_pattern}"}

    # Collect all data
    all_request_headers: dict[str, list[str]] = defaultdict(list)
    all_response_headers: dict[str, list[str]] = defaultdict(list)
    all_query_params: dict[str, list[str]] = defaultdict(list)
    all_body_params: dict[str, list[str]] = defaultdict(list)
    status_codes: list[int] = []
    content_types: list[str] = []
    request_ids: list[int] = []

    for req_id, entry in entries:
        request_ids.append(req_id)
        req = entry.request
        resp = entry.response
        status_codes.append(resp.status)
        if resp.content and resp.content.mimeType:
            content_types.append(resp.content.mimeType)

        for h in req.headers:
            all_request_headers[h.name].append(h.value)
        for h in resp.headers:
            all_response_headers[h.name].append(h.value)
        for q in req.queryString:
            all_query_params[q.name].append(q.value)

        body = get_request_body_text(entry)
        if body:
            try:
                body_json = json.loads(body)
                if isinstance(body_json, dict):
                    for k, v in body_json.items():
                        all_body_params[k].append(str(v))
            except (json.JSONDecodeError, TypeError):
                pass

    # Classify parameters
    total = len(entries)

    def classify(values: list[str]) -> dict[str, str]:
        """Classify a parameter's values as dynamic, constant, or variable."""
        unique = set(values)
        if len(unique) == 1:
            return {"status": "constant"}
        if len(unique) == total:
            return {"status": "dynamic", "unique_count": len(unique)}
        return {"status": "variable", "unique_count": len(unique), "values": list(unique)[:5]}

    param_analysis = {}
    for param, values in all_query_params.items():
        param_analysis[f"query:{param}"] = classify(values)
    for param, values in all_body_params.items():
        param_analysis[f"body:{param}"] = classify(values)

    return {
        "method": method,
        "url_pattern": url_pattern,
        "request_count": total,
        "request_ids": request_ids,
        "status_codes": sorted(set(status_codes)),
        "status_code_counts": {s: status_codes.count(s) for s in sorted(set(status_codes))},
        "content_types": sorted(set(content_types)),
        "common_request_headers": _common_headers(all_request_headers, total),
        "common_response_headers": _common_headers(all_response_headers, total),
        "query_params": {k: classify(v) for k, v in all_query_params.items()},
        "body_params": {k: classify(v) for k, v in all_body_params.items()},
        "parameter_analysis": param_analysis,
    }


def _common_headers(headers: dict[str, list[str]], total: int) -> list[dict[str, Any]]:
    """Return headers sorted by frequency, with count."""
    result = []
    for name, values in sorted(headers.items(), key=lambda x: -len(x[1])):
        result.append({
            "name": name,
            "count": len(values),
            "frequency": f"{len(values)}/{total}",
            "unique_values": len(set(values)),
        })
    return result[:20]


# ── Request comparison ──────────────────────────────────────────────────────

def compare_requests(
    storage: MemoryStorage,
    request_a: int,
    request_b: int,
) -> dict[str, Any]:
    """Diff two requests across all dimensions."""
    entry_a = storage.get_entry_by_id(request_a)
    entry_b = storage.get_entry_by_id(request_b)

    if entry_a is None:
        return {"error": True, "code": "REQUEST_NOT_FOUND", "message": f"Request ID {request_a} not found"}
    if entry_b is None:
        return {"error": True, "code": "REQUEST_NOT_FOUND", "message": f"Request ID {request_b} not found"}

    req_a, req_b = entry_a.request, entry_b.request
    resp_a, resp_b = entry_a.response, entry_b.response

    # URL diff
    url_diff = _diff_strings(req_a.url, req_b.url)

    # Method diff
    method_diff = _diff_strings(req_a.method, req_b.method)

    # Headers diff
    headers_a = {h.name: h.value for h in req_a.headers}
    headers_b = {h.name: h.value for h in req_b.headers}
    headers_diff = _diff_dicts(headers_a, headers_b)

    # Cookies diff
    cookies_a = {c.name: c.value for c in req_a.cookies}
    cookies_b = {c.name: c.value for c in req_b.cookies}
    cookies_diff = _diff_dicts(cookies_a, cookies_b)

    # Query diff
    query_a = {q.name: q.value for q in req_a.queryString}
    query_b = {q.name: q.value for q in req_b.queryString}
    query_diff = _diff_dicts(query_a, query_b)

    # Body diff
    body_a = get_request_body_text(entry_a)
    body_b = get_request_body_text(entry_b)
    body_diff = _diff_strings(body_a, body_b)

    # Response diff
    resp_status_diff = _diff_strings(str(resp_a.status), str(resp_b.status))
    resp_headers_a = {h.name: h.value for h in resp_a.headers}
    resp_headers_b = {h.name: h.value for h in resp_b.headers}
    resp_headers_diff = _diff_dicts(resp_headers_a, resp_headers_b)

    return {
        "request_a": request_a,
        "request_b": request_b,
        "url": url_diff,
        "method": method_diff,
        "request_headers": headers_diff,
        "request_cookies": cookies_diff,
        "query_parameters": query_diff,
        "request_body": body_diff,
        "response_status": resp_status_diff,
        "response_headers": resp_headers_diff,
    }


def _diff_strings(a: str, b: str) -> dict[str, Any]:
    if a == b:
        return {"same": True, "value": a}
    return {"same": False, "a": a, "b": b}


def _diff_dicts(a: dict[str, str], b: dict[str, str]) -> dict[str, Any]:
    keys_a = set(a.keys())
    keys_b = set(b.keys())

    only_a = keys_a - keys_b
    only_b = keys_b - keys_a
    common = keys_a & keys_b
    changed = {k for k in common if a[k] != b[k]}

    result: dict[str, Any] = {"same": not only_a and not only_b and not changed}
    if only_a:
        result["only_in_a"] = {k: a[k] for k in only_a}
    if only_b:
        result["only_in_b"] = {k: b[k] for k in only_b}
    if changed:
        result["changed"] = {k: {"a": a[k], "b": b[k]} for k in changed}
    return result


# ── Error detection ─────────────────────────────────────────────────────────

def find_errors(storage: MemoryStorage) -> list[dict[str, Any]]:
    """Find requests with 4xx/5xx status codes or failed requests."""
    errors = []
    for req_id, entry in storage.get_all_entries():
        status = entry.response.status
        reason = None

        if status >= 500:
            reason = f"Server error: {status} {entry.response.statusText}"
        elif status >= 400:
            reason = f"Client error: {status} {entry.response.statusText}"
        elif entry.time <= 0 and status == 0:
            reason = "Failed request (no response)"
        elif entry.response.redirectURL and status in (301, 302, 307, 308):
            reason = f"Redirect: {entry.response.redirectURL}"

        if reason:
            errors.append({
                "request_id": req_id,
                "method": entry.request.method,
                "url": entry.request.url,
                "status": status,
                "reason": reason,
            })

    return errors


# ── Slow requests ───────────────────────────────────────────────────────────

def find_slow_requests(
    storage: MemoryStorage,
    threshold_ms: float = 1000,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Find requests exceeding the time threshold."""
    slow = []
    for req_id, entry in storage.get_all_entries():
        if entry.time >= threshold_ms:
            slow.append({
                "request_id": req_id,
                "method": entry.request.method,
                "url": entry.request.url,
                "duration_ms": entry.time,
                "status": entry.response.status,
            })

    slow.sort(key=lambda x: -x["duration_ms"])
    return slow[:limit]


# ── Value tracing ───────────────────────────────────────────────────────────

def trace_value(
    storage: MemoryStorage,
    value: str,
    limit: int = 50,
) -> list[ValueTrace]:
    """Find where a specific value appears across all requests/responses."""
    value_lower = value.lower()
    traces: list[ValueTrace] = []

    for req_id, entry in storage.get_all_entries():
        if len(traces) >= limit:
            break

        req = entry.request
        resp = entry.response

        # Check URL
        if value_lower in req.url.lower():
            traces.append(ValueTrace(request_id=req_id, location="url", match=_truncate(req.url, value)))
            if len(traces) >= limit:
                break

        # Check request headers
        for h in req.headers:
            if value_lower in h.name.lower() or value_lower in h.value.lower():
                traces.append(ValueTrace(request_id=req_id, location="request_headers", match=f"{h.name}: {h.value}"))
                if len(traces) >= limit:
                    break

        # Check request body
        body = get_request_body_text(entry)
        if body and value_lower in body.lower():
            traces.append(ValueTrace(request_id=req_id, location="request_body", match=_truncate(body, value)))
            if len(traces) >= limit:
                break

        # Check response headers
        for h in resp.headers:
            if value_lower in h.name.lower() or value_lower in h.value.lower():
                traces.append(ValueTrace(request_id=req_id, location="response_headers", match=f"{h.name}: {h.value}"))
                if len(traces) >= limit:
                    break

        # Check response body
        resp_body = decode_entry_body(entry)
        if resp_body and value_lower in resp_body.lower():
            traces.append(ValueTrace(request_id=req_id, location="response_body", match=_truncate(resp_body, value)))
            if len(traces) >= limit:
                break

    return traces


def _truncate(text: str, query: str, ctx: int = 60) -> str:
    """Truncate text around a match."""
    idx = text.lower().find(query.lower())
    if idx == -1:
        return text[:ctx * 2]
    start = max(0, idx - ctx)
    end = min(len(text), idx + len(query) + ctx)
    snippet = text[start:end]
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return f"{prefix}{snippet}{suffix}"


# ── Authentication analysis ─────────────────────────────────────────────────

def analyze_auth(storage: MemoryStorage) -> dict[str, Any]:
    """Extract authentication mechanisms from the HAR."""
    auth_mechanisms: list[AuthInfo] = []
    seen_tokens: dict[str, int] = {}  # token_value → first request_id

    for req_id, entry in storage.get_all_entries():
        req = entry.request

        for h in req.headers:
            name_lower = h.name.lower()
            value = h.value

            # Bearer token
            if name_lower == "authorization" and value.lower().startswith("bearer "):
                token = value[7:]
                token_key = token[:20]  # use prefix for dedup
                if token_key not in seen_tokens:
                    seen_tokens[token_key] = req_id
                    auth_mechanisms.append(AuthInfo(
                        type="bearer",
                        header="Authorization",
                        first_seen=req_id,
                        used_by=[req_id],
                        details=f"Bearer token (prefix: {token[:20]}…)",
                    ))
                else:
                    # Add to used_by
                    for auth in auth_mechanisms:
                        if auth.type == "bearer" and auth.first_seen == seen_tokens[token_key]:
                            auth.used_by.append(req_id)
                            break

            # Basic auth
            elif name_lower == "authorization" and value.lower().startswith("basic "):
                auth_mechanisms.append(AuthInfo(
                    type="basic",
                    header="Authorization",
                    first_seen=req_id,
                    used_by=[req_id],
                    details="Basic authentication",
                ))

            # API key headers
            elif name_lower in ("x-api-key", "api-key", "x-auth-token"):
                auth_mechanisms.append(AuthInfo(
                    type="api_key",
                    header=h.name,
                    first_seen=req_id,
                    used_by=[req_id],
                    details=f"API key in {h.name} header",
                ))

        # Check for CSRF tokens in form data
        if req.postData and req.postData.text:
            try:
                body = json.loads(req.postData.text)
                if isinstance(body, dict):
                    for key in body:
                        if "csrf" in key.lower() or "token" in key.lower():
                            auth_mechanisms.append(AuthInfo(
                                type="csrf",
                                first_seen=req_id,
                                used_by=[req_id],
                                details=f"CSRF/token field in body: {key}",
                            ))
            except (json.JSONDecodeError, TypeError):
                pass

        # Check for JWT in cookies
        for cookie in req.cookies:
            if _is_jwt(cookie.value):
                auth_mechanisms.append(AuthInfo(
                    type="jwt",
                    first_seen=req_id,
                    used_by=[req_id],
                    details=f"JWT in cookie: {cookie.name}",
                ))

        # Check for session cookies
        for cookie in req.cookies:
            name_lower = cookie.name.lower()
            if any(s in name_lower for s in ("session", "sid", "jsession", "phpsess", "asp.net_session")):
                auth_mechanisms.append(AuthInfo(
                    type="cookie",
                    first_seen=req_id,
                    used_by=[req_id],
                    details=f"Session cookie: {cookie.name}",
                ))

    # Detect OAuth endpoints
    oauth_endpoints = []
    for req_id, entry in storage.get_all_entries():
        url = entry.request.url.lower()
        if any(s in url for s in ("oauth", "authorize", "token", "callback")):
            oauth_endpoints.append(req_id)

    if oauth_endpoints:
        auth_mechanisms.append(AuthInfo(
            type="oauth",
            first_seen=oauth_endpoints[0],
            used_by=oauth_endpoints,
            details="OAuth-related endpoints detected",
        ))

    return {
        "authentication": [m.model_dump() for m in auth_mechanisms],
        "oauth_endpoints": oauth_endpoints,
    }


def _is_jwt(value: str) -> bool:
    """Check if a string looks like a JWT (three base64url segments)."""
    parts = value.split(".")
    if len(parts) != 3:
        return False
    return all(re.match(r'^[A-Za-z0-9_-]+$', p) for p in parts)


# ── Request chain inference ─────────────────────────────────────────────────

def get_request_chain(
    storage: MemoryStorage,
    start_request_id: int,
    max_depth: int = 10,
) -> dict[str, Any]:
    """Infer request relationships based on timing, cookies, tokens, referer."""
    start_entry = storage.get_entry_by_id(start_request_id)
    if start_entry is None:
        return {"error": True, "code": "REQUEST_NOT_FOUND", "message": f"Request ID {start_request_id} not found"}

    chain: list[ChainEntry] = []
    visited = {start_request_id}

    # Collect cookies/tokens set by start request
    set_cookies = {c.name: c.value for c in start_entry.response.cookies}

    current_id = start_request_id
    for _ in range(max_depth):
        next_entry = _find_next_related(storage, current_id, set_cookies, visited)
        if next_entry is None:
            break
        next_id, reason = next_entry
        chain.append(ChainEntry(request_id=next_id, reason=reason))
        visited.add(next_id)

        # Update cookies from this entry's response
        entry = storage.get_entry_by_id(next_id)
        if entry:
            for c in entry.response.cookies:
                set_cookies[c.name] = c.value

        current_id = next_id

    return {
        "start_request_id": start_request_id,
        "chain": [c.model_dump() for c in chain],
        "note": "Inferred relationships based on timing, cookies, and headers — not definitive.",
    }


def _find_next_related(
    storage: MemoryStorage,
    current_id: int,
    known_cookies: dict[str, str],
    visited: set[int],
) -> tuple[int, str] | None:
    """Find the next request that likely follows from the current one."""
    current = storage.get_entry_by_id(current_id)
    if current is None:
        return None

    current_time = current.startedDateTime
    current_referer = ""
    current_origin = ""
    current_token = ""

    for h in current.request.headers:
        if h.name.lower() == "referer":
            current_referer = h.value
        if h.name.lower() == "origin":
            current_origin = h.value
        if h.name.lower() == "authorization":
            current_token = h.value

    best: tuple[int, str, float] | None = None

    for req_id, entry in storage.get_all_entries():
        if req_id in visited or req_id == current_id:
            continue
        if entry.startedDateTime <= current_time:
            continue

        reason_parts: list[str] = []
        score = 0.0

        # Uses cookies set by current request
        for cookie in entry.request.cookies:
            if cookie.name in known_cookies:
                reason_parts.append(f"uses cookie '{cookie.name}'")
                score += 10

        # Uses authorization token from current
        if current_token:
            for h in entry.request.headers:
                if h.name.lower() == "authorization" and h.value == current_token:
                    reason_parts.append("uses same authorization token")
                    score += 8

        # Referer points to current URL
        if current_referer and entry.request.url == current_referer:
            reason_parts.append("referenced by current request")
            score += 5

        if reason_parts and score > 0:
            time_diff = _parse_time_diff(current_time, entry.startedDateTime)
            if best is None or (score > best[2]) or (score == best[2] and time_diff < best[2]):
                best = (req_id, "; ".join(reason_parts), score)

    if best:
        return (best[0], best[1])
    return None


def _parse_time_diff(t1: str, t2: str) -> float:
    """Simple time difference in seconds between ISO timestamps."""
    try:
        from datetime import datetime
        d1 = datetime.fromisoformat(t1.replace("Z", "+00:00"))
        d2 = datetime.fromisoformat(t2.replace("Z", "+00:00"))
        return abs((d2 - d1).total_seconds())
    except Exception:
        return 999999.0


# ── API pattern detection ───────────────────────────────────────────────────

def detect_api_patterns(storage: MemoryStorage) -> list[APIPattern]:
    """Detect API patterns (REST, GraphQL, JSON API, SSE, WebSocket, etc.)."""
    patterns: list[APIPattern] = []
    all_entries = storage.get_all_entries()

    has_graphql = False
    has_json_api = False
    has_form = False
    has_websocket = False
    has_sse = False
    has_json_content = False
    has_html_content = False
    method_counts: dict[str, int] = defaultdict(int)

    for req_id, entry in all_entries:
        req = entry.request
        resp = entry.response
        method = req.method.upper()
        method_counts[method] += 1

        # GraphQL detection
        if req.postData and req.postData.text:
            try:
                body = json.loads(req.postData.text)
                if isinstance(body, dict) and ("query" in body or "operationName" in body):
                    has_graphql = True
            except (json.JSONDecodeError, TypeError):
                pass

        # JSON API detection
        for h in req.headers:
            if h.name.lower() == "accept" and "application/vnd.api+json" in h.value:
                has_json_api = True
            if h.name.lower() == "content-type" and "application/json" in h.value:
                has_json_content = True

        # Form submission
        if req.postData and req.postData.mimeType == "application/x-www-form-urlencoded":
            has_form = True

        # WebSocket
        if req.url.startswith("ws://") or req.url.startswith("wss://"):
            has_websocket = True

        # SSE detection
        for h in req.headers:
            if h.name.lower() == "accept" and "text/event-stream" in h.value:
                has_sse = True
        if resp.content and resp.content.mimeType == "text/event-stream":
            has_sse = True

        # HTML content
        if resp.content and "text/html" in resp.content.mimeType:
            has_html_content = True

    # REST pattern
    rest_methods = {"GET", "POST", "PUT", "PATCH", "DELETE"}
    used_methods = set(method_counts.keys())
    if len(used_methods & rest_methods) >= 2:
        confidence = min(1.0, len(used_methods & rest_methods) / 5)
        patterns.append(APIPattern(
            pattern="REST",
            confidence=confidence,
            details={"methods_used": list(used_methods & rest_methods)},
        ))

    if has_graphql:
        # Extract GraphQL details
        gql_details: dict[str, Any] = {"type": "GraphQL API detected"}
        for req_id, entry in all_entries:
            if entry.request.postData and entry.request.postData.text:
                try:
                    body = json.loads(entry.request.postData.text)
                    if isinstance(body, dict) and "query" in body:
                        gql_details["operationName"] = body.get("operationName", "unknown")
                        gql_details["has_variables"] = "variables" in body
                        break
                except (json.JSONDecodeError, TypeError):
                    pass
        patterns.append(APIPattern(pattern="GraphQL", confidence=0.9, details=gql_details))

    if has_json_api:
        patterns.append(APIPattern(pattern="JSON_API", confidence=0.8, details={"content_type": "application/vnd.api+json"}))

    if has_form:
        patterns.append(APIPattern(pattern="FormSubmission", confidence=0.7))

    if has_websocket:
        patterns.append(APIPattern(pattern="WebSocket", confidence=0.95))

    if has_sse:
        patterns.append(APIPattern(pattern="SSE", confidence=0.9))

    if has_json_content and not has_graphql:
        patterns.append(APIPattern(pattern="JSON_API_Inferred", confidence=0.5, details={"json_content_type": True}))

    return patterns


# ── Page flow ───────────────────────────────────────────────────────────────

def get_page_flow(storage: MemoryStorage) -> dict[str, Any]:
    """Group requests into a page flow — separate API calls from static assets."""
    static_extensions = {".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                         ".woff", ".woff2", ".ttf", ".eot", ".ico", ".map"}
    api_paths = {"/api", "/graphql", "/v1", "/v2", "/v3"}

    pages: list[dict[str, Any]] = []
    current_page: dict[str, Any] | None = None

    for req_id, entry in storage.get_all_entries():
        req = entry.request
        resp = entry.response
        url = req.url
        path = normalize_url(url).lower()

        # Detect page loads (HTML responses)
        if resp.content and "text/html" in resp.content.mimeType:
            if current_page:
                pages.append(current_page)
            current_page = {
                "page_url": url,
                "request_id": req_id,
                "html": [],
                "css": [],
                "js": [],
                "api_calls": [],
                "auth": [],
                "assets": [],
            }
            continue

        if current_page is None:
            current_page = {
                "page_url": "(initial requests)",
                "request_id": 0,
                "html": [],
                "css": [],
                "js": [],
                "api_calls": [],
                "auth": [],
                "assets": [],
            }

        entry_info = {"request_id": req_id, "url": url, "method": req.method, "status": resp.status}

        # Classify
        from pathlib import PurePosixPath
        ext = PurePosixPath(path).suffix

        if ext in (".css",):
            current_page["css"].append(entry_info)
        elif ext in (".js",):
            current_page["js"].append(entry_info)
        elif any(p in path for p in api_paths) or ext == ".json":
            current_page["api_calls"].append(entry_info)
        elif any(s in path for s in ("login", "auth", "oauth", "token")):
            current_page["auth"].append(entry_info)
        elif ext in static_extensions:
            current_page["assets"].append(entry_info)
        else:
            # Default to API if JSON content type
            if resp.content and "json" in (resp.content.mimeType or ""):
                current_page["api_calls"].append(entry_info)
            else:
                current_page["assets"].append(entry_info)

    if current_page:
        pages.append(current_page)

    return {
        "page_count": len(pages),
        "pages": pages,
    }


# ── Statistics ──────────────────────────────────────────────────────────────

def get_statistics(storage: MemoryStorage) -> dict[str, Any]:
    """Compute aggregate statistics for the HAR."""
    entries = storage.get_all_entries()
    total = len(entries)

    method_counts: dict[str, int] = defaultdict(int)
    status_counts: dict[str, int] = defaultdict(int)
    content_type_counts: dict[str, int] = defaultdict(int)
    domain_counts: dict[str, int] = defaultdict(int)
    durations: list[float] = []
    response_sizes: list[tuple[int, int, str]] = []  # (id, size, url)
    request_sizes: list[tuple[int, int, str]] = []

    for req_id, entry in entries:
        req = entry.request
        resp = entry.response

        method_counts[req.method.upper()] += 1
        status_counts[str(resp.status)] += 1
        domain_counts[extract_domain(req.url)] += 1

        if resp.content and resp.content.mimeType:
            content_type_counts[resp.content.mimeType] += 1

        if entry.time > 0:
            durations.append(entry.time)

        resp_size = resp.bodySize if resp.bodySize > 0 else (resp.content.size if resp.content else 0)
        if resp_size > 0:
            response_sizes.append((req_id, resp_size, req.url))

        req_size = req.bodySize if req.bodySize > 0 else 0
        if req_size <= 0 and req.postData and req.postData.text:
            req_size = len(req.postData.text.encode("utf-8"))
        if req_size > 0:
            request_sizes.append((req_id, req_size, req.url))

    avg_duration = sum(durations) / len(durations) if durations else 0
    response_sizes.sort(key=lambda x: -x[1])
    request_sizes.sort(key=lambda x: -x[1])

    return {
        "total_requests": total,
        "methods": dict(method_counts),
        "status_codes": dict(sorted(status_counts.items())),
        "status_summary": {
            "2xx": sum(v for k, v in status_counts.items() if k.startswith("2")),
            "3xx": sum(v for k, v in status_counts.items() if k.startswith("3")),
            "4xx": sum(v for k, v in status_counts.items() if k.startswith("4")),
            "5xx": sum(v for k, v in status_counts.items() if k.startswith("5")),
        },
        "domains": dict(sorted(domain_counts.items(), key=lambda x: -x[1])),
        "content_types": dict(sorted(content_type_counts.items(), key=lambda x: -x[1])),
        "average_response_time_ms": round(avg_duration, 2),
        "slowest_requests": [{"request_id": r[0], "duration_ms": r[1].time, "url": r[1].request.url} for r in sorted(entries, key=lambda x: -x[1].time)[:5]],
        "largest_responses": [{"request_id": r[0], "size": r[1], "url": r[2]} for r in response_sizes[:5]],
        "largest_requests": [{"request_id": r[0], "size": r[1], "url": r[2]} for r in request_sizes[:5]],
    }


# ── cURL export ─────────────────────────────────────────────────────────────

def export_as_curl(
    storage: MemoryStorage,
    request_id: int,
    redact_secrets: bool = True,
) -> dict[str, Any]:
    """Convert a request to a cURL command string."""
    entry = storage.get_entry_by_id(request_id)
    if entry is None:
        return {"error": True, "code": "REQUEST_NOT_FOUND", "message": f"Request ID {request_id} not found"}

    req = entry.request
    parts = [f"curl '{req.url}'"]

    if req.method.upper() != "GET":
        parts.append(f"-X {req.method.upper()}")

    for h in req.headers:
        name = h.name
        value = h.value
        if redact_secrets:
            from .security import redact_header
            value = redact_header(name, value)
        parts.append(f"-H '{name}: {value}'")

    body = get_request_body_text(entry)
    if body:
        if redact_secrets:
            from .security import redact_text
            body = redact_text(body)
        # Escape single quotes in body
        body_escaped = body.replace("'", "'\\''")
        parts.append(f"--data-raw '{body_escaped}'")

    curl_command = " \\\n  ".join(parts)
    return {"request_id": request_id, "curl": curl_command}
