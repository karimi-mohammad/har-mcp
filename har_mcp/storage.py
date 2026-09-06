"""Storage backend — in-memory indexed storage for parsed HAR entries."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .models import (
    HARFile, HAREntry, RequestSummary, SearchResult, EndpointInfo, DomainInfo,
)
from .har_parser import (
    normalize_url, normalize_path, extract_domain, extract_query_params,
    decode_entry_body, get_request_body_text,
)


class MemoryStorage:
    """In-memory indexed storage for a single loaded HAR file.

    Provides fast lookup by ID, filtered queries, full-text search,
    and pre-computed indexes for domains and endpoints.
    """

    def __init__(self, har_id: str, har: HARFile):
        self.har_id = har_id
        self.har = har
        self._entries: list[HAREntry] = har.log.entries

        # Build indexes
        self._domain_index: dict[str, list[int]] = defaultdict(list)
        self._endpoint_index: dict[tuple[str, str], list[int]] = defaultdict(list)
        self._url_index: dict[int, str] = {}
        self._normalized_path_index: dict[int, str] = {}

        for i, entry in enumerate(self._entries):
            url = entry.request.url
            domain = extract_domain(url)
            norm_url = normalize_url(url)
            norm_path = normalize_path(norm_url)
            method = entry.request.method.upper()

            self._domain_index[domain].append(i)
            self._endpoint_index[(method, norm_url)].append(i)
            self._url_index[i] = url
            self._normalized_path_index[i] = norm_path

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    def get_entry(self, index: int) -> HAREntry | None:
        """Get entry by 0-based index."""
        if 0 <= index < len(self._entries):
            return self._entries[index]
        return None

    def get_entry_by_id(self, request_id: int) -> HAREntry | None:
        """Get entry by 1-based request ID."""
        return self.get_entry(request_id - 1)

    def list_requests(
        self,
        method: str | None = None,
        domain: str | None = None,
        path: str | None = None,
        status: int | None = None,
        content_type: str | None = None,
        search: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[RequestSummary]:
        """List request summaries with optional filters."""
        results: list[RequestSummary] = []

        for i, entry in enumerate(self._entries):
            req = entry.request
            resp = entry.response
            method_upper = req.method.upper() if method else None
            domain_str = extract_domain(req.url)
            norm_url = normalize_url(req.url)
            ct = resp.content.mimeType if resp.content else ""

            # Apply filters
            if method and method_upper != method.upper():
                continue
            if domain and domain_str != domain:
                continue
            if path and path.lower() not in norm_url.lower():
                continue
            if status and resp.status != status:
                continue
            if content_type and content_type.lower() not in ct.lower():
                continue
            if search:
                search_lower = search.lower()
                searchable = f"{req.url} {norm_url} ".lower()
                # Also search headers
                for h in req.headers:
                    searchable += f"{h.name}: {h.value} ".lower()
                for h in resp.headers:
                    searchable += f"{h.name}: {h.value} ".lower()
                if search_lower not in searchable:
                    continue

            # Compute sizes
            req_size = req.bodySize if req.bodySize > 0 else 0
            if req_size <= 0 and req.postData and req.postData.text:
                req_size = len(req.postData.text.encode("utf-8"))
            resp_size = resp.bodySize if resp.bodySize > 0 else 0
            if resp_size <= 0 and resp.content:
                resp_size = resp.content.size

            results.append(RequestSummary(
                id=i + 1,
                method=method_upper or req.method,
                url=req.url,
                status=resp.status,
                content_type=ct,
                request_size=req_size,
                response_size=resp_size,
                started_at=entry.startedDateTime,
                duration_ms=entry.time,
            ))

        total = len(results)
        return results[offset:offset + limit]

    def search_entries(
        self,
        query: str,
        scope: str = "all",
        limit: int = 50,
    ) -> list[SearchResult]:
        """Full-text search across requests/responses."""
        query_lower = query.lower()
        results: list[SearchResult] = []

        for i, entry in enumerate(self._entries):
            if len(results) >= limit:
                break

            req = entry.request
            resp = entry.response
            req_id = i + 1
            url = req.url

            # Search URL
            if scope in ("all", "url"):
                if query_lower in url.lower():
                    results.append(SearchResult(
                        request_id=req_id,
                        location="url",
                        match=_truncate_match(url, query_lower),
                        url=url,
                        method=req.method,
                    ))
                    if len(results) >= limit:
                        break

            # Search headers
            if scope in ("all", "headers"):
                for h in req.headers:
                    if query_lower in h.name.lower() or query_lower in h.value.lower():
                        results.append(SearchResult(
                            request_id=req_id,
                            location="request_headers",
                            match=f"{h.name}: {_truncate_match(h.value, query_lower)}",
                            url=url,
                            method=req.method,
                        ))
                        if len(results) >= limit:
                            break
                if len(results) >= limit:
                    break
                for h in resp.headers:
                    if query_lower in h.name.lower() or query_lower in h.value.lower():
                        results.append(SearchResult(
                            request_id=req_id,
                            location="response_headers",
                            match=f"{h.name}: {_truncate_match(h.value, query_lower)}",
                            url=url,
                            method=req.method,
                        ))
                        if len(results) >= limit:
                            break
                if len(results) >= limit:
                    break

            # Search request body
            if scope in ("all", "request_body"):
                body = get_request_body_text(entry)
                if body and query_lower in body.lower():
                    results.append(SearchResult(
                        request_id=req_id,
                        location="request_body",
                        match=_truncate_match(body, query_lower),
                        url=url,
                        method=req.method,
                    ))
                    if len(results) >= limit:
                        break

            # Search response body
            if scope in ("all", "response_body"):
                resp_body = decode_entry_body(entry)
                if resp_body and query_lower in resp_body.lower():
                    results.append(SearchResult(
                        request_id=req_id,
                        location="response_body",
                        match=_truncate_match(resp_body, query_lower),
                        url=url,
                        method=req.method,
                    ))
                    if len(results) >= limit:
                        break

        return results

    def get_domains(self) -> list[DomainInfo]:
        """Return all domains with request counts."""
        return sorted(
            [DomainInfo(domain=d, request_count=len(ids)) for d, ids in self._domain_index.items()],
            key=lambda x: x.request_count,
            reverse=True,
        )

    def get_endpoints(self) -> list[EndpointInfo]:
        """Return unique endpoints (method + normalized path) with counts."""
        endpoint_map: dict[tuple[str, str], dict[str, Any]] = {}

        for (method, norm_url), indices in self._endpoint_index.items():
            norm_path = normalize_path(norm_url)
            key = (method, norm_path)
            if key not in endpoint_map:
                endpoint_map[key] = {"count": 0, "status_codes": set()}
            endpoint_map[key]["count"] += len(indices)
            for idx in indices:
                endpoint_map[key]["status_codes"].add(self._entries[idx].response.status)

        return sorted(
            [
                EndpointInfo(
                    method=m,
                    path=p,
                    count=info["count"],
                    status_codes=sorted(info["status_codes"]),
                )
                for (m, p), info in endpoint_map.items()
            ],
            key=lambda x: (x.method, x.path),
        )

    def get_entries_for_endpoint(self, method: str, url_pattern: str) -> list[tuple[int, HAREntry]]:
        """Get all entries matching a specific endpoint pattern."""
        results = []
        norm_pattern = normalize_path(url_pattern)

        for i, entry in enumerate(self._entries):
            req = entry.request
            if req.method.upper() != method.upper():
                continue
            norm_url = normalize_url(req.url)
            norm_path = normalize_path(norm_url)
            if norm_path == norm_pattern or url_pattern in req.url:
                results.append((i + 1, entry))

        return results

    def get_all_entries(self) -> list[tuple[int, HAREntry]]:
        """Return all entries with their 1-based IDs."""
        return [(i + 1, entry) for i, entry in enumerate(self._entries)]

    def get_domains_for_entry(self, entry_index: int) -> str:
        """Get the domain for a specific entry."""
        entry = self._entries[entry_index]
        return extract_domain(entry.request.url)


def _truncate_match(text: str, query: str, context_chars: int = 80) -> str:
    """Return a truncated snippet around the first match of *query* in *text*."""
    idx = text.lower().find(query)
    if idx == -1:
        return text[:context_chars * 2]

    start = max(0, idx - context_chars)
    end = min(len(text), idx + len(query) + context_chars)
    snippet = text[start:end]

    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return f"{prefix}{snippet}{suffix}"
