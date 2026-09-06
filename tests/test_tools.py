"""Tests for MCP tool functions — all Phase 1, 2, and 3 tools."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from har_mcp.server import (
    load_har, list_requests, get_request, get_response,
    search_requests, list_endpoints, list_domains, get_statistics,
    analyze_endpoint, compare_requests, find_errors, find_slow_requests,
    trace_value, analyze_auth, get_request_chain,
    detect_api_patterns, get_page_flow, export_request_as_curl,
    _loaded_hars,
)
from har_mcp.har_parser import parse_har, compute_har_id
from har_mcp.storage import MemoryStorage
from tests.conftest import SAMPLE_HAR


@pytest.fixture(autouse=True)
def clear_hars():
    """Clear loaded HARs before each test."""
    _loaded_hars.clear()
    yield
    _loaded_hars.clear()


@pytest.fixture
def loaded_har_id() -> str:
    """Load the sample HAR and return its ID."""
    result = load_har(str(SAMPLE_HAR))
    assert "har_id" in result
    return result["har_id"]


# ═══════════════════════════════════════════════════════════════════════════
# Phase 1 — Essential Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestLoadHAR:
    def test_load_valid_har(self):
        result = load_har(str(SAMPLE_HAR))
        assert "har_id" in result
        assert result["version"] == "1.2"
        assert result["request_count"] == 8
        assert "api.example.com" in result["domains"]
        assert "cdn.example.com" in result["domains"]

    def test_load_invalid_path(self):
        result = load_har("/nonexistent/file.har")
        assert result.get("error") is True
        assert result["code"] == "INVALID_PATH"

    def test_load_invalid_har(self, tmp_path: Path):
        bad_file = tmp_path / "bad.har"
        bad_file.write_text("not json")
        result = load_har(str(bad_file))
        assert result.get("error") is True
        assert result["code"] == "PARSE_ERROR"


class TestListRequests:
    def test_list_all(self, loaded_har_id: str):
        result = list_requests(loaded_har_id)
        assert isinstance(result, list)
        assert len(result) == 8
        # Each should have id, method, url, status but no body
        for req in result:
            assert "id" in req
            assert "method" in req
            assert "url" in req
            assert "status" in req
            assert "post_data" not in req  # no body in list

    def test_filter_method(self, loaded_har_id: str):
        posts = list_requests(loaded_har_id, method="POST")
        assert all(r["method"] == "POST" for r in posts)
        assert len(posts) == 4  # login, orders, graphql, upload

    def test_filter_domain(self, loaded_har_id: str):
        cdn = list_requests(loaded_har_id, domain="cdn.example.com")
        assert len(cdn) == 1
        assert "product-1.jpg" in cdn[0]["url"]

    def test_filter_status(self, loaded_har_id: str):
        errors = list_requests(loaded_har_id, status=404)
        assert len(errors) == 1

    def test_filter_path(self, loaded_har_id: str):
        users = list_requests(loaded_har_id, path="/users")
        assert len(users) == 2

    def test_limit(self, loaded_har_id: str):
        limited = list_requests(loaded_har_id, limit=3)
        assert len(limited) == 3

    def test_offset(self, loaded_har_id: str):
        page1 = list_requests(loaded_har_id, limit=3, offset=0)
        page2 = list_requests(loaded_har_id, limit=3, offset=3)
        assert len(page1) == 3
        assert len(page2) == 3
        assert page1[0]["id"] != page2[0]["id"]

    def test_har_not_loaded(self):
        result = list_requests("nonexistent")
        assert result.get("error") is True


class TestGetRequest:
    def test_get_request(self, loaded_har_id: str):
        result = get_request(loaded_har_id, 1)
        assert result["id"] == 1
        assert result["method"] == "GET"
        assert "example.com" in result["url"]
        assert "headers" in result
        assert "cookies" in result
        assert "response" in result
        assert "timings" in result

    def test_get_request_redacted(self, loaded_har_id: str):
        result = get_request(loaded_har_id, 1, redact_secrets=True)
        # Authorization header should be redacted
        auth_headers = [h for h in result["headers"] if h["name"] == "Authorization"]
        assert len(auth_headers) == 1
        assert auth_headers[0]["value"] == "<REDACTED>"

    def test_get_request_unredacted(self, loaded_har_id: str):
        result = get_request(loaded_har_id, 1, redact_secrets=False)
        auth_headers = [h for h in result["headers"] if h["name"] == "Authorization"]
        assert len(auth_headers) == 1
        assert "Bearer" in auth_headers[0]["value"]

    def test_get_request_post_data(self, loaded_har_id: str):
        # Login request (ID 2)
        result = get_request(loaded_har_id, 2)
        assert result["post_data"] is not None
        assert "username" in result["post_data"]["text"]

    def test_get_request_not_found(self, loaded_har_id: str):
        result = get_request(loaded_har_id, 999)
        assert result.get("error") is True
        assert result["code"] == "REQUEST_NOT_FOUND"


class TestGetResponse:
    def test_get_response(self, loaded_har_id: str):
        result = get_response(loaded_har_id, 1)
        assert result["status"] == 200
        assert "headers" in result
        assert "content" in result
        assert result["content"]["mime_type"] == "application/json"
        assert "John Doe" in result["content"]["text"]

    def test_get_response_binary(self, loaded_har_id: str):
        # Image request (ID 5)
        result = get_response(loaded_har_id, 5)
        assert result["content"]["is_binary"] is True
        assert result["content"]["mime_type"] == "image/jpeg"
        assert "text" not in result["content"]  # no text for binary

    def test_get_response_truncation(self, loaded_har_id: str):
        # The upload response has small body, but let's test the structure
        result = get_response(loaded_har_id, 8)
        assert "truncated" in result["content"]
        assert "original_size" in result["content"]

    def test_get_response_not_found(self, loaded_har_id: str):
        result = get_response(loaded_har_id, 999)
        assert result.get("error") is True


class TestSearchRequests:
    def test_search_url(self, loaded_har_id: str):
        results = search_requests(loaded_har_id, "login", scope="url")
        assert len(results) >= 1
        assert any("login" in r["url"] for r in results)

    def test_search_headers(self, loaded_har_id: str):
        results = search_requests(loaded_har_id, "Bearer", scope="headers")
        assert len(results) >= 1

    def test_search_response_body(self, loaded_har_id: str):
        results = search_requests(loaded_har_id, "John Doe", scope="response_body")
        assert len(results) >= 1

    def test_search_request_body(self, loaded_har_id: str):
        results = search_requests(loaded_har_id, "username", scope="request_body")
        assert len(results) >= 1

    def test_search_all(self, loaded_har_id: str):
        results = search_requests(loaded_har_id, "example.com", scope="all")
        assert len(results) >= 1

    def test_search_limit(self, loaded_har_id: str):
        results = search_requests(loaded_har_id, "example", limit=2)
        assert len(results) <= 2


class TestListEndpoints:
    def test_list_endpoints(self, loaded_har_id: str):
        endpoints = list_endpoints(loaded_har_id)
        assert isinstance(endpoints, list)
        assert len(endpoints) > 0
        for ep in endpoints:
            assert "method" in ep
            assert "path" in ep
            assert "count" in ep
            assert "status_codes" in ep

    def test_endpoints_have_ids_normalized(self, loaded_har_id: str):
        endpoints = list_endpoints(loaded_har_id)
        # /v1/users/{id} should exist (two requests with different numeric IDs)
        user_eps = [e for e in endpoints if "{id}" in e["path"] and "users" in e["path"]]
        assert len(user_eps) >= 1


class TestListDomains:
    def test_list_domains(self, loaded_har_id: str):
        domains = list_domains(loaded_har_id)
        assert isinstance(domains, list)
        assert len(domains) == 2  # api.example.com + cdn.example.com
        domain_names = [d["domain"] for d in domains]
        assert "api.example.com" in domain_names
        assert "cdn.example.com" in domain_names


class TestGetStatistics:
    def test_statistics(self, loaded_har_id: str):
        stats = get_statistics(loaded_har_id)
        assert stats["total_requests"] == 8
        assert "GET" in stats["methods"]
        assert "POST" in stats["methods"]
        assert "2xx" in stats["status_summary"]
        assert "4xx" in stats["status_summary"]
        assert "5xx" in stats["status_summary"]
        assert stats["average_response_time_ms"] > 0


# ═══════════════════════════════════════════════════════════════════════════
# Phase 2 — Analysis Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestAnalyzeEndpoint:
    def test_analyze_endpoint(self, loaded_har_id: str):
        result = analyze_endpoint(loaded_har_id, "GET", "/v1/users/12345")
        assert result["request_count"] == 2
        assert 200 in result["status_codes"]
        assert 404 in result["status_codes"]
        assert "parameter_analysis" in result

    def test_analyze_endpoint_not_found(self, loaded_har_id: str):
        result = analyze_endpoint(loaded_har_id, "DELETE", "/nonexistent")
        assert result.get("error") is True


class TestCompareRequests:
    def test_compare_requests(self, loaded_har_id: str):
        # Compare first GET /users with second GET /users (404)
        result = compare_requests(loaded_har_id, 1, 6)
        assert result["request_a"] == 1
        assert result["request_b"] == 6
        assert "url" in result
        assert "method" in result
        assert "request_headers" in result
        assert "response_status" in result

    def test_compare_same_request(self, loaded_har_id: str):
        result = compare_requests(loaded_har_id, 1, 1)
        assert result["url"]["same"] is True
        assert result["method"]["same"] is True

    def test_compare_not_found(self, loaded_har_id: str):
        result = compare_requests(loaded_har_id, 1, 999)
        assert result.get("error") is True


class TestFindErrors:
    def test_find_errors(self, loaded_har_id: str):
        errors = find_errors(loaded_har_id)
        assert len(errors) >= 2  # 404 + 500
        error_ids = [e["request_id"] for e in errors]
        assert 6 in error_ids  # 404
        assert 8 in error_ids  # 500


class TestFindSlowRequests:
    def test_find_slow(self, loaded_har_id: str):
        slow = find_slow_requests(loaded_har_id, threshold_ms=500)
        assert len(slow) >= 1  # upload at 2000ms
        assert slow[0]["duration_ms"] >= 500

    def test_find_slow_high_threshold(self, loaded_har_id: str):
        slow = find_slow_requests(loaded_har_id, threshold_ms=10000)
        assert len(slow) == 0


class TestTraceValue:
    def test_trace_token(self, loaded_har_id: str):
        traces = trace_value(loaded_har_id, "xyz789")
        assert len(traces) >= 1
        assert traces[0]["location"] == "response_body"

    def test_trace_session(self, loaded_har_id: str):
        traces = trace_value(loaded_har_id, "new_session_abc")
        assert len(traces) >= 1

    def test_trace_nonexistent(self, loaded_har_id: str):
        traces = trace_value(loaded_har_id, "ZZZZZ_NOT_FOUND_ZZZZZ")
        assert len(traces) == 0


class TestAnalyzeAuth:
    def test_analyze_auth(self, loaded_har_id: str):
        auth = analyze_auth(loaded_har_id)
        assert "authentication" in auth
        types = [a["type"] for a in auth["authentication"]]
        assert "bearer" in types
        assert "cookie" in types or "session" in str(types).lower()


class TestGetRequestChain:
    def test_request_chain(self, loaded_har_id: str):
        result = get_request_chain(loaded_har_id, 2, max_depth=5)
        assert "start_request_id" in result
        assert "chain" in result
        assert "note" in result
        assert "Inferred" in result["note"]

    def test_chain_not_found(self, loaded_har_id: str):
        result = get_request_chain(loaded_har_id, 999)
        assert result.get("error") is True


# ═══════════════════════════════════════════════════════════════════════════
# Phase 3 — Advanced Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestDetectAPIPatterns:
    def test_detect_patterns(self, loaded_har_id: str):
        patterns = detect_api_patterns(loaded_har_id)
        assert isinstance(patterns, list)
        pattern_names = [p["pattern"] for p in patterns]
        assert "REST" in pattern_names
        assert "GraphQL" in pattern_names
        # JSON_API_Inferred requires JSON content without GraphQL
        # Since our sample has GraphQL, it won't be added


class TestGetPageFlow:
    def test_page_flow(self, loaded_har_id: str):
        flow = get_page_flow(loaded_har_id)
        assert "page_count" in flow
        assert "pages" in flow
        assert flow["page_count"] >= 1


class TestExportAsCurl:
    def test_export_curl(self, loaded_har_id: str):
        result = export_request_as_curl(loaded_har_id, 2)
        assert "curl" in result
        assert "POST" in result["curl"]
        assert "/auth/login" in result["curl"]

    def test_export_curl_redacted(self, loaded_har_id: str):
        result = export_request_as_curl(loaded_har_id, 1, redact_secrets=True)
        assert "<REDACTED>" in result["curl"]

    def test_export_curl_not_found(self, loaded_har_id: str):
        result = export_request_as_curl(loaded_har_id, 999)
        assert result.get("error") is True
