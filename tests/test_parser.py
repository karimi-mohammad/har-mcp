"""Tests for HAR parser — parsing, decompression, normalization."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from har_mcp.har_parser import (
    parse_har, compute_har_id, normalize_url, normalize_path,
    extract_domain, extract_query_params, decode_entry_body,
)
from har_mcp.models import HARFile


class TestParseHAR:
    """Test HAR file parsing."""

    def test_parse_valid_har(self, sample_har_path: Path):
        har = parse_har(sample_har_path)
        assert isinstance(har, HARFile)
        assert har.log.version == "1.2"
        assert har.log.creator.name == "Chrome DevTools"
        assert len(har.log.entries) == 8

    def test_parse_har_has_entries(self, sample_har: HARFile):
        assert len(sample_har.log.entries) > 0
        first = sample_har.log.entries[0]
        assert first.request.method == "GET"
        assert "example.com" in first.request.url

    def test_parse_har_request_details(self, sample_har: HARFile):
        entry = sample_har.log.entries[0]
        assert entry.request.httpVersion == "HTTP/2.0"
        assert len(entry.request.headers) == 4
        assert entry.request.headers[0].name == "Accept"

    def test_parse_har_response_details(self, sample_har: HARFile):
        entry = sample_har.log.entries[0]
        assert entry.response.status == 200
        assert entry.response.content.mimeType == "application/json"
        assert entry.response.content.size == 256

    def test_parse_har_timings(self, sample_har: HARFile):
        entry = sample_har.log.entries[0]
        assert entry.timings.send == 1
        assert entry.timings.wait == 100
        assert entry.timings.receive == 17

    def test_parse_har_post_data(self, sample_har: HARFile):
        # Find the login POST request
        login = [e for e in sample_har.log.entries if "/auth/login" in e.request.url][0]
        assert login.request.postData is not None
        assert login.request.postData.mimeType == "application/json"
        assert "username" in login.request.postData.text

    def test_parse_har_cookies(self, sample_har: HARFile):
        entry = sample_har.log.entries[0]
        assert len(entry.response.cookies) == 1
        assert entry.response.cookies[0].name == "session_id"

    def test_parse_empty_har(self, tmp_path: Path):
        """Parse a HAR with no entries."""
        har_data = {"log": {"version": "1.2", "creator": {"name": "test"}, "entries": []}}
        har_file = tmp_path / "empty.har"
        har_file.write_text(json.dumps(har_data))

        har = parse_har(har_file)
        assert len(har.log.entries) == 0

    def test_parse_har_missing_fields(self, tmp_path: Path):
        """Parse a HAR with missing optional fields — should not crash."""
        har_data = {
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "startedDateTime": "2024-01-01T00:00:00Z",
                        "time": 100,
                        "request": {"method": "GET", "url": "https://example.com"},
                        "response": {"status": 200, "content": {"text": "hello"}},
                        "timings": {"send": 0, "wait": 50, "receive": 50},
                    }
                ],
            }
        }
        har_file = tmp_path / "minimal.har"
        har_file.write_text(json.dumps(har_data))

        har = parse_har(har_file)
        assert len(har.log.entries) == 1
        assert har.log.entries[0].request.method == "GET"

    def test_parse_invalid_json(self, tmp_path: Path):
        """Should raise on invalid JSON."""
        bad_file = tmp_path / "bad.har"
        bad_file.write_text("not json at all")
        with pytest.raises(json.JSONDecodeError):
            parse_har(bad_file)

    def test_parse_missing_log_key(self, tmp_path: Path):
        """Should raise on missing log key."""
        bad_file = tmp_path / "nolog.har"
        bad_file.write_text("{}")
        with pytest.raises(ValueError, match="missing 'log'"):
            parse_har(bad_file)


class TestComputeHarId:
    """Test HAR ID computation."""

    def test_deterministic_id(self, sample_har_path: Path):
        id1 = compute_har_id(sample_har_path)
        id2 = compute_har_id(sample_har_path)
        assert id1 == id2

    def test_id_length(self, sample_har_path: Path):
        har_id = compute_har_id(sample_har_path)
        assert len(har_id) == 12

    def test_different_files_different_ids(self, tmp_path: Path):
        f1 = tmp_path / "a.har"
        f2 = tmp_path / "b.har"
        f1.write_text('{"log":{"entries":[]}}')
        f2.write_text('{"log":{"entries":[1]}}')
        assert compute_har_id(f1) != compute_har_id(f2)


class TestURLNormalization:
    """Test URL normalization utilities."""

    def test_normalize_url_strips_query(self):
        assert normalize_url("https://api.example.com/v1/users?page=1") == "/v1/users"

    def test_normalize_url_keeps_path(self):
        assert normalize_url("https://example.com/api/test") == "/api/test"

    def test_normalize_path_numeric_id(self):
        assert normalize_path("/api/users/12345") == "/api/users/{id}"

    def test_normalize_path_uuid(self):
        assert normalize_path("/api/items/550e8400-e29b-41d4-a716-446655440000") == "/api/items/{id}"

    def test_normalize_path_no_id(self):
        assert normalize_path("/api/users/me") == "/api/users/me"

    def test_normalize_path_multiple_ids(self):
        assert normalize_path("/api/org/123/user/456") == "/api/org/{id}/user/{id}"

    def test_extract_domain(self):
        assert extract_domain("https://api.example.com/v1/test") == "api.example.com"

    def test_extract_domain_no_subdomain(self):
        assert extract_domain("https://example.com") == "example.com"

    def test_extract_query_params(self):
        params = extract_query_params("https://example.com/api?foo=bar&baz=123")
        assert params == {"foo": "bar", "baz": "123"}

    def test_extract_query_params_empty(self):
        params = extract_query_params("https://example.com/api")
        assert params == {}


class TestDecodeContent:
    """Test response body decoding."""

    def test_decode_json(self, sample_har: HARFile):
        entry = sample_har.log.entries[0]
        text = decode_entry_body(entry)
        assert "John Doe" in text

    def test_decode_empty(self, sample_har: HARFile):
        # Image entry has no text
        image_entry = [e for e in sample_har.log.entries if "product-1.jpg" in e.request.url][0]
        text = decode_entry_body(image_entry)
        assert text == ""
