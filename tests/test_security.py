"""Tests for security module — path validation, secret redaction, content detection."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from har_mcp.security import (
    validate_path, redact_header, redact_cookie, redact_text,
    redact_headers, redact_cookies, is_binary_content, is_text_content,
    sanitize_for_log,
)
from har_mcp.config import Config, set_config


@pytest.fixture
def unrestricted_config():
    """Config with no allowed root."""
    set_config(Config(allowed_root=None))
    yield
    set_config(Config())  # reset


@pytest.fixture
def restricted_config(tmp_path: Path):
    """Config with restricted root."""
    set_config(Config(allowed_root=tmp_path))
    yield
    set_config(Config())  # reset


class TestValidatePath:
    def test_valid_path(self, tmp_path: Path):
        test_file = tmp_path / "test.har"
        test_file.write_text("{}")
        result = validate_path(str(test_file))
        assert result == test_file

    def test_nonexistent_file(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            validate_path(str(tmp_path / "nonexistent.har"))

    def test_path_traversal(self, tmp_path: Path):
        """Path traversal should be blocked."""
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        (allowed / "test.har").write_text("{}")

        set_config(Config(allowed_root=allowed))
        try:
            with pytest.raises(ValueError, match="traversal"):
                validate_path(str(tmp_path / "forbidden.har"), allowed_root=allowed)
        finally:
            set_config(Config())

    def test_relative_traversal(self, tmp_path: Path):
        """Relative path traversal should be blocked."""
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        (allowed / "test.har").write_text("{}")

        set_config(Config(allowed_root=allowed))
        try:
            with pytest.raises((ValueError, FileNotFoundError)):
                validate_path("../test.har", allowed_root=allowed)
        finally:
            set_config(Config())

    def test_not_a_file(self, tmp_path: Path):
        """Directories should be rejected."""
        with pytest.raises(ValueError, match="Not a file"):
            validate_path(str(tmp_path))


class TestRedactHeader:
    def test_redact_authorization(self):
        result = redact_header("Authorization", "Bearer secret123")
        assert result == "<REDACTED>"

    def test_redact_cookie(self):
        result = redact_header("Cookie", "session=abc123")
        assert result == "<REDACTED>"

    def test_redact_set_cookie(self):
        result = redact_header("Set-Cookie", "session=abc123; Path=/")
        assert result == "<REDACTED>"

    def test_redact_api_key(self):
        result = redact_header("X-API-Key", "key_12345")
        assert result == "<REDACTED>"

    def test_redact_xsrf(self):
        result = redact_header("X-CSRF-Token", "token123")
        assert result == "<REDACTED>"

    def test_no_redact_normal_header(self):
        result = redact_header("Content-Type", "application/json")
        assert result == "application/json"

    def test_no_redact_user_agent(self):
        result = redact_header("User-Agent", "Mozilla/5.0")
        assert result == "Mozilla/5.0"

    def test_redact_bearer_in_value(self):
        """Bearer token pattern in any header value should be redacted."""
        result = redact_header("X-Custom", "Bearer abc123")
        assert "<REDACTED>" in result


class TestRedactCookie:
    def test_redact_session_cookie(self):
        name, value = redact_cookie("session_id", "abc123")
        assert name == "session_id"
        assert value == "<REDACTED>"

    def test_redact_token_cookie(self):
        name, value = redact_cookie("access_token", "xyz789")
        assert value == "<REDACTED>"

    def test_no_redact_normal_cookie(self):
        name, value = redact_cookie("theme", "dark")
        assert value == "dark"


class TestRedactText:
    def test_redact_jwt_in_text(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = redact_text(f"token: {jwt}")
        assert jwt not in result
        assert "<REDACTED>" in result

    def test_redact_bearer_in_text(self):
        result = redact_text("Authorization: Bearer mytoken123")
        assert "mytoken123" not in result
        assert "<REDACTED>" in result

    def test_redact_basic_in_text(self):
        result = redact_text("Basic dXNlcjpwYXNz")
        assert "dXNlcjpwYXNz" not in result
        assert "<REDACTED>" in result

    def test_no_redact_normal_text(self):
        result = redact_text("Hello world, no secrets here")
        assert result == "Hello world, no secrets here"


class TestRedactHeaders:
    def test_redact_multiple(self):
        headers = [
            {"name": "Authorization", "value": "Bearer secret"},
            {"name": "Content-Type", "value": "application/json"},
            {"name": "Cookie", "value": "session=abc"},
        ]
        result = redact_headers(headers)
        assert result[0]["value"] == "<REDACTED>"
        assert result[1]["value"] == "application/json"
        assert result[2]["value"] == "<REDACTED>"


class TestRedactCookies:
    def test_redact_multiple(self):
        cookies = [
            {"name": "session_id", "value": "abc123"},
            {"name": "theme", "value": "dark"},
        ]
        result = redact_cookies(cookies)
        assert result[0]["value"] == "<REDACTED>"
        assert result[1]["value"] == "dark"


class TestBinaryDetection:
    def test_is_binary_image(self):
        assert is_binary_content("image/png") is True
        assert is_binary_content("image/jpeg") is True
        assert is_binary_content("image/gif") is True

    def test_is_binary_video(self):
        assert is_binary_content("video/mp4") is True

    def test_is_binary_audio(self):
        assert is_binary_content("audio/mpeg") is True

    def test_is_binary_pdf(self):
        assert is_binary_content("application/pdf") is True

    def test_is_binary_octet(self):
        assert is_binary_content("application/octet-stream") is True

    def test_not_binary_json(self):
        assert is_binary_content("application/json") is False

    def test_not_binary_text(self):
        assert is_binary_content("text/html") is False

    def test_not_binary_xml(self):
        assert is_binary_content("text/xml") is False

    def test_not_binary_empty(self):
        assert is_binary_content("") is False

    def test_binary_with_charset(self):
        assert is_binary_content("image/png; charset=utf-8") is True

    def test_text_content(self):
        assert is_text_content("application/json") is True
        assert is_text_content("") is True
        assert is_text_content("image/png") is False


class TestSanitizeForLog:
    def test_sanitize_bearer(self):
        result = sanitize_for_log("Bearer secrettoken123")
        assert "secrettoken123" not in result
        assert "<REDACTED>" in result

    def test_sanitize_truncate(self):
        long = "x" * 300
        result = sanitize_for_log(long, max_len=100)
        assert len(result) < 150
        assert "…" in result

    def test_sanitize_short(self):
        result = sanitize_for_log("short", max_len=100)
        assert result == "short"
