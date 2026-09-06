"""Shared test fixtures for HAR MCP tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Add parent directory to path so we can import har_mcp
sys.path.insert(0, str(Path(__file__).parent.parent))

from har_mcp.har_parser import parse_har, compute_har_id
from har_mcp.storage import MemoryStorage

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_HAR = FIXTURES_DIR / "sample.har"


@pytest.fixture
def sample_har_path() -> Path:
    return SAMPLE_HAR


@pytest.fixture
def sample_har() -> "HARFile":
    return parse_har(SAMPLE_HAR)


@pytest.fixture
def sample_har_id() -> str:
    return compute_har_id(SAMPLE_HAR)


@pytest.fixture
def sample_storage(sample_har, sample_har_id) -> MemoryStorage:
    return MemoryStorage(sample_har_id, sample_har)
