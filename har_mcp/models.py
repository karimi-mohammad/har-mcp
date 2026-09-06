"""Pydantic data models for HAR 1.2 structures."""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


# ── Low-level HAR structures ────────────────────────────────────────────────

class HARHeader(BaseModel):
    name: str = ""
    value: str = ""


class HARCookie(BaseModel):
    name: str = ""
    value: str = ""
    path: str = ""
    domain: str = ""
    expires: str = ""
    httpOnly: bool = False
    secure: bool = False
    comment: str = ""


class HARQueryParameter(BaseModel):
    name: str = ""
    value: str = ""
    comment: str = ""


class HARPostData(BaseModel):
    mimeType: str = ""
    text: str = ""
    params: list[dict[str, Any]] = Field(default_factory=list)
    comment: str = ""


class HARRequest(BaseModel):
    method: str = ""
    url: str = ""
    httpVersion: str = ""
    cookies: list[HARCookie] = Field(default_factory=list)
    headers: list[HARHeader] = Field(default_factory=list)
    queryString: list[HARQueryParameter] = Field(default_factory=list)
    postData: HARPostData | None = None
    headersSize: int = -1
    bodySize: int = -1
    comment: str = ""


class HARContent(BaseModel):
    size: int = 0
    mimeType: str = ""
    text: str = ""
    encoding: str = ""  # "base64" when applicable
    comment: str = ""


class HARResponse(BaseModel):
    status: int = 0
    statusText: str = ""
    httpVersion: str = ""
    cookies: list[HARCookie] = Field(default_factory=list)
    headers: list[HARHeader] = Field(default_factory=list)
    content: HARContent = Field(default_factory=HARContent)
    redirectURL: str = ""
    headersSize: int = -1
    bodySize: int = -1
    comment: str = ""


class HARTiming(BaseModel):
    blocked: float = -1
    dns: float = -1
    connect: float = -1
    send: float = 0
    wait: float = 0
    receive: float = 0
    ssl: float = -1
    comment: str = ""


class HARCreator(BaseModel):
    name: str = ""
    version: str = ""
    comment: str = ""


class HAREntry(BaseModel):
    startedDateTime: str = ""
    time: float = 0
    request: HARRequest = Field(default_factory=HARRequest)
    response: HARResponse = Field(default_factory=HARResponse)
    cache: dict[str, Any] = Field(default_factory=dict)
    timings: HARTiming = Field(default_factory=HARTiming)
    serverIPAddress: str = ""
    connection: str = ""
    comment: str = ""


class HARLog(BaseModel):
    version: str = ""
    creator: HARCreator = Field(default_factory=HARCreator)
    entries: list[HAREntry] = Field(default_factory=list)
    comment: str = ""


class HARFile(BaseModel):
    log: HARLog = Field(default_factory=HARLog)


# ── Derived / summary models ────────────────────────────────────────────────

class RequestSummary(BaseModel):
    """Lightweight summary for list operations — no body content."""
    id: int
    method: str
    url: str
    status: int
    content_type: str = ""
    request_size: int = 0
    response_size: int = 0
    started_at: str = ""
    duration_ms: float = 0


class SearchResult(BaseModel):
    request_id: int
    location: str  # "url", "headers", "request_body", "response_body"
    match: str
    url: str
    method: str


class EndpointInfo(BaseModel):
    method: str
    path: str
    count: int = 0
    status_codes: list[int] = Field(default_factory=list)


class DomainInfo(BaseModel):
    domain: str
    request_count: int = 0


class AuthInfo(BaseModel):
    type: str  # "bearer", "basic", "cookie", "csrf", "jwt", "api_key", "oauth"
    header: str = ""
    first_seen: int = 0
    used_by: list[int] = Field(default_factory=list)
    details: str = ""


class ChainEntry(BaseModel):
    request_id: int
    reason: str


class ValueTrace(BaseModel):
    request_id: int
    location: str  # "request_headers", "request_body", "response_headers", "response_body", "url", "cookies"
    match: str


class APIPattern(BaseModel):
    pattern: str  # "REST", "GraphQL", "JSON_API", etc.
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class HAROverview(BaseModel):
    har_id: str
    version: str
    request_count: int
    domains: list[str]
    endpoints: int
    auth_mechanisms: list[str]
    error_count: int
    slow_request_count: int
