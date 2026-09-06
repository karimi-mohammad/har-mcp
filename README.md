# HAR Analysis MCP Server

A **local, read-only** MCP Server that parses and analyzes HAR (HTTP Archive) files for AI agents.

> Give your AI agent eyes into HTTP traffic — without exposing secrets or leaving your machine.

> ⚠️ **Disclaimer:** This was a weekend vibe-coding project, built almost entirely through AI-assisted pair programming. It works, but it's **not production-hardened**. There may be security holes, edge cases, and rough edges. If you find bugs, open an issue — or better yet, open a PR. Don't trust it with anything you can't afford to lose.

## Why?

When reverse-engineering APIs, debugging web apps, or analyzing traffic, you need to understand what's happening in the network layer. HAR files capture all HTTP traffic, but they're huge JSON blobs that don't fit in an LLM's context.

This MCP server solves that: it parses the HAR locally and exposes **18 targeted tools** that let an AI agent query exactly the parts it needs — one request at a time, with secrets automatically redacted.

## Features

- **Load & parse** HAR 1.2 files (handles missing fields, compressed bodies, base64 content)
- **Smart search** across all requests/responses with scope filters
- **Endpoint discovery** — unique API endpoints with normalization (`/users/123` → `/users/{id}`)
- **Value tracing** — follow tokens, session IDs, JWTs across the entire traffic
- **Authentication detection** — Bearer, Basic, cookies, CSRF, JWT, OAuth, API keys
- **Request comparison** — diff two requests across all dimensions
- **Request chain inference** — login → profile → order flows (heuristic, not definitive)
- **API pattern detection** — REST, GraphQL, JSON API, WebSocket, SSE
- **cURL export** — with automatic secret redaction
- **Security first** — no network access, no code execution, path traversal protection

## Project Structure

```
har-mcp/
├── har_mcp/
│   ├── __init__.py
│   ├── __main__.py        # python -m har_mcp entry point
│   ├── server.py           # MCP server — tool registration & wiring
│   ├── har_parser.py       # HAR 1.2 parsing, decompression, URL normalization
│   ├── analyzer.py         # Smart analysis (auth, patterns, chains, comparison)
│   ├── models.py           # Data models for HAR structures
│   ├── security.py         # Path validation, secret redaction, content sanitization
│   ├── storage.py          # In-memory storage backend
│   └── config.py           # Environment variable configuration
├── tests/
│   ├── conftest.py
│   ├── test_parser.py
│   ├── test_security.py
│   ├── test_tools.py
│   └── fixtures/
│       └── sample.har      # Fake sample HAR for testing
├── sample.har              # Fake sample HAR (example.com only)
├── setup.py
├── requirements.txt
└── README.md
```

## Requirements

- Python 3.11+

## Installation

```bash
# Clone the repo
git clone https://github.com/user/har-mcp.git
cd har-mcp

# Install in editable mode (recommended)
pip install -e .

# Or install dependencies only
pip install -r requirements.txt
```

## Configuration

All configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `HAR_ALLOWED_ROOT` | *(unrestricted)* | Restrict file access to this directory — **strongly recommended** |
| `HAR_MAX_FILE_SIZE` | `524288000` (500MB) | Maximum HAR file size in bytes |
| `HAR_BODY_LIMIT` | `10000` | Max body chars returned to LLM |
| `HAR_REDACT_SECRETS` | `true` | Redact sensitive headers/cookies by default |
| `HAR_LARGE_FILE_THRESHOLD` | `104857600` (100MB) | Threshold for switching to SQLite backend |
| `HAR_LOG_LEVEL` | `INFO` | Logging level |

## MCP Client Setup

### Claude Desktop

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "har-analysis": {
      "command": "python",
      "args": ["-m", "har_mcp.server"],
      "env": {
        "HAR_ALLOWED_ROOT": "/path/to/your/har-files"
      }
    }
  }
}
```

On Windows, use the full Python path if `python` isn't found:

```json
{
  "mcpServers": {
    "har-analysis": {
      "command": "C:\\Users\\you\\AppData\\Local\\Programs\\Python\\Python313\\python.exe",
      "args": ["-m", "har_mcp.server"],
      "env": {
        "HAR_ALLOWED_ROOT": "C:\\path\\to\\har-files"
      }
    }
  }
}
```

### Claude Code

Add to your project's `.mcp.json` or run:

```bash
claude mcp add har-analysis -- python -m har_mcp.server
```

### Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "har-analysis": {
      "command": "python",
      "args": ["-m", "har_mcp.server"]
    }
  }
}
```

### VS Code (Cline / Roo Code)

Add to MCP settings in your VS Code config.

## Available Tools

### Phase 1 — Discovery

| Tool | Description |
|------|-------------|
| `load_har` | Load a HAR file from disk, returns `har_id` |
| `list_requests` | List requests with filters (method, domain, path, status, search, limit, offset) |
| `get_request` | Full request details — headers, cookies, query params, postData |
| `get_response` | Full response — status, headers, cookies, content, timings |
| `search_requests` | Full-text search across URL, headers, request body, response body |
| `list_endpoints` | Unique endpoints with counts and status codes |
| `list_domains` | All domains with request counts |
| `get_statistics` | Aggregate stats — methods, status codes, response times, sizes |

### Phase 2 — Analysis

| Tool | Description |
|------|-------------|
| `analyze_endpoint` | Deep endpoint analysis — parameter classification, header patterns |
| `compare_requests` | Diff two requests across URL, headers, cookies, query, body, response |
| `find_errors` | Find 4xx/5xx/failed requests |
| `find_slow_requests` | Find requests exceeding a time threshold |
| `trace_value` | Trace where a specific value (token, cookie, ID) appears |
| `analyze_auth` | Extract authentication mechanisms from the traffic |
| `get_request_chain` | Infer request relationships (timing, cookies, tokens) |

### Phase 3 — Advanced

| Tool | Description |
|------|-------------|
| `detect_api_patterns` | Detect REST, GraphQL, SSE, WebSocket, form submission |
| `get_page_flow` | Browser page flow overview — API calls vs static assets |
| `export_request_as_curl` | Convert request to cURL command (secrets redacted by default) |

## Example Workflow

```
1. Load the HAR file
   → load_har("recording.har")
   → Returns: har_id, version, request_count, domains

2. Get an overview
   → get_statistics(har_id)
   → See methods, status codes, avg response time, largest responses

3. Find all API endpoints
   → list_endpoints(har_id)
   → GET /api/users (12x, [200])
   → POST /api/login (3x, [200, 401])

4. Search for authentication
   → search_requests(har_id, query="token", scope="all")
   → Find where tokens appear in headers, bodies, cookies

5. Trace a specific token
   → trace_value(har_id, value="eyJ...")
   → See it first appear in POST /login response, then used in subsequent requests

6. Analyze the auth flow
   → analyze_auth(har_id)
   → Detects: Bearer token, session cookie, CSRF token

7. Compare two similar requests
   → compare_requests(har_id, request_a=5, request_b=8)
   → See what changed (different query params, different response)

8. Export as cURL
   → export_request_as_curl(har_id, request_id=12)
   → Ready-to-run command with secrets redacted
```

## Security Model

| Protection | Description |
|------------|-------------|
| **Local only** | Zero outbound HTTP requests — everything stays on your machine |
| **Read-only** | HAR files are never modified |
| **Path traversal** | File access validated against `HAR_ALLOWED_ROOT` |
| **No code execution** | HAR content is never evaluated (no JS, HTML, SQL execution) |
| **Secret redaction** | `Authorization`, `Cookie`, `Set-Cookie`, `API-Key`, `X-API-Key`, `CSRF`, JWTs are masked by default |
| **Binary content** | Only metadata returned for images/PDFs/etc., never raw binary |
| **Body truncation** | Large bodies truncated with `{ "truncated": true, "original_size": N }` |
| **Log sanitization** | Secrets stripped from all log output |

To see unredacted values, pass `redact_secrets: false` to `get_request` or `get_response`.

## Testing

```bash
# Install test dependencies
pip install -e ".[dev]"

# Run all tests (111 tests)
pytest tests/ -v

# Run specific test file
pytest tests/test_parser.py -v
pytest tests/test_security.py -v
pytest tests/test_tools.py -v

# Run with coverage
pytest tests/ --cov=har_mcp
```

## Limitations

- SQLite backend for very large HARs (>100MB) is planned but not yet implemented
- WebSocket frame content is not parsed
- Request chain inference is heuristic — relationships are **inferred**, not definitive
- Some non-standard compressed bodies may not decode

## License

MIT
