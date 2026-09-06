# HAR Analysis MCP Server

A local, read-only MCP Server that parses and analyzes HAR (HTTP Archive) files for AI agents.

## Features

- **Load & parse** HAR 1.2 files with graceful handling of missing fields
- **Search** across all requests/responses with full-text search
- **Analyze endpoints** — parameter classification (dynamic/constant/variable), header patterns
- **Trace values** — follow tokens, session IDs, JWTs across the entire traffic
- **Detect authentication** — Bearer, Basic, cookies, CSRF, JWT, OAuth, API keys
- **Compare requests** — diff two requests across all dimensions
- **Infer request chains** — login → profile → order flows
- **Detect API patterns** — REST, GraphQL, JSON API, WebSocket, SSE
- **Export as cURL** — with automatic secret redaction
- **Security first** — no network access, no code execution, path traversal protection

## Requirements

- Python 3.11+

## Installation

```bash
# Clone or download the project
cd har-mcp

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Running the MCP Server

```bash
# Default (stdio transport)
python -m har_mcp.server

# With restricted file access
HAR_ALLOWED_ROOT=/path/to/har-files python -m har_mcp.server
```

### CLI Entry Point

```bash
har-mcp
# or
har-mcp --allowed-root ./har-files
```

## Configuration

All configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `HAR_ALLOWED_ROOT` | None (unrestricted) | Restrict file access to this directory |
| `HAR_MAX_FILE_SIZE` | 524288000 (500MB) | Maximum HAR file size in bytes |
| `HAR_BODY_LIMIT` | 10000 | Max body chars returned to LLM |
| `HAR_REDACT_SECRETS` | true | Redact sensitive headers/cookies by default |
| `HAR_LARGE_FILE_THRESHOLD` | 104857600 (100MB) | Threshold for SQLite backend |
| `HAR_LOG_LEVEL` | INFO | Logging level |

## MCP Client Configuration

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

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

### VS Code (Continue / Cline)

Add to MCP settings:

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

## Available Tools

### Phase 1 — Essential

| Tool | Description |
|------|-------------|
| `load_har` | Load a HAR file from disk |
| `list_requests` | List requests with filters (method, domain, path, status, search) |
| `get_request` | Full request details (headers, cookies, query, postData) |
| `get_response` | Full response (headers, cookies, content, timings) |
| `search_requests` | Full-text search across URL/headers/body |
| `list_endpoints` | Unique endpoints with counts |
| `list_domains` | All domains with request counts |
| `get_statistics` | Aggregate statistics |

### Phase 2 — Analysis

| Tool | Description |
|------|-------------|
| `analyze_endpoint` | Deep endpoint analysis with param classification |
| `compare_requests` | Diff two requests side by side |
| `find_errors` | Find 4xx/5xx/failed requests |
| `find_slow_requests` | Find requests above time threshold |
| `trace_value` | Trace where a value appears across all traffic |
| `analyze_auth` | Extract authentication mechanisms |
| `get_request_chain` | Infer request relationships |

### Phase 3 — Advanced

| Tool | Description |
|------|-------------|
| `detect_api_patterns` | Detect REST, GraphQL, SSE, WebSocket patterns |
| `get_page_flow` | Browser page flow overview |
| `export_request_as_curl` | Convert request to cURL (secrets redacted by default) |

## Example Workflow

```
1. load_har("path/to/recording.har")
   → Returns: har_id, request_count, domains

2. list_domains(har_id="abc123")
   → See all domains and their request counts

3. list_endpoints(har_id="abc123")
   → See all API endpoints

4. search_requests(har_id="abc123", query="token", scope="all")
   → Find where tokens appear

5. trace_value(har_id="abc123", value="eyJ...")
   → Follow a JWT through the traffic

6. analyze_auth(har_id="abc123")
   → Understand the authentication flow

7. get_request_chain(har_id="abc123", start_request_id=2)
   → See the request sequence after login

8. analyze_endpoint(har_id="abc123", method="POST", url_pattern="/v1/orders")
   → Deep analysis of the orders endpoint
```

## Security Model

- **Local only** — no outbound HTTP requests
- **Read-only** — HAR files are never modified
- **Path traversal protection** — file access validated against allowed root
- **No code execution** — HAR content is never evaluated (no JS, HTML, SQL)
- **Secret redaction** — Authorization, Cookie, API keys, JWTs are redacted by default
- **Binary content** — only metadata returned, never raw binary
- **Body truncation** — large bodies truncated with size metadata
- **Log sanitization** — secrets stripped from all log output

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_parser.py -v

# Run with coverage
pytest tests/ --cov=har_mcp
```

## Limitations

- SQLite backend for large HARs (>100MB) is planned but not yet implemented
- WebSocket frame content is not parsed
- Some compressed bodies may not decode if encoding is non-standard
- Request chain inference is heuristic, not definitive

## License

MIT
