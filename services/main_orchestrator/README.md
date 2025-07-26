# Main Orchestrator Service

## Overview
The Main Orchestrator coordinates the vulnerability management workflow by calling parser, enricher, LLM, and prioritization services.

## Endpoints
- `POST /scan/process` - Submit Nmap XML scan results for full workflow processing.
- `GET /health` - Health check.
- `GET /metrics` - Service metrics.

## Example Usage
```
curl -X POST http://localhost:8000/scan/process \
  -H "Content-Type: application/json" \
  -d '{
    "xml_content": "<nmaprun ...>...</nmaprun>"
}'
```

## Notes
- All internal service calls use Docker DNS names (e.g., `parser_service:8000`).
- Only this service is exposed to the host on port 8000.
