# Parser Service

## Overview
Parses Nmap XML scan results and returns structured JSON.

## Endpoints
- `POST /parse/xml` - Parse Nmap XML.
- `GET /health` - Health check.
- `GET /metrics` - Service metrics.

## Example Usage
```
curl -X POST http://parser_service:8000/parse/xml \
  -H "Content-Type: application/json" \
  -d '{
    "xml_content": "<nmaprun ...>...</nmaprun>"
}'
```
