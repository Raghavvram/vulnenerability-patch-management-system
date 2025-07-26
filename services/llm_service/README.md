# LLM Service (Perplexity Sonar)

## Overview
Analyzes enriched vulnerability data using Perplexity Sonar LLM API.

## Endpoints
- `POST /analyze` - Analyze vulnerabilities.
- `GET /health` - Health check.
- `GET /metrics` - Service metrics.
- `GET /models` - List available LLM models.

## Example Usage
```
curl -X POST http://llm_service:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "enriched_hosts": [ { "ip": "192.168.1.100", ... } ]
}'
```
