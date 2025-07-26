# Prioritization Engine

## Overview
Assigns priority and SLA timelines to analyzed vulnerabilities using ML and rule-based logic.

## Endpoints
- `POST /prioritize` - Prioritize vulnerabilities.
- `GET /health` - Health check.
- `GET /metrics` - Service metrics.

## Example Usage
```
curl -X POST http://prioritization_engine:8000/prioritize \
  -H "Content-Type: application/json" \
  -d '{
    "analyzed_hosts": [ { "ip": "192.168.1.100", ... } ]
}'
```
