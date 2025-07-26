# Enricher Service

## Overview
Enriches parsed scan data with vulnerability information and stores results in PostgreSQL.

## Endpoints
- `POST /enrich` - Enrich host/service data.
- `GET /health` - Health check.
- `GET /metrics` - Service metrics.

## Example Usage
```
curl -X POST http://enricher_service:8000/enrich \
  -H "Content-Type: application/json" \
  -d '{
    "hosts": [ { "ip": "192.168.1.100", ... } ]
}'
```
