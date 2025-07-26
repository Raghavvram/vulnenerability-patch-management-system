psql -U vulnuser -d vulndb


echo "Enter Grafana admin password:"
read -s GF_SECURITY_ADMIN_PASSWORD

# Import Grafana dashboard
curl -sf -X POST \
  "http://admin:${GF_SECURITY_ADMIN_PASSWORD}@localhost:3000/api/dashboards/db" \
  -H 'Content-Type: application/json' \
  -d @monitoring/grafana/dashboards/vulnerability-management.json

