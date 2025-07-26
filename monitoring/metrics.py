from prometheus_client import Counter, Histogram, Gauge, start_http_server
import time


# Metrics definitions
vulnerability_counter = Counter(
    'vulnerabilities_discovered_total', 'Total vulnerabilities discovered', ['severity', 'asset_type']
)
patch_duration = Histogram(
    'patch_deployment_duration_seconds', 'Time taken to deploy patches', ['priority']
)
sla_compliance = Gauge(
    'sla_compliance_percentage', 'SLA compliance percentage', ['priority_level']
)
llm_analysis_duration = Histogram(
    'llm_analysis_duration_seconds', 'Time taken for LLM vulnerability analysis'
)


class MetricsCollector:
    def __init__(self):
        self.start_time = time.time()

    def record_vulnerability_discovered(self, severity: str, asset_type: str):
        vulnerability_counter.labels(severity=severity, asset_type=asset_type).inc()

    def record_patch_deployment(self, priority: str, duration_seconds: float):
        patch_duration.labels(priority=priority).observe(duration_seconds)

    def update_sla_compliance(self, priority_level: str, compliance_percentage: float):
        sla_compliance.labels(priority_level=priority_level).set(compliance_percentage)

    def record_llm_analysis(self, duration_seconds: float):
        llm_analysis_duration.observe(duration_seconds)


# Start metrics server
if __name__ == "__main__":
    start_http_server(8080)
    print("Metrics server started on port 8080")

