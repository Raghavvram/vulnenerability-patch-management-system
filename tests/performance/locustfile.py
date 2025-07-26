# tests/performance/locustfile.py
from locust import HttpUser, task, between


class VulnerabilitySystemUser:
    wait_time = between(1, 3)

    def on_start(self):
        """Called when a simulated user starts"""
        self.sample_scan = self.load_sample_scan_data()

    @task(3)
    def submit_scan_data(self):
        """Simulate submitting scan data for processing"""
        response = self.client.post(
            "/scan/process",
            json={"xml_content": self.sample_scan},
            headers={"Content-Type": "application/json"}
        )

        if response.status_code == 200:
            job_id = response.json().get("job_id")
            if job_id:
                self.check_job_status(job_id)

    @task(1)
    def check_system_health(self):
        """Check health endpoints"""
        self.client.get("/health")

    def check_job_status(self, job_id):
        """Check processing job status"""
        self.client.get(f"/jobs/{job_id}")

    def load_sample_scan_data(self):
        with open("test_data/sample_scan.xml", "r") as f:
            return f.read()

