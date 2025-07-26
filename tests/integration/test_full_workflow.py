import pytest
import docker
import requests
import time
import os


@pytest.fixture(scope="module")
def docker_services():
    """Start all services using docker-compose"""
    client = docker.from_env()

    # Start services
    compose_file = "docker-compose.test.yml"
    client.containers.run(
        "docker/compose:latest",
        f"up -d -f {compose_file}",
        volumes={os.getcwd(): {'bind': '/app', 'mode': 'rw'}}
    )

    # Wait for services to be ready
    time.sleep(30)

    yield

    # Cleanup
    client.containers.run(
        "docker/compose:latest",
        f"down -f {compose_file}",
        volumes={os.getcwd(): {'bind': '/app', 'mode': 'rw'}}
    )




def test_end_to_end_vulnerability_processing(docker_services):
    """Test complete vulnerability processing workflow"""

    # Submit scan data
    scan_data = {"xml_content": load_test_nmap_xml()}
    response = requests.post("http://localhost:8000/scan/process", json=scan_data)
    assert response.status_code == 200

    job_id = response.json()["job_id"]

    # Poll for completion
    max_wait = 120  # 2 minutes
    start_time = time.time()

    while time.time() - start_time < max_wait:
        status_response = requests.get(f"http://localhost:8000/jobs/{job_id}")
        if status_response.json()["status"] == "completed":
            break
        time.sleep(5)

    # Verify results
    results = requests.get(f"http://localhost:8000/jobs/{job_id}/results")
    assert results.status_code == 200

    data = results.json()
    assert "vulnerabilities" in data
    assert "remediation_plan" in data
    assert "ansible_playbook" in data

def load_test_nmap_xml():
    # Placeholder function for now
    return "<nmaprun></nmaprun>"

