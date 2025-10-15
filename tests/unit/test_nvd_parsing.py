import json
import os
import sys
from pathlib import Path

# Ensure src on path
repo_root = Path(__file__).resolve().parents[2]
src_path = repo_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
	sys.path.insert(0, str(src_path))

from services.enricher_service.main import VulnerabilityEnricher


def load_fixture(name: str) -> dict:
	fixtures_dir = repo_root / "tests" / "fixtures"
	with open(fixtures_dir / name, "r", encoding="utf-8") as f:
		return json.load(f)


def test_parse_cve_data_v31():
	enricher = VulnerabilityEnricher()
	payload = load_fixture("nvd_v2_sample_v31.json")
	vulns = payload.get("vulnerabilities", [])
	parsed = enricher.parse_cve_data(vulns)
	assert parsed, "Expected parsed CVEs"
	# Ensure required keys and score extraction
	first = parsed[0]
	assert "cve_id" in first and first["cve_id"], "CVE id missing"
	assert "cvss" in first and isinstance(first["cvss"], (int, float)), "CVSS missing"
	assert "description" in first, "Description missing"


def test_parse_cve_data_v30_and_v2():
	enricher = VulnerabilityEnricher()
	payload = load_fixture("nvd_v2_sample_v30_v2.json")
	vulns = payload.get("vulnerabilities", [])
	parsed = enricher.parse_cve_data(vulns)
	assert parsed, "Expected parsed CVEs"
	# At least one entry should have cvss from v3.0 or v2
	assert any(c.get("cvss", 0) > 0 for c in parsed)
