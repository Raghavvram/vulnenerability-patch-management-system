import asyncio
import os
import sys
from typing import Dict
from dotenv import load_dotenv

# Load environment variables from .env (including PERPLEXITY_API_KEY)
load_dotenv()

# Monkeypatch the enricher to ensure at least one vulnerability is present
repo_root = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(repo_root, "src")
if os.path.isdir(src_path) and src_path not in sys.path:
    sys.path.insert(0, src_path)

from services.enricher_service import main as enricher_main

async def _fake_enrich_service(self, service_data: Dict) -> Dict:
    enriched = service_data.copy()
    enriched.update({
        "cpe": "cpe:2.3:a:apache:http:2.4.41:*:*:*:*:*:*:*",
        "vulnerabilities": [
            {
                "cve_id": "CVE-2024-9999",
                "cvss": 9.8,
                "epss": 0.92,
                "description": "Mock RCE for smoke testing"
            }
        ],
        "cvss_max": 9.8,
        "epss_max": 0.92,
        "attack_techniques": ["T1190"],
        "exploit_available": True,
    })
    return enriched

# Apply monkeypatch
enricher_main.VulnerabilityEnricher.enrich_service = _fake_enrich_service  # type: ignore

from services.main_orchestrator.main import process_scan


async def run_smoke_with_mock_vuln() -> None:
    xml = (
        "<nmaprun>"
        "<host>"
        "<address addr=\"10.0.0.1\" addrtype=\"ipv4\"/>"
        "<hostnames><hostname name=\"svc-host\"/></hostnames>"
        "<status state=\"up\"/>"
        "<ports>"
        "  <port protocol=\"tcp\" portid=\"443\">"
        "    <state state=\"open\"/>"
        "    <service name=\"http\" version=\"Apache 2.4.41\" product=\"apache\" extrainfo=\"\" />"
        "  </port>"
        "</ports>"
        "</host>"
        "</nmaprun>"
    )

    result = await process_scan(xml)

    # Basic checks
    hosts_count = len(result.get("prioritized_hosts", []))
    prioritized_services = result.get("summary", {}).get("prioritized_services")

    print({
        "hosts_count": hosts_count,
        "prioritized_services": prioritized_services,
        "perplexity_key_present": bool(os.getenv("PERPLEXITY_API_KEY")),
        "first_service_priority": (result.get("prioritized_hosts", []) or [{}])[0].get("services", [{}])[0].get("priority_info", {})
    })

    assert hosts_count >= 1, "Expected at least one host"
    assert prioritized_services and prioritized_services >= 1, "Expected at least one prioritized service"


if __name__ == "__main__":
    asyncio.run(run_smoke_with_mock_vuln())


