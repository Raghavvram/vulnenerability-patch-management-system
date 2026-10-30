from pathlib import Path
from unittest.mock import patch

from services.parser_service.main import parse_nmap_xml


def test_parse_nmap_xml_extracts_product_version_and_cpe():
    repo_root = Path(__file__).resolve().parents[2]
    scan_file = repo_root / "nmap-scans" / "scan_localhost.xml"
    with open(scan_file, "r", encoding="utf-8") as f:
        xml_content = f.read()

    result = parse_nmap_xml(xml_content)
    assert result["status"] == "success"
    hosts = result["hosts"]
    assert len(hosts) == 1
    services = hosts[0]["services"]

    # Port 80 service check
    http_svc = next((s for s in services if s["port"] == 80), None)
    assert http_svc is not None
    assert http_svc["service"] == "http"
    assert http_svc["product"] == "Apache httpd"
    assert http_svc["version"] == "2.4.65"
    assert http_svc["extrainfo"] == "(Debian)"
    assert "cpe:/a:apache:http_server:2.4.65" in http_svc.get("cpelist", [])
    assert http_svc.get("cpe") == "cpe:/a:apache:http_server:2.4.65"


def test_parse_nmap_xml_manual_fallback():
    sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <nmaprun scanner="nmap" version="7.95">
      <host>
        <status state="up"/>
        <address addr="10.0.0.1" addrtype="ipv4"/>
        <hostnames><hostname name="test.local"/></hostnames>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu">
              <cpe>cpe:/a:openbsd:openssh:8.9p1</cpe>
            </service>
          </port>
        </ports>
      </host>
    </nmaprun>"""
    with patch("libnmap.parser.NmapParser.parse_fromstring", side_effect=RuntimeError("libnmap simulated failure")):
        result = parse_nmap_xml(sample_xml)

    assert result["status"] == "success"
    svc = result["hosts"][0]["services"][0]
    assert svc["port"] == 22
    assert svc["product"] == "OpenSSH"
    assert svc["version"] == "8.9p1"
    assert svc.get("cpe") == "cpe:/a:openbsd:openssh:8.9p1"
    assert "cpe:/a:openbsd:openssh:8.9p1" in svc.get("cpelist", [])
