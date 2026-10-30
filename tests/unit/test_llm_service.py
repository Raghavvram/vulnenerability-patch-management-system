import os
from services.llm_service.main import GroqLLMAnalyzer, LLMAnalyzer


def test_groq_default_model_is_valid():
    analyzer = GroqLLMAnalyzer()
    assert analyzer.model == "llama-3.3-70b-versatile"
    assert "compound" not in analyzer.model


def test_groq_model_env_override(monkeypatch):
    monkeypatch.setenv("GROQ_MODEL", "llama-3.1-8b-instant")
    analyzer = GroqLLMAnalyzer()
    assert analyzer.model == "llama-3.1-8b-instant"


def test_fallback_analysis_structure():
    analyzer = LLMAnalyzer()
    vuln_data = {
        "ip": "10.0.0.1",
        "service": "http",
        "vulnerabilities": [
            {"cve_id": "CVE-2024-0001", "cvss": 8.5, "epss": 0.2}
        ],
        "cvss_max": 8.5,
        "epss_max": 0.2
    }
    result = analyzer.fallback_analysis(vuln_data)
    d = result.dict()
    assert d["priority"] in ["Critical", "High", "Medium", "Low"]
    assert d["risk_score"] > 0
    assert isinstance(d["remediation_steps"], list)
    assert "ansible_playbook" in d
