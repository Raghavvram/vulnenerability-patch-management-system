# Project Kanban Board & Improvement Roadmap
**Repository:** Vulnerability Patch Management System (`vulnpm`)  
**Last Updated:** October 2026  
**Status:** Active Maintenance & Modernization  

---

## Priority Legend
- `[P0 - Critical]`: Immediate blocker or defect causing incorrect scan results, silent test failures, or pipeline crashes.
- `[P1 - High]`: High-impact architectural flaw, security vulnerability, invalid API identifier, or massive dependency bloat.
- `[P2 - Medium]`: Important functional enhancement, real external data integration, or test coverage expansion.
- `[P3 - Low]`: Quality-of-life feature, tooling convenience, or future roadmap integration.

---

## Kanban Board Overview

```
+---------------------------------------------------------------------------------------------------+
|  [DEPRECATED]      [BLOCKED]          [TO-DO]               [IN-PROGRESS]        [DONE]           |
|  Legacy deps (P1)  ML training (P2)   Parser bugfix (P0)    Git hygiene (P1)     Modular pipeline |
|  Dead stubs (P1)   CI secrets (P1)    Real EPSS API (P1)    pyproject deps (P0)  Nmap parser      |
|  0-byte pkl (P1)   NVD limits (P1)    Pydantic LLM (P1)     CI failure gate (P0) NVD API v2 query |
|  Tracked pyc (P1)                     Local cache (P1)                           Streamlit UI     |
|                                       CISA KEV check (P1)                        CLI runner       |
+---------------------------------------------------------------------------------------------------+
```

---

## 1. Deprecated (Items to Remove / Retire)

- [ ] `[P1 - High]` **Zombie Dependencies in `requirements.txt`**:
  - Remove unused microservice leftovers: `fastapi`, `uvicorn[standard]`, `sqlalchemy`, `psycopg2-binary`, `python-jose[cryptography]`, `passlib[bcrypt]`, `python-keycloak`, `rq`, `locust`, `openai`, `httpx`.
- [ ] `[P1 - High]` **Dead & Broken Code Files**:
  - Retire or fix `src/services/llm_service/output_validator.py` (contains undefined `load_safe_patterns()` and `load_dangerous_patterns()`).
  - Retire or fix `src/services/llm_service/secure_prompting.py` (contains undefined `load_secure_template()` and `generate_fallback_response()`).
- [ ] `[P1 - High]` **Tracked Cache & Binary Artifacts in Git**:
  - Untrack `__pycache__/*.pyc` files (12+ tracked files).
  - Untrack 0-byte `src/services/prioritization_engine/model.pkl`.
  - Untrack `src/vulnpm.egg-info/` directory.
- [ ] `[P2 - Medium]` **Outdated Documentation References in `README.md`**:
  - Remove references to non-existent files: `examples/scan.xml` (directory was deleted), `test_nmap_scan_and_submit.sh`, `docker-compose.yml`, and `deploy_vulnerability_management.sh`.
  - Remove Docker troubleshooting section (`docker logs`, `docker restart`) now that architecture is pure Python functions.
- [ ] `[P1 - High]` **Insecure Python Pickle Loading**:
  - Deprecate unsafe `pickle.load` in `PrioritizationEngine` in favor of deterministic formulaic scoring or ONNX runtime.

---

## 2. Blocked (Waiting on External Input / Dependencies)

- [ ] `[P2 - Medium]` **Trained Machine Learning Model for Prioritization**:
  - *Blocked by:* Absence of labeled training dataset (historical enterprise vulnerability triage outcomes) and feature schema.
  - *Resolution:* Use rule-based + weighted composite scoring (CVSS + EPSS + CISA KEV + Asset Criticality) until dataset is established.
- [ ] `[P1 - High]` **Live LLM Integration Testing in GitHub Actions CI**:
  - *Blocked by:* Requires repository secrets (`GROQ_API_KEY`, `PERPLEXITY_API_KEY`) in GitHub repo settings.
  - *Resolution:* Add hermetic mock tests in CI that test JSON parsing and fallback without live API calls.
- [ ] `[P1 - High]` **NVD API v2 Rate-Limit Throttling**:
  - *Blocked by:* Unauthenticated rate-limit (5 requests / 30s) causing scan enrichment to stall or return 429 without `NVD_API_KEY`.
  - *Resolution:* Implement local disk/SQLite caching layer and support optional user API key.

---

## 3. In-Progress (Current Maintenance & Modernization)

- [x] `[P0 - Critical]` **Fix `libnmap` Attribute Access Bug (`parser_service/main.py`)**:
  - `NmapService` objects in `python-libnmap` store product, version, and extrainfo in `service.service_dict`.
  - Fixed extraction to pull `product`, `version`, `extrainfo`, and `cpelist` from `service_dict` and preserve native CPEs.
- [x] `[P0 - Critical]` **Modernize `pyproject.toml` Packaging**:
  - Populated `dependencies` in `pyproject.toml` with actual required packages (`python-libnmap`, `aiohttp`, `groq`, `python-dotenv`, `scikit-learn`, `numpy`, `streamlit`, `pandas`, `plotly`).
  - Defined optional/dev dependencies: `pytest`, `pytest-asyncio`, `ruff`.
  - Added `[build-system]` declaration (`setuptools.build_meta`).
- [x] `[P0 - Critical]` **Fix CI Pipeline Reliability (`.github/workflows/ci.yml`)**:
  - Removed `|| echo "No tests or tests optional"` so test failures strictly fail the CI build.
  - Updated branch triggers to include `main`, `master`, `develop`, and `errorfree`.
- [ ] `[P1 - High]` **Git Hygiene & Clean `.gitignore`**:
  - Untrack `.pyc`, `model.pkl`, and `egg-info` from git index.
  - Update `.gitignore` with comprehensive patterns for `*.egg-info/`, `.pytest_cache/`, `output/*.json`, and OS artifacts.

---

## 4. To-Do (Planned Core Improvements)

### A. Parser Service (`parser_service`)
- [x] `[P0 - Critical]` **Extract Nmap Detected CPEs**:
  - Nmap outputs `<cpe>cpe:/a:vendor:product:version</cpe>`. Parser now extracts `cpelist` and `cpe` directly and `enricher_service` prioritizes them.
- [ ] `[P2 - Medium]` **Improve Fallback XML Parser**:
  - Add parsing for `<script>` elements (e.g., `ssl-cert`, `http-title`, `vulners` output) in manual XML parser.
- [ ] `[P2 - Medium]` **Input Validation & Sanitization**:
  - Reject XML bombs or entity expansion (XXE protection via `defusedxml`).

### B. Enricher Service (`enricher_service`)
- [ ] `[P1 - High]` **Local Caching Layer (SQLite / diskcache)**:
  - Cache CVE lookups by CPE and EPSS scores by CVE ID to avoid duplicate HTTP requests and avoid hitting NVD rate limits.
- [ ] `[P1 - High]` **Real EPSS API Integration**:
  - Replace the placeholder `epss = 0.1` with live queries to FIRST.org EPSS API (`https://api.first.org/data/v1/epss?cve=...`).
- [ ] `[P1 - High]` **Version-Aware CVE Filtering**:
  - Filter out CVEs whose affected version ranges do not match the discovered version, eliminating false positives from wildcard CPEs.
- [ ] `[P2 - Medium]` **Dynamic MITRE ATT&CK Mapping**:
  - Replace hardcoded `["T1190"]` with a mapping dictionary based on Common Weakness Enumeration (CWE) or CAPEC IDs.

### C. LLM Service (`llm_service`)
- [x] `[P0 - Critical]` **Fix Groq Model Identifier**:
  - Updated invalid `"groq/compound"` model name to supported `"llama-3.3-70b-versatile"`, configurable via `GROQ_MODEL` env var.
- [ ] `[P1 - High]` **Structured Outputs via Pydantic**:
  - Define `VulnerabilityAnalysis` using Pydantic `BaseModel` and utilize Groq/OpenAI JSON schema mode for bulletproof structured outputs.
- [ ] `[P2 - Medium]` **Context-Aware Ansible Playbook Generation**:
  - Detect host OS family (Debian/Ubuntu vs. RHEL/CentOS) from Nmap OS detection and output accurate package manager commands (`apt` vs `dnf`).
- [ ] `[P2 - Medium]` **Prompt Injection Hardening**:
  - Properly sanitize service banners and XML inputs before feeding to LLM prompts to prevent prompt injection attacks.

### D. Prioritization Engine (`prioritization_engine`)
- [ ] `[P1 - High]` **CISA KEV Integration**:
  - Check CVEs against CISA's Known Exploited Vulnerabilities catalog (actively exploited in the wild = auto-escalate to Critical).
- [ ] `[P1 - High]` **Deterministic Composite Scoring**:
  - Formalize transparent scoring algorithm: `Score = 0.35 * CVSS + 0.30 * EPSS + 0.20 * Asset_Criticality + 0.15 * Exposure`.
- [ ] `[P2 - Medium]` **Path Safety for Model Loading**:
  - Use `pathlib.Path(__file__).parent / "model.pkl"` rather than relying on current working directory.

### E. CLI & Reporting (`cli.py`)
- [ ] `[P1 - High]` **Automatic Directory Creation**:
  - Create `output/` directory if it does not already exist before saving report JSON.
- [ ] `[P2 - Medium]` **Multi-Format Export**:
  - Add `--format` flag supporting `json`, `markdown`, `html`, and `sarif`.
- [ ] `[P3 - Low]` **Quiet / Verbose Flags**:
  - Add `-v` / `--verbose` and `-q` / `--quiet` for pipeline and scripting automation.

### F. Dashboard (`app/dashboard.py`)
- [ ] `[P2 - Medium]` **Async Progress & Toast Notifications**:
  - Provide real-time status updates as hosts are parsed, enriched, and analyzed.
- [ ] `[P2 - Medium]` **Remediation Playbook Viewer & Downloader**:
  - Add UI tab to view and download the generated Ansible playbooks for each vulnerable host.
- [ ] `[P3 - Low]` **Scan Comparison (Diff View)**:
  - Allow uploading two scans to visualize fixed, new, and persistent vulnerabilities over time.

### G. Testing & Quality Assurance
- [ ] `[P0 - Critical]` **Comprehensive Unit Test Suite**:
  - Add unit tests for `parser_service` (both libnmap and manual paths).
  - Add unit tests for `prioritization_engine` scoring logic.
  - Add unit tests for `llm_service` fallback and JSON parsing.
- [ ] `[P1 - High]` **Integration Test**:
  - Add end-to-end integration test with `tests/fixtures/` and mocked HTTP responses.
- [ ] `[P1 - High]` **Linting & Code Quality**:
  - Configure `ruff` for linting and formatting.
  - Add `mypy` type checking across `src/`.

---

## 5. Done (Existing Completed Features)

- [x] Functional orchestrator pipeline (`process_scan` executing parse -> enrich -> analyze -> prioritize).
- [x] Nmap XML parsing using `libnmap` with fallback manual `xml.etree` parser.
- [x] NVD API v2 client with retry logic, rate limit backoff, and keyword search fallback.
- [x] Initial unit tests for NVD CVE response parsing (`tests/unit/test_nvd_parsing.py`).
- [x] Dual LLM analysis architecture: Groq primary, Perplexity fallback, and deterministic rule-based fallback.
- [x] Composite vulnerability risk scoring formula and SLA timeline calculation.
- [x] CLI entrypoint (`cli.py`) processing XML scans and outputting timestamped JSON reports.
- [x] Streamlit web dashboard (`app/dashboard.py`) with Treemaps, bar charts, scatter plots, and host drilldowns.
- [x] Sample Nmap scan XMLs for localhost, gateway, and Active Directory (`nmap-scans/`).

---

## 6. Backlog & Suggestions (Future Architectural Enhancements)

- [ ] `[P2 - Medium]` **Multi-Scanner Ingestion**: Expand parser to ingest Trivy (container/SBOM), Nuclei (web vulnerabilities), and OpenVAS/GVM scans.
- [ ] `[P2 - Medium]` **Automated Remediation Verification**: Add re-scan capability using `python-libnmap` / `nmap` subprocess to verify if patches resolved identified CVEs.
- [ ] `[P3 - Low]` **Ticketing Integrations**: Webhook / API integrations to export prioritized findings to Jira, GitHub Issues, or GitLab Issues.
- [ ] `[P3 - Low]` **Docker Container & Pre-built Distribution**: Provide a multi-stage Dockerfile to run both the CLI and Streamlit dashboard without local Python setup.
- [ ] `[P3 - Low]` **Role-Based Access & Audit Logging**: Structured JSON logging for compliance audits (NIST SP 800-40r4 / ISO 27001).
