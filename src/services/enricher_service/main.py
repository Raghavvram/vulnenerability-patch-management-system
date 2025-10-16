import os
import logging
from typing import Dict, List
import aiohttp
import asyncio

# Configure module logger
logger = logging.getLogger(__name__)

class VulnerabilityEnricher:
    def __init__(self):
        self.nvd_api_key = os.getenv("NVD_API_KEY")

    def extract_vendor(self, service_name: str, product_name: str) -> str:
        """Extract likely vendor from service/product names for NVD CPE mapping."""
        name = (product_name or service_name or "").lower()
        vendor_mapping = {
            # Web servers
            "apache httpd": "apache",
            "httpd": "apache",
            "apache": "apache",
            "nginx": "nginx",
            # Databases
            "postgresql": "postgresql",
            "postgres": "postgresql",
            # SSH
            "openssh": "openbsd",
            "ssh": "openbsd",
            # Caches
            "redis": "redislabs",
            # MQ
            "rabbitmq": "pivotal_software",
            # Windows/Samba
            "samba smbd": "samba",
            "smbd": "samba",
            # Kubernetes
            "kubelet": "kubernetes",
            # Protocol generic
            "http": "apache",
            "https": "apache",
        }
        # Find best key contained in name
        for key, vendor in vendor_mapping.items():
            if key in name:
                return vendor
        return "unknown"

    def normalize_product(self, service_name: str, product_name: str) -> str:
        """Map product/service names to NVD CPE product tokens."""
        name = (product_name or service_name or "").lower()
        product_mapping = {
            "apache httpd": "http_server",
            "httpd": "http_server",
            "apache": "http_server",
            "nginx": "nginx",
            "postgresql": "postgresql",
            "postgres": "postgresql",
            "openssh": "openssh",
            "ssh": "openssh",
            "redis": "redis",
            "rabbitmq": "rabbitmq",
            "samba smbd": "samba",
            "smbd": "samba",
            "kubelet": "kubelet",
            # generic http/https defaults to apache http_server
            "http": "http_server",
            "https": "http_server",
        }
        for key, prod in product_mapping.items():
            if key in name:
                return prod
        # fallback to tokens without spaces
        return name.replace(" ", "_") or "unknown"

    def generate_cpe(self, service_data: Dict) -> str:
        """Generate CPE 2.3 identifier from service/product/version information."""
        service_name = service_data.get("service", "") or ""
        product_name = service_data.get("product", "") or ""
        vendor = self.extract_vendor(service_name, product_name)
        product = self.normalize_product(service_name, product_name)
        version = (service_data.get("version", "*") or "*").strip()
        # Normalize version token (leave as-is; NVD will still match wildcard fallback)
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

    async def query_nvd_api(self, cpe: str) -> List[Dict]:
        """Query NIST NVD API v2 for CVE information using cpeName with keyword fallback.
        Implements recommended headers and basic retry on 429.
        """
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {}
        if self.nvd_api_key:
            # Send both common header names for compatibility
            headers["apiKey"] = self.nvd_api_key
            headers["X-Api-Key"] = self.nvd_api_key
        headers["User-Agent"] = "vulnpm/0.1 (dashboard@local)"

        async def _fetch(session: aiohttp.ClientSession, params: Dict) -> List[Dict]:
            try:
                async with session.get(base_url, headers=headers, params=params, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return self.parse_cve_data(data.get("vulnerabilities", []))
                    if resp.status == 429:
                        retry_after = int(resp.headers.get("Retry-After", "3"))
                        logger.warning(f"NVD API rate limited, retrying in {retry_after}s")
                        await asyncio.sleep(retry_after)
                        return await _fetch(session, params)
                    if resp.status == 404:
                        logger.info("NVD API returned 404 for given query params (no matching records)")
                        return []
                    text = await resp.text()
                    logger.warning(f"NVD API returned {resp.status}: {text[:200]}")
                    return []
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(f"Error querying NVD API: {e}")
                return []

        def _cpe_variants(cpe_str: str) -> List[str]:
            """Generate CPE string variants for wider matching."""
            parts = cpe_str.split(":")
            # cpe:2.3:a:vendor:product:version:update:...
            if len(parts) < 6: # need at least up to version
                return [cpe_str]
            variants = {cpe_str}
            # Add wildcard version variant
            parts_star = parts.copy()
            if parts_star[5] != "*":
                parts_star[5] = "*"
                variants.add(":".join(parts_star))
            return list(variants)

        def _keyword_variants(cpe_str: str) -> List[str]:
            """Generate keyword search variants from a CPE string."""
            parts = cpe_str.split(":")
            # cpe:2.3:a:vendor:product:version:update:...
            if len(parts) < 6:
                return []
            vendor = parts[3]
            product = parts[4]
            version = parts[5] if parts[5] != "*" else ""
            
            combos = []
            if vendor and product and version:
                combos.append(f"{vendor} {product} {version}")
            if vendor and product:
                combos.append(f"{vendor} {product}")
            if product and version:
                combos.append(f"{product} {version}")
            if product:
                combos.append(product)
            # De-duplicate while preserving order
            return list(dict.fromkeys(combos))

        async with aiohttp.ClientSession() as session:
            # Try exact and wildcard cpeName
            for cpe_variant in _cpe_variants(cpe):
                params_primary = {"cpeName": cpe_variant, "resultsPerPage": 200}
                results = await _fetch(session, params_primary)
                if results:
                    return results
            # Fallback through keyword variants
            for kw in _keyword_variants(cpe):
                params_fallback = {"keywordSearch": kw, "resultsPerPage": 200}
                results = await _fetch(session, params_fallback)
                if results:
                    return results
            return []

    def parse_cve_data(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Parse CVE data from NVD response"""
        parsed_cves = []
        for vuln in vulnerabilities:
            try:
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "")
                
                # Extract CVSS score
                cvss_score = 0.0
                metrics = cve_data.get("metrics", {})
                if "cvssMetricV31" in metrics:
                    cvss_score = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", 0.0)
                elif "cvssMetricV30" in metrics:
                    cvss_score = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore", 0.0)
                elif "cvssMetricV2" in metrics:
                    cvss_score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", 0.0)
                
                # Extract description
                descriptions = cve_data.get("descriptions", [])
                description = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
                
                parsed_cves.append({
                    "cve_id": cve_id,
                    "cvss": cvss_score,
                    "epss": 0.1,  # Placeholder - would need separate EPSS API call
                    "description": description[:500]  # Truncate long descriptions
                })
            except Exception as e:
                logger.warning(f"Error parsing CVE data: {e}")
                continue
        
        return parsed_cves

    def add_epss_scores(self, cves: List[Dict]) -> List[Dict]:
        """Add EPSS scores - placeholder implementation"""
        for cve in cves:
            # In a real implementation, you'd query the EPSS API
            cve["epss"] = 0.1  # Default low exploitation probability
        return cves

    def map_to_attack_framework(self, cves: List[Dict]) -> List[str]:
        """Map CVEs to MITRE ATT&CK techniques - placeholder"""
        # In a real implementation, you'd have a mapping database
        return ["T1190"]  # Exploit Public-Facing Application

    async def enrich_service(self, service_data: Dict) -> Dict:
        """Enrich service data with vulnerability information"""
        try:
            # Generate CPE identifier
            cpe = self.generate_cpe(service_data)
            
            # Query NVD API for CVEs
            cves = await self.query_nvd_api(cpe)
            
            # Add EPSS scores
            enriched_cves = self.add_epss_scores(cves)
            
            # Add MITRE ATT&CK mapping
            attack_techniques = self.map_to_attack_framework(cves)
            
            service_data.update({
                "cpe": cpe,
                "vulnerabilities": enriched_cves,
                "epss_max": max([cve.get("epss", 0) for cve in enriched_cves]) if enriched_cves else 0,
                "cvss_max": max([cve.get("cvss", 0) for cve in enriched_cves]) if enriched_cves else 0,
                "attack_techniques": attack_techniques
            })
            
            return service_data
        except Exception as e:
            logger.error(f"Error enriching service data: {e}")
            return service_data

async def enrich_hosts(hosts: List[Dict]) -> Dict:
    """Pure function: Enrich scan data with vulnerability information and return structured dict.
    No DB writes or endpoints.
    """
    enricher = VulnerabilityEnricher()
    enriched_hosts: List[Dict] = []
    for host in hosts:
        enriched_services = []
        for service in host.get("services", []):
            enriched_service = await enricher.enrich_service(service.copy())
            enriched_services.append(enriched_service)
        host_copy = host.copy()
        host_copy["services"] = enriched_services
        enriched_hosts.append(host_copy)

    return {
        "status": "success",
        "enriched_hosts": enriched_hosts,
        "summary": {
            "total_hosts": len(enriched_hosts),
            "total_services": sum(len(h.get("services", [])) for h in enriched_hosts)
        }
    }
