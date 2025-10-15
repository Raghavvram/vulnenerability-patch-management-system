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

    def extract_vendor(self, service_name: str) -> str:
        """Extract vendor from service name"""
        vendor_mapping = {
            "apache": "apache",
            "nginx": "nginx", 
            "mysql": "oracle",
            "postgresql": "postgresql",
            "ssh": "openssh",
            "http": "apache",
            "https": "apache"
        }
        return vendor_mapping.get(service_name.lower(), "unknown")

    def generate_cpe(self, service_data: Dict) -> str:
        """Generate CPE 2.3 identifier from service information"""
        vendor = self.extract_vendor(service_data.get("service", ""))
        product = service_data.get("service", "unknown")
        version = service_data.get("version", "*")
        
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

    async def query_nvd_api(self, cpe: str) -> List[Dict]:
        """Query NIST NVD API for CVE information"""
        headers = {"apiKey": self.nvd_api_key} if self.nvd_api_key else {}
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"cpeName": cpe, "resultsPerPage": 10}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self.parse_cve_data(data.get("vulnerabilities", []))
                    else:
                        logger.warning(f"NVD API returned status {response.status}")
                        return []
        except Exception as e:
            logger.error(f"Error querying NVD API: {e}")
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
                metrics = vuln.get("metrics", {})
                if "cvssMetricV31" in metrics:
                    cvss_score = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", 0.0)
                elif "cvssMetricV30" in metrics:
                    cvss_score = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore", 0.0)
                
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
