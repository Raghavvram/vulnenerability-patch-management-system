from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os
import logging
from typing import Dict, List
import aiohttp
import asyncio
import psycopg2
from psycopg2.extras import execute_values

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Vulnerability Enricher Service", version="1.0.0")

class EnrichmentRequest(BaseModel):
    hosts: List[Dict]

class PostgresDB:
    def __init__(self):
        self.dbname = os.getenv("POSTGRES_DB", "vulndb")
        self.user = os.getenv("POSTGRES_USER", "vulnuser")
        self.password = os.getenv("POSTGRES_PASSWORD")
        self.host = os.getenv("POSTGRES_HOST", "postgres")  # FIXED: use service name
        self.port = os.getenv("POSTGRES_PORT", "5432")       # FIXED: use default port
        self.conn = None
        self.connect()

    def connect(self):
        try:
            self.conn = psycopg2.connect(
                dbname=self.dbname,
                user=self.user,
                password=self.password,
                host=self.host,
                port=self.port
            )
        except Exception as e:
            logger.error(f"Failed to connect to PostgreSQL: {e}")
            self.conn = None

    def insert_vulnerabilities(self, host, service, vulnerabilities):
        if not self.conn:
            logger.error("No DB connection available.")
            return
        rows = []
        for vuln in vulnerabilities:
            rows.append((
                host.get("ip"),
                host.get("hostname"),
                vuln.get("cve_id"),
                vuln.get("cvss"),
                vuln.get("epss"),
                vuln.get("priority", "Medium"),
                "open",  # status
                service.get("service"),
                service.get("version"),
                vuln.get("description"),
                "Medium",  # asset_criticality
                host.get("business_unit"),
                host.get("owner_team"),
                service.get("service"),
                service.get("version")
            ))
        try:
            with self.conn.cursor() as cur:
                execute_values(cur, """
                    INSERT INTO vulnerabilities (
                        asset_ip, asset_hostname, cve_id, cvss_score, epss_score, priority, status,
                        service_name, service_version, description, asset_criticality, business_unit,
                        owner_team, service_name, service_version
                    ) VALUES %s
                """, rows)
                self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to insert vulnerabilities: {e}")

db = PostgresDB()

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

# Initialize enricher
enricher = VulnerabilityEnricher()

@app.post("/enrich")
async def enrich_data(request: EnrichmentRequest):
    """Enrich scan data with vulnerability information and write to PostgreSQL"""
    try:
        enriched_hosts = []
        for host in request.hosts:
            enriched_services = []
            for service in host.get("services", []):
                enriched_service = await enricher.enrich_service(service.copy())
                enriched_services.append(enriched_service)
                # Write vulnerabilities to DB
                vulnerabilities = enriched_service.get("vulnerabilities", [])
                if vulnerabilities:
                    db.insert_vulnerabilities(host, service, vulnerabilities)
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
    except Exception as e:
        logger.error(f"Enrichment failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint (always HTTP 200)"""
    return {"status": "healthy", "service": "enricher", "version": "1.0.0"}

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "Vulnerability Enricher Service",
        "version": "1.0.0",
        "endpoints": {
            "health": "/health",
            "enrich": "/enrich",
            "metrics": "/metrics"
        }
    }

@app.get("/metrics")
async def metrics():
    return {"metrics": "not_implemented", "service": "enricher-service", "version": "1.0.0"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
