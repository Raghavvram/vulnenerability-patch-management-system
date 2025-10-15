import os
import json
import logging
from typing import Dict, List
import requests
import asyncio
import aiohttp

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VulnerabilityAnalysis:
    def __init__(self, risk_score: float, priority: str, exploitation_likelihood: str,
                 business_impact: str, remediation_steps: List[str], ansible_playbook: str,
                 compliance_impact: str, timeline_recommendation: str):
        self.risk_score = risk_score
        self.priority = priority
        self.exploitation_likelihood = exploitation_likelihood
        self.business_impact = business_impact
        self.remediation_steps = remediation_steps
        self.ansible_playbook = ansible_playbook
        self.compliance_impact = compliance_impact
        self.timeline_recommendation = timeline_recommendation

    def dict(self):
        return {
            "risk_score": self.risk_score,
            "priority": self.priority,
            "exploitation_likelihood": self.exploitation_likelihood,
            "business_impact": self.business_impact,
            "remediation_steps": self.remediation_steps,
            "ansible_playbook": self.ansible_playbook,
            "compliance_impact": self.compliance_impact,
            "timeline_recommendation": self.timeline_recommendation,
        }

class PerplexityLLMAnalyzer:
    def __init__(self):
        self.api_key = os.getenv("PERPLEXITY_API_KEY")
        self.api_url = "https://api.perplexity.ai/chat/completions"
        self.model = "sonar-pro"  # Using sonar-pro for advanced search capabilities
        
        if not self.api_key:
            logger.warning("PERPLEXITY_API_KEY not found in environment variables")

    def create_analysis_prompt(self, vulnerability_data: Dict) -> tuple[str, str]:
        """Create structured prompt for vulnerability analysis using Perplexity Sonar"""
        system_prompt = """
        You are a SOC (Security Operations Center) analyst specializing in vulnerability management for enterprise banking environments.
        
        Your role is to analyze vulnerability
        - NIST SP 800-40r4 patch management guidelines
        - NIST 800-53 SI-2 flaw remediation requirements  
        - ISO 27001:2022 Annex A 8.8 technical vulnerability management standards
        
        CRITICAL: You must respond with ONLY valid JSON in the exact format specified.
        Do not include any explanatory text before or after the JSON.
        
        Required JSON format:
        {
            "risk_score": float (0-10 scale),
            "priority": "Critical|High|Medium|Low",
            "exploitation_likelihood": "Very High|High|Medium|Low|Very Low",
            "business_impact": "detailed string explaining potential business consequences",
            "remediation_steps": ["step1", "step2", "step3"],
            "ansible_playbook": "YAML formatted Ansible playbook as string",
            "compliance_impact": "NIST/ISO compliance implications",
            "timeline_recommendation": "specific timeframe for remediation"
        }
        """

        user_prompt = f"""
        VULNERABILITY ANALYSIS REQUEST:

        Asset Information:
        - IP Address: {vulnerability_data.get('ip', 'unknown')}
        - Hostname: {vulnerability_data.get('hostname', 'unknown')}
        - Service: {vulnerability_data.get('service', 'unknown')}
        - Version: {vulnerability_data.get('version', 'unknown')}
        - Asset Criticality: {vulnerability_data.get('asset_criticality', 'Medium')}

        Vulnerability Summary:
        - Total CVEs Found: {len(vulnerability_data.get('vulnerabilities', []))}
        - Maximum CVSS Score: {vulnerability_data.get('cvss_max', 0)}
        - Maximum EPSS Score: {vulnerability_data.get('epss_max', 0)}
        - CPE Identifier: {vulnerability_data.get('cpe', 'unknown')}

        Top Critical Vulnerabilities:
        {json.dumps(vulnerability_data.get('vulnerabilities', [])[:3], indent=2)}

        Network Context:
        - Internet Facing: {vulnerability_data.get('internet_facing', False)}
        - Network Segment: {vulnerability_data.get('network_segment', 'internal')}
        - Compensating Controls: {vulnerability_data.get('compensating_controls', [])}

        Please analyze this vulnerability data and provide a comprehensive security assessment in the required JSON format.
        """

        return system_prompt, user_prompt

    async def call_perplexity_api(self, system_prompt: str, user_prompt: str) -> str:
        """Make async API call to Perplexity Sonar"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": 0.1,  # Low temperature for consistent analysis
            "max_tokens": 4000,
            "top_p": 0.9,
            "stream": False
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.api_url, 
                    headers=headers, 
                    json=payload, 
                    timeout=aiohttp.ClientTimeout(total=120)
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        return result["choices"][0]["message"]["content"]
                    else:
                        error_text = await response.text()
                        logger.error(f"Perplexity API error {response.status}: {error_text}")
                        raise RuntimeError(f"Perplexity API error: {error_text}")
                        
        except asyncio.TimeoutError:
            logger.error("Perplexity API request timed out")
            raise TimeoutError("API request timed out")
        except Exception as e:
            logger.error(f"Error calling Perplexity API: {e}")
            raise RuntimeError(f"API call failed: {str(e)}")

    def fallback_analysis(self, vulnerability_data: Dict) -> VulnerabilityAnalysis:
        """Fallback rule-based analysis when Perplexity API is unavailable"""
        cvss_max = vulnerability_data.get('cvss_max', 0)
        epss_max = vulnerability_data.get('epss_max', 0)
        vuln_count = len(vulnerability_data.get('vulnerabilities', []))
        
        # Advanced rule-based scoring
        risk_score = min(10.0, (cvss_max * 0.6) + (epss_max * 10 * 0.3) + (vuln_count * 0.1))
        
        if risk_score >= 8.5:
            priority = "Critical"
            timeline = "4 hours"
            likelihood = "Very High"
        elif risk_score >= 7.0:
            priority = "High" 
            timeline = "24 hours"
            likelihood = "High"
        elif risk_score >= 5.0:
            priority = "Medium"
            timeline = "72 hours"
            likelihood = "Medium"
        else:
            priority = "Low"
            timeline = "7 days"
            likelihood = "Low"

        service_name = vulnerability_data.get('service', 'unknown')
        
        return VulnerabilityAnalysis(
            risk_score=round(risk_score, 2),
            priority=priority,
            exploitation_likelihood=likelihood,
            business_impact=f"Service {service_name} on {vulnerability_data.get('ip', 'unknown')} has {vuln_count} vulnerabilities with max CVSS {cvss_max}. Potential for service disruption and data compromise.",
            remediation_steps=[
                f"Immediately review {vuln_count} identified vulnerabilities",
                f"Apply security patches for {service_name}",
                "Verify service functionality after updates",
                "Update security monitoring rules",
                "Document remediation actions for compliance"
            ],
            ansible_playbook=f"""---
- name: Emergency patch for {service_name}
  hosts: {vulnerability_data.get('ip', 'target_host')}
  become: yes
  tasks:
    - name: Update package cache
      package:
        update_cache: yes
        
    - name: Apply security updates
      package:
        name: "{service_name}"
        state: latest
        
    - name: Restart {service_name} service
      service:
        name: {service_name}
        state: restarted
        
    - name: Verify service is running
      service:
        name: {service_name}
        state: started""",
            compliance_impact=f"NIST SI-2 compliance breach if not remediated within {timeline}. ISO 27001 A.8.8 requires immediate action for {priority} priority vulnerabilities.",
            timeline_recommendation=timeline
        )

    async def analyze_vulnerability(self, vulnerability_data: Dict) -> VulnerabilityAnalysis:
        """Perform Perplexity Sonar-based vulnerability analysis"""
        if not self.api_key:
            logger.warning("No Perplexity API key available, using fallback analysis")
            return self.fallback_analysis(vulnerability_data)
            
        try:
            system_prompt, user_prompt = self.create_analysis_prompt(vulnerability_data)
            
            # Call Perplexity Sonar API
            response_content = await self.call_perplexity_api(system_prompt, user_prompt)
            
            # Clean and parse JSON response
            cleaned_response = response_content.strip()
            if cleaned_response.startswith("```"):
                cleaned_response = cleaned_response[7:]
            if cleaned_response.endswith("```"):
                cleaned_response = cleaned_response[:-3]
            cleaned_response = cleaned_response.strip()
            
            try:
                analysis_json = json.loads(cleaned_response)
                return VulnerabilityAnalysis(**analysis_json)
                
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse Perplexity JSON response: {e}")
                logger.debug(f"Raw response: {response_content}")
                return self.fallback_analysis(vulnerability_data)
                
        except Exception as e:
            logger.error(f"Perplexity analysis failed: {e}")
            return self.fallback_analysis(vulnerability_data)

async def analyze_enriched_hosts(enriched_hosts: List[Dict]) -> Dict:
    """Pure function: Analyze enriched vulnerability data and return structured dict."""
    analyzer = PerplexityLLMAnalyzer()
    logger.info(f"Starting analysis of {len(enriched_hosts)} hosts")
    analyzed_hosts = []

    for host in enriched_hosts:
        analyzed_services = []
        for service in host.get("services", []):
            if service.get("vulnerabilities"):
                logger.info(f"Analyzing service {service.get('service')} on {host.get('ip')}")
                service_with_context = service.copy()
                service_with_context.update({
                    "ip": host.get("ip"),
                    "hostname": host.get("hostname", ""),
                    "asset_criticality": host.get("asset_criticality", "Medium"),
                    "internet_facing": host.get("internet_facing", False),
                    "network_segment": host.get("network_segment", "internal")
                })
                analysis = await analyzer.analyze_vulnerability(service_with_context)
                service["analysis"] = analysis.dict()
            analyzed_services.append(service)
        host_copy = host.copy()
        host_copy["services"] = analyzed_services
        analyzed_hosts.append(host_copy)

    analyzed_count = sum(
        1 for h in analyzed_hosts 
        for s in h.get("services", []) 
        if s.get("vulnerabilities") and s.get("analysis")
    )

    logger.info(f"Analysis completed for {analyzed_count} vulnerable services")

    return {
        "status": "success",
        "analyzed_hosts": analyzed_hosts,
        "summary": {
            "total_hosts": len(analyzed_hosts),
            "analyzed_services": analyzed_count,
            "llm_provider": "perplexity_sonar",
            "model": analyzer.model
        }
    }
