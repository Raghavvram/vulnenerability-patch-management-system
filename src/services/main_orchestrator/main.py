import logging
from typing import Dict, Any
from services.parser_service import parse_nmap_xml
from services.enricher_service import enrich_hosts
from services.llm_service import analyze_enriched_hosts
from services.prioritization_engine import prioritize_analyzed_hosts

logger = logging.getLogger(__name__)

async def process_scan(xml_content: str) -> Dict[str, Any]:
    """Pure orchestrator function: runs parse -> enrich -> analyze -> prioritize and returns final result."""
    if not xml_content or not xml_content.strip():
        raise ValueError("xml_content is required and cannot be empty")

    logger.info("Starting scan processing")

    # Parse
    parsed = parse_nmap_xml(xml_content)
    hosts = parsed.get("hosts", [])
    logger.info(f"Parsed {parsed.get('summary', {}).get('total_hosts', 0)} hosts")

    # Enrich
    enriched = await enrich_hosts(hosts)
    enriched_hosts = enriched.get("enriched_hosts", [])
    logger.info(f"Enriched {enriched.get('summary', {}).get('total_hosts', 0)} hosts")

    # LLM analyze
    analyzed = await analyze_enriched_hosts(enriched_hosts)
    analyzed_hosts = analyzed.get("analyzed_hosts", [])
    logger.info(f"Analyzed {analyzed.get('summary', {}).get('analyzed_services', 0)} services")

    # Prioritize
    prioritized = await prioritize_analyzed_hosts(analyzed_hosts)
    logger.info(f"Prioritized {prioritized.get('summary', {}).get('prioritized_services', 0)} services")

    return prioritized
