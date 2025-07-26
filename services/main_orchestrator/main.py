from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import httpx
import logging
import uuid
from typing import Dict, Any
import asyncio
import psycopg2
import redis
import json
import os

app = FastAPI(
    title="Vulnerability Management Orchestrator",
    description="LLM-driven vulnerability patch management system orchestrator",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Health check endpoint
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "main-orchestrator", "version": "1.0.0"}

# Metrics endpoint (dummy for now)
@app.get("/metrics")
async def metrics():
    return {"metrics": "not_implemented", "service": "main-orchestrator", "version": "1.0.0"}

class ServiceRegistry:
    PARSER_SERVICE = "http://parser_service:8000"
    ENRICHER_SERVICE = "http://enricher_service:8000"
    LLM_SERVICE = "http://llm_service:8000"
    PRIORITIZATION_ENGINE = "http://prioritization_engine:8000"

class ScanRequest(BaseModel):
    xml_content: str
    scan_id: str = None
    target_network: str = None

class ScanResponse(BaseModel):
    status: str
    job_id: str
    message: str = None
    data: Dict[str, Any] = None

def get_postgres_conn():
    return psycopg2.connect(
        dbname=os.getenv("POSTGRES_DB", "vulndb"),
        user=os.getenv("POSTGRES_USER", "vulnuser"),
        password=os.getenv("POSTGRES_PASSWORD"),
        host=os.getenv("POSTGRES_HOST", "postgres"),
        port=os.getenv("POSTGRES_PORT", "5432")
    )

redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "redis"),
    port=int(os.getenv("REDIS_PORT", "6379")),
    password=os.getenv("REDIS_PASSWORD", None),
    decode_responses=True
)

def set_job_status(job_id, status, step, error=None):
    redis_client.hmset(job_id, {
        "status": status,
        "current_step": step,
        "error": error or ""
    })

def get_job_status(job_id):
    return redis_client.hgetall(job_id)

def store_job_result(job_id, result):
    conn = get_postgres_conn()
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS job_results (
                job_id VARCHAR(64) PRIMARY KEY,
                result JSONB,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)
        cur.execute(
            "INSERT INTO job_results (job_id, result) VALUES (%s, %s) ON CONFLICT (job_id) DO UPDATE SET result = EXCLUDED.result",
            (job_id, json.dumps(result))
        )
        conn.commit()
    conn.close()

@app.post("/scan/process", response_model=ScanResponse)
async def process_scan_results(request: ScanRequest, background_tasks: BackgroundTasks):
    """Main orchestration endpoint for processing scan results"""
    if not request.xml_content.strip():
        raise HTTPException(status_code=400, detail="xml_content is required and cannot be empty")
    job_id = request.scan_id or f"scan_{str(uuid.uuid4())[:8]}"
    set_job_status(job_id, "processing", "parsing")
    logger.info(f"Starting scan processing for job {job_id}")
    # Step 1: Parse scan results
    logger.info(f"Job {job_id}: Calling parser service")
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            parse_response = await client.post(
                f"{ServiceRegistry.PARSER_SERVICE}/parse/xml",
                json={"xml_content": request.xml_content},
                headers={"Content-Type": "application/json"}
            )
        logger.info(f"Job {job_id}: Parser response status: {parse_response.status_code}")
        if parse_response.status_code != 200:
            error_msg = f"Parser service failed with status {parse_response.status_code}: {parse_response.text}"
            logger.error(f"Job {job_id}: {error_msg}")
            set_job_status(job_id, "failed", "parsing_failed", error_msg)
            return ScanResponse(status="error", job_id=job_id, message=error_msg)
        parsed_data = parse_response.json()
        set_job_status(job_id, "processing", "enrichment")
        logger.info(f"Job {job_id}: Successfully parsed {parsed_data.get('summary', {}).get('total_hosts', 0)} hosts")
    except httpx.ConnectError as e:
        error_msg = f"Cannot connect to parser service: {str(e)}"
        logger.error(f"Job {job_id}: {error_msg}")
        set_job_status(job_id, "failed", "connection_failed", error_msg)
        return ScanResponse(status="error", job_id=job_id, message=error_msg)
    except Exception as e:
        error_msg = f"Parser service error: {str(e)}"
        logger.error(f"Job {job_id}: {error_msg}")
        set_job_status(job_id, "failed", "parsing_error", error_msg)
        return ScanResponse(status="error", job_id=job_id, message=error_msg)
    # Step 2: Enrich parsed data
    logger.info(f"Job {job_id}: Calling enricher service")
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            enrich_response = await client.post(
                f"{ServiceRegistry.ENRICHER_SERVICE}/enrich",
                json={"hosts": parsed_data.get("hosts", [])},
                headers={"Content-Type": "application/json"}
            )
        logger.info(f"Job {job_id}: Enricher response status: {enrich_response.status_code}")
        if enrich_response.status_code != 200:
            error_msg = f"Enricher service failed with status {enrich_response.status_code}: {enrich_response.text}"
            logger.error(f"Job {job_id}: {error_msg}")
            set_job_status(job_id, "failed", "enrichment_failed", error_msg)
            return ScanResponse(status="error", job_id=job_id, message=error_msg)
        enriched_data = enrich_response.json()
        set_job_status(job_id, "processing", "llm_analysis")
        logger.info(f"Job {job_id}: Successfully enriched {enriched_data.get('summary', {}).get('total_hosts', 0)} hosts")
    except Exception as e:
        error_msg = f"Enricher service error: {str(e)}"
        logger.error(f"Job {job_id}: {error_msg}")
        set_job_status(job_id, "failed", "enrichment_error", error_msg)
        return ScanResponse(status="error", job_id=job_id, message=error_msg)
    # Step 3: LLM analysis
    logger.info(f"Job {job_id}: Calling LLM service")
    try:
        async with httpx.AsyncClient(timeout=180.0) as client:
            llm_response = await client.post(
                f"{ServiceRegistry.LLM_SERVICE}/analyze",
                json={"enriched_hosts": enriched_data.get("enriched_hosts", [])},
                headers={"Content-Type": "application/json"}
            )
        logger.info(f"Job {job_id}: LLM response status: {llm_response.status_code}")
        if llm_response.status_code != 200:
            error_msg = f"LLM service failed with status {llm_response.status_code}: {llm_response.text}"
            logger.error(f"Job {job_id}: {error_msg}")
            set_job_status(job_id, "failed", "llm_failed", error_msg)
            return ScanResponse(status="error", job_id=job_id, message=error_msg)
        llm_data = llm_response.json()
        set_job_status(job_id, "processing", "prioritization")
        logger.info(f"Job {job_id}: LLM analysis completed for {llm_data.get('summary', {}).get('analyzed_services', 0)} services")
    except Exception as e:
        error_msg = f"LLM service error: {str(e)}"
        logger.error(f"Job {job_id}: {error_msg}")
        set_job_status(job_id, "failed", "llm_error", error_msg)
        return ScanResponse(status="error", job_id=job_id, message=error_msg)
    # Step 4: Prioritization
    logger.info(f"Job {job_id}: Calling prioritization engine")
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            prio_response = await client.post(
                f"{ServiceRegistry.PRIORITIZATION_ENGINE}/prioritize",
                json={"analyzed_hosts": llm_data.get("analyzed_hosts", [])},
                headers={"Content-Type": "application/json"}
            )
            logger.info(f"Job {job_id}: Prioritization response status: {prio_response.status_code}")
            if prio_response.status_code != 200:
                error_msg = f"Prioritization engine failed with status {prio_response.status_code}: {prio_response.text}"
                logger.error(f"Job {job_id}: {error_msg}")
                set_job_status(job_id, "failed", "prioritization_failed", error_msg)
                return ScanResponse(status="error", job_id=job_id, message=error_msg)
            prio_data = prio_response.json()
            set_job_status(job_id, "completed", "completed")
            logger.info(f"Job {job_id}: Prioritization completed for {prio_data.get('summary', {}).get('prioritized_services', 0)} services")
    except Exception as e:
        error_msg = f"Prioritization engine error: {str(e)}"
        logger.error(f"Job {job_id}: {error_msg}")
        set_job_status(job_id, "failed", "prioritization_error", error_msg)
        return ScanResponse(status="error", job_id=job_id, message=error_msg)
    # Store final output
    set_job_status(job_id, "completed", "completed")
    store_job_result(job_id, prio_data)
    logger.info(f"Job {job_id}: Full workflow completed successfully")
    return ScanResponse(status="success", job_id=job_id, message="Scan processed and prioritized successfully", data=prio_data)
