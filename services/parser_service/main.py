from fastapi import FastAPI, HTTPException
from libnmap.parser import NmapParser
from pydantic import BaseModel
import logging
import xml.etree.ElementTree as ET

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Nmap Parser Service", version="1.0.0")

class NmapInput(BaseModel):
    xml_content: str

def parse_nmap_xml_safe(xml_content: str):
    """Safe XML to JSON converter for Nmap results"""
    try:
        # First try with libnmap
        report = NmapParser.parse_fromstring(xml_content)
        hosts_data = []
        
        for host in report.hosts:
            host_info = {
                "ip": host.address,
                "hostname": host.hostnames[0] if host.hostnames else "",
                "status": host.status,
                "services": []
            }
            
            # Safe way to get services - iterate through all ports
            if hasattr(host, 'services') and host.services:
                for service in host.services:
                    try:
                        service_info = {
                            "port": getattr(service, 'port', 0),
                            "protocol": getattr(service, 'protocol', 'tcp'),
                            "service": getattr(service, 'service', 'unknown'),
                            "version": getattr(service, 'version', ''),
                            "state": getattr(service, 'state', 'unknown'),
                            "banner": getattr(service, 'banner', ''),
                            "product": getattr(service, 'product', ''),
                            "extrainfo": getattr(service, 'extrainfo', '')
                        }
                        host_info["services"].append(service_info)
                    except Exception as svc_error:
                        logger.warning(f"Error processing service: {svc_error}")
                        continue
            
            hosts_data.append(host_info)
        
        return hosts_data
        
    except Exception as libnmap_error:
        logger.warning(f"libnmap parsing failed: {libnmap_error}, trying manual XML parsing")
        
        # Fallback: Manual XML parsing
        try:
            root = ET.fromstring(xml_content)
            hosts_data = []
            
            for host_elem in root.findall('host'):
                # Get host address
                addr_elem = host_elem.find('address')
                ip = addr_elem.get('addr') if addr_elem is not None else 'unknown'
                
                # Get hostname
                hostnames_elem = host_elem.find('hostnames')
                hostname = ''
                if hostnames_elem is not None:
                    hostname_elem = hostnames_elem.find('hostname')
                    if hostname_elem is not None:
                        hostname = hostname_elem.get('name', '')
                
                # Get host status
                status_elem = host_elem.find('status')
                status = status_elem.get('state') if status_elem is not None else 'unknown'
                
                host_info = {
                    "ip": ip,
                    "hostname": hostname,
                    "status": status,
                    "services": []
                }
                
                # Get ports/services
                ports_elem = host_elem.find('ports')
                if ports_elem is not None:
                    for port_elem in ports_elem.findall('port'):
                        port_num = int(port_elem.get('portid', 0))
                        protocol = port_elem.get('protocol', 'tcp')
                        
                        # Get state
                        state_elem = port_elem.find('state')
                        state = state_elem.get('state') if state_elem is not None else 'unknown'
                        
                        # Get service info
                        service_elem = port_elem.find('service')
                        service_name = 'unknown'
                        version = ''
                        product = ''
                        extrainfo = ''
                        
                        if service_elem is not None:
                            service_name = service_elem.get('name', 'unknown')
                            version = service_elem.get('version', '')
                            product = service_elem.get('product', '')
                            extrainfo = service_elem.get('extrainfo', '')
                        
                        service_info = {
                            "port": port_num,
                            "protocol": protocol,
                            "service": service_name,
                            "version": version,
                            "state": state,
                            "banner": '',
                            "product": product,
                            "extrainfo": extrainfo
                        }
                        
                        host_info["services"].append(service_info)
                
                hosts_data.append(host_info)
            
            return hosts_data
            
        except Exception as manual_error:
            raise Exception(f"Both libnmap and manual parsing failed: {libnmap_error}, {manual_error}")

@app.post("/parse/xml")
async def parse_nmap_xml(data: NmapInput):
    """Parse Nmap XML and return structured JSON"""
    try:
        # Input validation
        if not data.xml_content.strip():
            raise HTTPException(status_code=400, detail="xml_content cannot be empty")
        
        logger.info("Starting Nmap XML parsing")
        
        # Use the safe parser
        hosts_data = parse_nmap_xml_safe(data.xml_content)
        
        logger.info(f"Successfully parsed {len(hosts_data)} hosts with {sum(len(h['services']) for h in hosts_data)} services")
        
        return {
            "status": "success", 
            "hosts": hosts_data,
            "summary": {
                "total_hosts": len(hosts_data),
                "total_services": sum(len(h['services']) for h in hosts_data)
            }
        }
        
    except Exception as e:
        error_msg = f"Parsing failed: {str(e)}"
        logger.error(error_msg)
        logger.error(f"XML content causing error: {data.xml_content[:500]}...")
        raise HTTPException(status_code=500, detail=error_msg)

@app.get("/health")
async def health_check():
    """Health check endpoint (always HTTP 200)"""
    return {"status": "healthy", "service": "parser", "version": "1.0.0"}

@app.get("/")
async def root():
    """Root endpoint with service information"""
    return {
        "service": "Nmap Parser Service",
        "version": "1.0.0",
        "endpoints": {
            "health": "/health",
            "parse": "/parse/xml",
            "metrics": "/metrics"
        }
    }

@app.get("/metrics")
async def metrics():
    return {"metrics": "not_implemented", "service": "parser-service", "version": "1.0.0"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
