-- Create vulnerabilities table
-- Create the main vulnerabilities table (FULLY CORRECTED)
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    asset_ip INET NOT NULL,
    asset_hostname VARCHAR(255),
    cve_id VARCHAR(20),
    cvss_score DECIMAL(3,1),
    epss_score DECIMAL(5,4),
    priority VARCHAR(10) CHECK (priority IN ('Critical', 'High', 'Medium', 'Low')),
    status VARCHAR(20) CHECK (status IN ('open', 'in_progress', 'remediated', 'false_positive')),
    discovered_at TIMESTAMP NOT NULL DEFAULT NOW(),
    remediated_at TIMESTAMP,              -- FIXED: Complete field definition
    asset_criticality VARCHAR(10) DEFAULT 'Medium',
    business_unit VARCHAR(100),
    owner_team VARCHAR(100),
    service_name VARCHAR(100),
    service_version VARCHAR(100),
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);


-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_vuln_priority ON vulnerabilities(priority);


-- Insert mock data for dashboard demo
INSERT INTO vulnerabilities (
    asset_ip, asset_hostname, cve_id, cvss_score, epss_score, priority, status, discovered_at, remediated_at, asset_criticality, business_unit, owner_team, service_name, service_version, description
) VALUES
    ('192.168.1.10', 'web-server-01', 'CVE-2024-1234', 9.8, 0.9500, 'Critical', 'open', NOW() - INTERVAL '10 days', NULL, 'High', 'IT', 'SecOps', 'nginx', '1.18.0', 'Remote code execution vulnerability'),
    ('192.168.1.11', 'db-server-01', 'CVE-2024-5678', 8.2, 0.8500, 'High', 'remediated', NOW() - INTERVAL '20 days', NOW() - INTERVAL '5 days', 'Medium', 'Finance', 'DBA', 'postgres', '13.3', 'Privilege escalation vulnerability'),
    ('192.168.1.12', 'app-server-01', 'CVE-2024-4321', 6.5, 0.6000, 'Medium', 'open', NOW() - INTERVAL '5 days', NULL, 'Medium', 'HR', 'AppTeam', 'tomcat', '9.0.54', 'Information disclosure vulnerability'),
    ('192.168.1.13', 'web-server-02', 'CVE-2024-8765', 9.5, 0.9000, 'Critical', 'remediated', NOW() - INTERVAL '25 days', NOW() - INTERVAL '2 days', 'High', 'IT', 'SecOps', 'apache', '2.4.51', 'Buffer overflow vulnerability'),
    ('192.168.1.14', 'dev-server-01', 'CVE-2024-1111', 3.1, 0.2000, 'Low', 'open', NOW() - INTERVAL '2 days', NULL, 'Low', 'Dev', 'DevOps', 'node', '16.13.0', 'Denial of service vulnerability');

