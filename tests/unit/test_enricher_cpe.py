from services.enricher_service.main import VulnerabilityEnricher


def test_generate_cpe_uses_native_cpe_when_available():
    enricher = VulnerabilityEnricher()
    # Service with native Nmap CPE 2.2 where service name is generic
    service_data = {
        "service": "mysql",
        "product": "",
        "version": "",
        "cpe": "cpe:/a:mariadb:mariadb:10.5.8"
    }
    cpe = enricher.generate_cpe(service_data)
    assert cpe == "cpe:2.3:a:mariadb:mariadb:10.5.8:*:*:*:*:*:*:*"


def test_generate_cpe_fallback_with_extracted_version():
    enricher = VulnerabilityEnricher()
    service_data = {
        "service": "http",
        "product": "Apache httpd",
        "version": "2.4.65"
    }
    cpe = enricher.generate_cpe(service_data)
    assert cpe == "cpe:2.3:a:apache:http_server:2.4.65:*:*:*:*:*:*:*"


def test_generate_cpe_handles_cpe_23_directly():
    enricher = VulnerabilityEnricher()
    service_data = {
        "service": "http",
        "cpe": "cpe:2.3:a:apache:http_server:2.4.65:*:*:*:*:*:*:*"
    }
    cpe = enricher.generate_cpe(service_data)
    assert cpe == "cpe:2.3:a:apache:http_server:2.4.65:*:*:*:*:*:*:*"


def test_generate_cpe_uses_cpelist_when_cpe_field_absent():
    enricher = VulnerabilityEnricher()
    service_data = {
        "service": "postgres",
        "cpelist": ["cpe:/a:postgresql:postgresql:15.2"]
    }
    cpe = enricher.generate_cpe(service_data)
    assert cpe == "cpe:2.3:a:postgresql:postgresql:15.2:*:*:*:*:*:*:*"
