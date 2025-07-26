from typing import Dict


# compliance/iso27001_validator.py
class ISO27001Validator:
    def validate_technical_vulnerability_management(self, system_data: Dict) -> Dict:
        """Validate against ISO 27001:2022 Annex A 8.8"""

        results = {
            "control_8_8_compliance": 0,
            "evidence": {}
        }

        # A.8.8.1: Information about technical vulnerabilities should be obtained
        info_gathering_score = self.assess_vulnerability_information_gathering(system_data)
        results["evidence"]["information_gathering"] = info_gathering_score

        # A.8.8.2: Exposure to vulnerabilities should be evaluated
        exposure_evaluation_score = self.assess_exposure_evaluation(system_data)
        results["evidence"]["exposure_evaluation"] = exposure_evaluation_score

        # A.8.8.3: Appropriate measures should be taken
        remediation_measures_score = self.assess_remediation_measures(system_data)
        results["evidence"]["remediation_measures"] = remediation_measures_score

        # Calculate overall compliance
        scores = [
            info_gathering_score["score"],
            exposure_evaluation_score["score"],
            remediation_measures_score["score"]
        ]
        results["control_8_8_compliance"] = sum(scores) / len(scores)

        return results

    def assess_vulnerability_information_gathering(self, system_data: Dict) -> Dict:
        """Assess vulnerability information gathering processes"""
        score = 0
        evidence = []

        # Check for automated vulnerability scanning
        if system_data.get("automated_scanning"):
            score += 20
            evidence.append("Automated vulnerability scanning implemented")

        # Verify threat intelligence integration
        if system_data.get("threat_intelligence"):
            score += 20
            evidence.append("Threat intelligence feeds integrated")

        # Check vendor advisory monitoring
        if system_data.get("vendor_advisories"):
            score += 20
            evidence.append("Vendor security advisories monitored")

        # Verify CVE database integration
        if system_data.get("cve_integration"):
            score += 20
            evidence.append("CVE database integration active")

        # Check for continuous monitoring
        if system_data.get("continuous_monitoring"):
            score += 20
            evidence.append("Continuous vulnerability monitoring enabled")

        return {"score": score, "evidence": evidence}

