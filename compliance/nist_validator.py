from typing import Dict


# compliance/nist_validator.py
class NISTComplianceValidator:
    def __init__(self):
        self.checklist = self.load_nist_checklist()

    def validate_patch_management_process(self, system_data: Dict) -> Dict:
        """Validate system against NIST SP 800-40r4 requirements"""

        results = {
            "overall_compliance": 0,
            "requirements": {}
        }

        # Section 3.1: Reduce Patching-Related Disruptions
        results["requirements"]["disruption_reduction"] = \
            self.check_disruption_controls(system_data)

        # Section 3.2: Inventory Your Software and Assets
        results["requirements"]["asset_inventory"] = \
            self.check_asset_inventory(system_data)

        # Section 3.3: Define Risk Response Scenarios
        results["requirements"]["risk_scenarios"] = \
            self.check_risk_scenarios(system_data)

        # Section 3.4: Assign Each Asset to a Maintenance Group
        results["requirements"]["maintenance_groups"] = \
            self.check_maintenance_groups(system_data)

        # Section 3.5: Define Maintenance Plans
        results["requirements"]["maintenance_plans"] = \
            self.check_maintenance_plans(system_data)

        # Section 3.6: Choose Actionable Metrics
        results["requirements"]["metrics"] = \
            self.check_metrics_collection(system_data)

        # Calculate overall compliance percentage
        compliance_scores = [req["score"] for req in results["requirements"].values()]
        results["overall_compliance"] = sum(compliance_scores) / len(compliance_scores)

        return results

    def check_asset_inventory(self, system_data: Dict) -> Dict:
        """Verify asset inventory completeness per NIST 3.2"""
        score = 0
        details = []

        # Check if all discovered assets are cataloged
        if system_data.get("asset_catalog"):
            score += 25
            details.append("✓ Asset catalog exists")

        # Verify software inventory
        if system_data.get("software_inventory"):
            score += 25
            details.append("✓ Software inventory maintained")

        # Check for asset criticality classification
        if system_data.get("asset_criticality_assigned"):
            score += 25
            details.append("✓ Asset criticality assigned")


        return {"score": score, "details": details}

