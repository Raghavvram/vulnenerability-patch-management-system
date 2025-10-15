try:
    import numpy as np
except ImportError:
    import sys
    class NumpyDummy:
        def array(self, x):
            return x
    np = NumpyDummy()
    sys.modules['numpy'] = np

from typing import Dict, Tuple, List
from datetime import datetime, timedelta
import logging
import pickle
import os

# Configure module logger
logger = logging.getLogger(__name__)

class PrioritizationEngine:
    def __init__(self):
        self.model = self.load_ml_model()
        self.sla_matrix = self.load_sla_configuration()

    def load_ml_model(self):
        """Load ML model for priority prediction"""
        try:
            if os.path.exists("model.pkl") and os.path.getsize("model.pkl") > 0:
                with open("model.pkl", "rb") as f:
                    return pickle.load(f)
            else:
                logger.warning("model.pkl is missing or empty, using DummyModel.")
        except Exception as e:
            logger.warning(f"Could not load ML model: {e}")
        
        # Return a dummy model that always predicts medium probability
        class DummyModel:
            def predict_proba(self, features):
                return np.array([[0.3, 0.7]])  # [low_prob, high_prob]
        return DummyModel()

    def load_sla_configuration(self) -> Dict:
        """Load SLA configuration matrix"""
        return {
            "Critical": {"Critical": 4, "High": 8, "Medium": 12, "Low": 24},
            "High": {"Critical": 24, "High": 48, "Medium": 72, "Low": 96},
            "Medium": {"Critical": 72, "High": 96, "Medium": 120, "Low": 168},
            "Low": {"Critical": 168, "High": 240, "Medium": 336, "Low": 720}
        }

    def calculate_priority_score(self, analysis_data: Dict) -> Tuple[float, str]:
        """Calculate composite priority score using multiple factors"""
        # CVSS component (40% weight)
        cvss_score = analysis_data.get('cvss_max', 0) / 10.0
        
        # EPSS component (30% weight) - exploitation likelihood
        epss_score = analysis_data.get('epss_max', 0)
        
        # Asset criticality (20% weight)
        asset_map = {'Critical': 1.0, 'High': 0.8, 'Medium': 0.5, 'Low': 0.2}
        asset_criticality = analysis_data.get('asset_criticality', 'Medium')
        asset_score = asset_map.get(asset_criticality, 0.5)
        
        # Environmental factors (10% weight)
        env_score = 0.0
        if analysis_data.get('internet_facing'):
            env_score += 0.5
        if not analysis_data.get('compensating_controls'):
            env_score += 0.3
        if analysis_data.get('exploit_available'):
            env_score += 0.2
        
        # Composite score calculation
        composite_score = (
            cvss_score * 0.4 +
            epss_score * 0.3 +
            asset_score * 0.2 +
            min(env_score, 1.0) * 0.1
        )
        
        # ML model prediction for fine-tuning
        try:
            features = np.array([[
                cvss_score, epss_score, asset_score, env_score,
                len(analysis_data.get('attack_techniques', [])),
                1 if analysis_data.get('exploit_available') else 0
            ]])
            
            ml_adjustment = self.model.predict_proba(features)[0][1]  # Probability of high priority
            final_score = (composite_score * 0.7) + (ml_adjustment * 0.3)
        except Exception as e:
            logger.warning(f"ML model prediction failed: {e}")
            final_score = composite_score
        
        # Priority classification
        if final_score >= 0.8:
            priority = "Critical"
        elif final_score >= 0.6:
            priority = "High"
        elif final_score >= 0.4:
            priority = "Medium"
        else:
            priority = "Low"
            
        return final_score, priority

    def assign_sla_timeline(self, priority: str, asset_criticality: str = "Medium") -> Dict:
        """Assign SLA timelines based on priority and asset criticality"""
        sla_hours = self.sla_matrix.get(priority, {}).get(asset_criticality, 168)
        
        return {
            "priority": priority,
            "sla_hours": sla_hours,
            "sla_deadline": (datetime.now() + timedelta(hours=sla_hours)).isoformat(),
            "escalation_threshold": sla_hours * 0.8,
            "emergency_threshold": sla_hours * 1.2
        }

async def prioritize_analyzed_hosts(analyzed_hosts: List[Dict]) -> Dict:
    """Pure function: Prioritize analyzed vulnerability data and return structured dict"""
    engine = PrioritizationEngine()
    prioritized_hosts: List[Dict] = []

    for host in analyzed_hosts:
        prioritized_services = []
        for service in host.get("services", []):
            if service.get("vulnerabilities"):
                score, priority = engine.calculate_priority_score(service)
                sla_info = engine.assign_sla_timeline(
                    priority,
                    service.get('asset_criticality', 'Medium')
                )
                service["priority_info"] = {
                    "priority_score": round(score, 3),
                    "priority": priority,
                    **sla_info
                }
            prioritized_services.append(service)

        host_copy = host.copy()
        host_copy["services"] = prioritized_services
        prioritized_hosts.append(host_copy)

    return {
        "status": "success",
        "prioritized_hosts": prioritized_hosts,
        "summary": {
            "total_hosts": len(prioritized_hosts),
            "prioritized_services": sum(1 for h in prioritized_hosts for s in h.get("services", []) if s.get("vulnerabilities"))
        }
    }
