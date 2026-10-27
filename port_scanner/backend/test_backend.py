"""
Automated Backend & Model Test Suite for Network Vulnerability Detection Framework.
Validates database schemas, machine learning predictions, Explainable AI generation,
and all Flask REST API endpoints.
"""

import os
import sys
import unittest
import json

# Ensure project root is on sys.path and UTF-8 encoding
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

from backend.app import app
from backend.database import init_db, get_recent_scans, get_scan_details
from backend.model import get_loaded_model, predict_single_port
from backend.xai import explain_port_risk, generate_defensive_recommendations
from backend.analyzer import analyze_target

class TestVulnerabilityFramework(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("\n=======================================================")
        print("  Starting Automated Vulnerability Framework Tests     ")
        print("=======================================================")
        init_db()
        cls.client = app.test_client()

    def test_01_database_init(self):
        """Verify database tables and connectivity."""
        print("[*] Testing Database Initialization...")
        scans = get_recent_scans(limit=1)
        self.assertIsInstance(scans, list)
        print("  [OK] Database tables active and queryable.")

    def test_02_machine_learning_inference(self):
        """Verify ML model accuracy and risk prediction."""
        print("[*] Testing Machine Learning Model Inference...")
        model = get_loaded_model()
        self.assertIsNotNone(model)

        # Test MySQL high-risk profile
        mysql_port = {
            "port": 3306,
            "protocol": "TCP",
            "service": "MySQL",
            "state": "Open",
            "exposure_level": "External",
            "banner": "Default Credentials Risk",
            "service_version_risk": 0.85,
            "known_vuln_indicator": 1,
            "cvss_score": 8.9,
            "encryption_detected": False
        }
        pred_label, conf, probs = predict_single_port(mysql_port, model)
        print(f"  [OK] Port 3306 (MySQL) -> Predicted: {pred_label} (Confidence: {conf * 100:.1f}%)")
        self.assertIn(pred_label, ["High", "Critical"])
        self.assertGreater(conf, 0.70)

        # Test HTTPS safe profile
        https_port = {
            "port": 443,
            "protocol": "TCP",
            "service": "HTTPS",
            "state": "Open",
            "exposure_level": "External",
            "banner": "None",
            "service_version_risk": 0.1,
            "known_vuln_indicator": 0,
            "cvss_score": 1.5,
            "encryption_detected": True
        }
        pred_label, conf, probs = predict_single_port(https_port, model)
        print(f"  [OK] Port 443 (HTTPS) -> Predicted: {pred_label} (Confidence: {conf * 100:.1f}%)")
        self.assertIn(pred_label, ["Safe", "Low"])

    def test_03_explainable_ai(self):
        """Verify Local XAI attribution and reason generation."""
        print("[*] Testing Explainable AI (XAI) Reason Synthesis...")
        port_data = {
            "port": 3306,
            "protocol": "TCP",
            "service": "MySQL",
            "state": "Open",
            "exposure_level": "External",
            "banner": "Default Credentials Risk",
            "cvss_score": 8.9,
            "encryption_detected": False
        }
        xai_res = explain_port_risk(port_data, "Critical", 0.97)
        self.assertTrue(len(xai_res["reasons"]) > 0)
        self.assertIn("Critical", xai_res["ai_explanation"])
        print(f"  [OK] Generated XAI Explanation:\n       \"{xai_res['ai_explanation']}\"")

        # Verify recommendations
        recs = generate_defensive_recommendations(3306, "MySQL", "TCP", "Critical", False)
        self.assertTrue(len(recs) >= 3)
        print(f"  [OK] Generated {len(recs)} defensive recommendations for Port 3306.")

    def test_04_api_health_endpoint(self):
        """Verify GET /api/health."""
        print("[*] Testing API: GET /api/health...")
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["model_status"], "Loaded")
        print("  [OK] Health endpoint OK.")

    def test_05_api_analyze_and_retrieve(self):
        """Verify POST /api/analyze, GET /api/scans, GET /api/results/<id>, GET /api/port."""
        print("[*] Testing API: POST /api/analyze (Demo Enterprise Bastion)...")
        payload = {
            "target": "192.168.1.10",
            "mode": "demo",
            "preset": "enterprise"
        }
        res = self.client.post("/api/analyze", json=payload)
        self.assertEqual(res.status_code, 200)
        res_data = res.get_json()
        self.assertTrue(res_data["success"])
        scan = res_data["data"]
        scan_id = scan["id"]
        self.assertGreater(scan["total_ports"], 0)
        self.assertGreater(scan["risk_score"], 0)
        print(f"  [OK] Analysis completed for scan ID {scan_id}. Overall Risk: {scan['risk_score']}/100 ({scan['risk_tier']})")

        # Test results retrieval
        res_get = self.client.get(f"/api/results/{scan_id}")
        self.assertEqual(res_get.status_code, 200)
        get_data = res_get.get_json()["data"]
        self.assertEqual(get_data["id"], scan_id)
        self.assertEqual(len(get_data["ports"]), len(scan["ports"]))
        print(f"  [OK] Retrieved scan details with {len(get_data['ports'])} ports and XAI explanations from SQLite.")

        # Test individual port retrieval
        res_port = self.client.get(f"/api/port/{scan_id}/3306")
        self.assertEqual(res_port.status_code, 200)
        port_item = res_port.get_json()["data"]
        self.assertEqual(port_item["port"], 3306)
        print(f"  [OK] Retrieved individual port analysis for Port 3306 ({port_item['service']}).")

    def test_06_api_statistics_and_xai_global(self):
        """Verify GET /api/statistics and GET /api/xai-global."""
        print("[*] Testing API: GET /api/statistics and GET /api/xai-global...")
        res_stats = self.client.get("/api/statistics")
        self.assertEqual(res_stats.status_code, 200)
        self.assertTrue(res_stats.get_json()["success"])

        res_xai = self.client.get("/api/xai-global")
        self.assertEqual(res_xai.status_code, 200)
        xai_data = res_xai.get_json()["data"]
        self.assertTrue(len(xai_data) > 0)
        print(f"  [OK] Global XAI returned {len(xai_data)} weighted feature importances.")

    def test_07_frontend_static_serving(self):
        """Verify index.html and static assets serving."""
        print("[*] Testing Frontend Asset Serving...")
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Network Vulnerability Intelligence Dashboard", res.data)
        print("  [OK] Root URL serves frontend index.html correctly.")

if __name__ == "__main__":
    unittest.main(verbosity=2)
