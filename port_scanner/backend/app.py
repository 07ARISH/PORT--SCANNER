"""
Flask REST API Server for Network Vulnerability Detection through Port Intelligence.
Hosts REST endpoints for scan execution, ML risk inference, XAI feature attribution,
historical scan reporting, and serves the mobile-responsive Android frontend.
"""

import os
import sys

# Ensure root directory is on Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from backend.database import (
    init_db, save_scan_record, get_recent_scans,
    get_scan_details, get_port_analysis, get_global_statistics
)
from backend.analyzer import analyze_target, DEMO_TARGET_PROFILES
from backend.xai import get_global_feature_importance
from backend.model import get_loaded_model

# Setup paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
CORS(app)

# Initialize Database & ML Model on startup
@app.before_request
def setup_runtime():
    pass

# Serve Frontend SPA & Static Assets
@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.route("/<path:path>")
def static_proxy(path):
    file_path = os.path.join(FRONTEND_DIR, path)
    if os.path.isfile(file_path):
        return send_from_directory(FRONTEND_DIR, path)
    return send_from_directory(FRONTEND_DIR, "index.html")

# ================= REST API ENDPOINTS =================

@app.route("/api/health", methods=["GET"])
def health():
    """Health check endpoint confirming ML model, DB, and API status."""
    try:
        model = get_loaded_model()
        model_status = "Loaded" if model else "Not Ready"
    except Exception as e:
        model_status = f"Error: {str(e)}"

    return jsonify({
        "status": "healthy",
        "service": "Network Vulnerability Intelligence API",
        "model_status": model_status,
        "database": "SQLite Active",
        "framework": "Explainable AI (XAI) + Port Intelligence",
        "version": "1.0.0"
    })

@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Executes vulnerability detection on a target.
    Request body JSON:
    {
        "target": "192.168.1.10",
        "mode": "demo" | "live",
        "preset": "enterprise" | "scada" | "cloud" | "hardened"
    }
    """
    try:
        data = request.get_json() or {}
        target = data.get("target", "192.168.1.10")
        mode = data.get("mode", "demo")
        preset = data.get("preset", "enterprise")

        # Execute analysis pipeline
        scan_result = analyze_target(target=target, mode=mode, preset=preset)

        # Save to SQLite database
        scan_id = save_scan_record(scan_result)
        scan_result["id"] = scan_id

        return jsonify({
            "success": True,
            "message": "Analysis completed successfully.",
            "data": scan_result
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route("/api/scans", methods=["GET"])
def list_scans():
    """Retrieves list of recent scan sessions."""
    try:
        limit = int(request.args.get("limit", 15))
        scans = get_recent_scans(limit=limit)
        return jsonify({"success": True, "scans": scans})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/results/<int:scan_id>", methods=["GET"])
def get_results(scan_id):
    """Retrieves complete scan results including all port assessments and XAI explanations."""
    try:
        scan = get_scan_details(scan_id)
        if not scan:
            return jsonify({"success": False, "error": "Scan record not found"}), 404
        return jsonify({"success": True, "data": scan})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/port/<int:scan_id>/<int:port_number>", methods=["GET"])
def get_port_details(scan_id, port_number):
    """Retrieves deep-dive intelligence and XAI explanations for an individual port."""
    try:
        port_info = get_port_analysis(scan_id, port_number)
        if not port_info:
            return jsonify({"success": False, "error": "Port result not found"}), 404
        return jsonify({"success": True, "data": port_info})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/statistics", methods=["GET"])
def statistics():
    """Retrieves aggregated vulnerability and network intelligence statistics."""
    try:
        stats = get_global_statistics()
        return jsonify({"success": True, "data": stats})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/xai-global", methods=["GET"])
def xai_global():
    """Retrieves global Explainable AI feature importance metrics."""
    try:
        importances = get_global_feature_importance()
        return jsonify({
            "success": True,
            "data": importances,
            "description": "Global feature attributions derived from the Random Forest model"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/presets", methods=["GET"])
def get_presets():
    """Returns available demo target scenario presets."""
    presets = [
        {
            "id": "enterprise",
            "name": "Corporate Web & Database Bastion",
            "target": "192.168.1.10",
            "description": "Enterprise environment with exposed MySQL (3306), Redis (6379), HTTP (80), and OpenSSH (22)."
        },
        {
            "id": "scada",
            "name": "Industrial SCADA / OT Node",
            "target": "10.0.4.55",
            "description": "Legacy industrial automation unit running cleartext Modbus-TCP (502), Telnet (23), and VNC (5900)."
        },
        {
            "id": "cloud",
            "name": "Cloud Native Microservices Gateway",
            "target": "172.24.0.12",
            "description": "Kubernetes cluster gateway with exposed Docker Daemon API (2375) and Elasticsearch (9200)."
        },
        {
            "id": "hardened",
            "name": "Hardened Defense Perimeter",
            "target": "10.10.10.1",
            "description": "Hardened security bastion running TLS 1.3 HTTPS (443) and key-authenticated OpenSSH 9.6 (22)."
        }
    ]
    return jsonify({"success": True, "presets": presets})

def initialize_app():
    """Bootstraps database and ML model before running server."""
    print("[*] Initializing Database...")
    init_db()
    print("[*] Loading / Training Machine Learning Model...")
    get_loaded_model()
    print("[+] Application bootstrap complete.")

if __name__ == "__main__":
    initialize_app()
    # Listen on all interfaces (0.0.0.0) so it's accessible from Android devices over LAN
    port = int(os.environ.get("PORT", 5000))
    print(f"\n=======================================================")
    print(f"  AI Network Vulnerability Detection Server Running!  ")
    print(f"  Local URL:   http://localhost:{port}                ")
    print(f"  Network URL: http://0.0.0.0:{port}                  ")
    print(f"=======================================================\n")
    app.run(host="0.0.0.0", port=port, debug=False)
