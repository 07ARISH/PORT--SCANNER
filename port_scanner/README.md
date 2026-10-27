# An Explainable AI Framework for Real-Time Network Vulnerability Detection Through Port Intelligence

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0%2B-black.svg)](https://flask.palletsprojects.com/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.4%2B-orange.svg)](https://scikit-learn.org/)
[![Android-Ready](https://img.shields.io/badge/Android-Compatible%20PWA%2FWebView-success.svg)](#android-compatibility--mobile-usage)

---

## 1. Project Abstract

In contemporary enterprise networks, open ports and exposed services represent the primary entry points for cyber adversaries. Traditional vulnerability assessment approaches often rely on signature-based scanners that produce static, opaque severity numbers without actionable, interpretable justifications. 

This project introduces **PortIntel XAI**, an academic-grade cybersecurity framework that bridges **Defensive Port Intelligence** and **Explainable Artificial Intelligence (XAI)**. The framework ingests multi-dimensional port telemetry (service protocols, version fingerprints, exposure layers, CVSS baselines, and cryptographic flags) to classify vulnerability risk across five discrete tiers: `Safe`, `Low`, `Medium`, `High`, and `Critical`. 

Crucially, rather than operating as an uninterpretable black box, the system deploys an **Explainable AI (XAI)** engine combining **Tree-based Local Feature Attribution** and **Natural Language Reasoning Synthesis**. It dynamically articulates *why* a particular service is classified as risky (e.g., public exposure of unencrypted database daemons) and generates tailored, non-destructive defensive remediation blueprints. Designed mobile-first, the web application runs seamlessly across desktop browsers, Android mobile devices, and Android WebViews.

---

## 2. System Architecture

```
+-----------------------------------------------------------------------------------+
|                           Android / Web Client Layer                              |
|   +-----------------------+ +-----------------------+ +-----------------------+   |
|   |  Responsive Dashboard | |  Port Intel Inventory | |      XAI Studio       |   |
|   |  (Metrics & Gauge)    | |  (Filter & Search)    | |  (Waterfall & Reason) |   |
|   +-----------------------+ +-----------------------+ +-----------------------+   |
|   +-----------------------+ +-----------------------+ +-----------------------+   |
|   | Vulnerability Matrix  | | Real-Time Live Feed   | | PDF Security Reports  |   |
|   +-----------------------+ +-----------------------+ +-----------------------+   |
+------------------------------------------+----------------------------------------+
                                           | REST API (HTTP/JSON)
                                           v
+-----------------------------------------------------------------------------------+
|                              Flask REST Backend API                               |
|   +-------------------------+ +-------------------------+ +---------------------+ |
|   |   /api/analyze (POST)   | |   /api/scans (GET)      | | /api/health (GET)   | |
|   |   /api/results (GET)    | |   /api/port (GET)       | | /api/xai-global(GET)| |
|   +-------------------------+ +-------------------------+ +---------------------+ |
+------------------+-----------------------+----------------------+-----------------+
                   |                       |                      |
                   v                       v                      v
+-----------------------------+ +--------------------+ +----------------------------+
|  Port Intelligence Engine   | | SQLite DB Engine   | | Explainable AI (XAI)       |
|  - Safe Socket Probe        | | (vulnerability.db) | | - Local Feature Impact     |
|  - Demo Threat Scenarios    | | - Scans            | | - Global Feature Ranking   |
|  - Banner / Transport Audit | | - Port Results     | | - Natural Language Reason  |
|  - Composite Risk Index     | | - Explanations     | | - Hardening Directives     |
+--------------+--------------+ +--------------------+ +--------------+-------------+
               |                                                      |
               +---------------------------> + <----------------------+
                                             |
                                             v
                           +-----------------------------------+
                           |  Machine Learning Pipeline        |
                           |  - Preprocessor: ColumnTransformer|
                           |  - Random Forest Classifier (120) |
                           |  - Risk Output: Safe -> Critical  |
                           +-----------------------------------+
```

---

## 3. Technology Stack

* **Frontend**: HTML5, CSS3 (Cybersecurity Dark Theme, Glassmorphism, CSS Grid/Flexbox), JavaScript (ES6+), Chart.js 4.4, Font Awesome 6.4, html2pdf.js.
* **Backend**: Python 3.10+, Flask, Flask-CORS.
* **Machine Learning**: Scikit-Learn (Random Forest Classifier, ColumnTransformer, OneHotEncoder, StandardScaler), Pandas, NumPy.
* **Database**: SQLite 3 (`database/vulnerability.db`).
* **Mobile Compatibility**: Responsive Android touch-optimized layout, Chrome Mobile, Android WebView / Capacitor support.

---

## 4. Machine Learning & Explainable AI (XAI) Methodology

### 4.1 Feature Schema
The model analyzes 10 diagnostic port intelligence dimensions:

| Feature | Type | Description |
| :--- | :--- | :--- |
| `port` | Numerical | Port number (1–65535) |
| `protocol` | Categorical | Transport layer protocol (`TCP`, `UDP`) |
| `service` | Categorical | Identified daemon (`HTTP`, `HTTPS`, `SSH`, `MySQL`, `Redis`, `FTP`, `Telnet`, etc.) |
| `port_state` | Categorical | Socket status (`Open`, `Filtered`, `Closed`) |
| `service_version_risk` | Numerical | Metric representing service age and unpatched vulnerability status (0.0 to 1.0) |
| `exposure_level` | Categorical | Network boundary placement (`Internal`, `External`, `DMZ`) |
| `known_vuln_indicator`| Binary | Presence of published high-severity CVE signatures (0 or 1) |
| `cvss_baseline` | Numerical | Base Common Vulnerability Scoring System baseline (0.0 to 10.0) |
| `banner_flags` | Categorical | Insecure authentication indicators (`Cleartext Auth`, `Default Creds`, `None`) |
| `encryption_detected` | Binary | Cryptographic protocol active (`1` for TLS/SSH/HTTPS, `0` for Cleartext) |

### 4.2 XAI Formulation & Reasoning Synthesis
The Explainable AI module delivers two layers of transparency:

1. **Global Interpretability**: Extracts normalized Gini importance scores across all model decision trees:
   $$\text{Importance}_{\text{Global}}(f) = \frac{1}{N_{\text{trees}}} \sum_{t=1}^{N_{\text{trees}}} \Delta \text{Impurity}_t(f)$$
2. **Local Instance Attribution**: Computes the exact risk boosters and risk reducers for any scanned port:
   $$\text{Risk Impact}(f_i) = w_i \cdot \text{Significance}(f_i \mid \text{Target Context})$$
3. **Natural Language AI Reasoning**: Synthesizes human-readable cybersecurity justifications, e.g.:
   > *"Port 3306 (MySQL) is classified as Critical with 97% confidence because an exposed database service combined with unencrypted cleartext transmission and an elevated CVSS baseline (8.9/10) significantly expands the network attack surface and permits credential harvesting."*

---

## 5. Risk Score Formulation

The framework calculates an **Overall Network Risk Score** ($S_{\text{network}} \in [0, 100]$):

$$S_{\text{network}} = 0.65 \cdot \max_{p \in \text{Ports}}(\text{RiskWeight}_p) + 0.35 \cdot \left( \frac{1}{|\text{Ports}|} \sum_{p \in \text{Ports}} \text{RiskWeight}_p \right)$$

* **0–20**: `Safe` (Hardened, encrypted perimeter)
* **21–40**: `Low Risk` (Minor exposure, active encryption)
* **41–60**: `Medium Risk` (Configuration audits warranted)
* **61–80**: `High Risk` (Unencrypted legacy protocols, elevated CVSS)
* **81–100**: `Critical Risk` (Exposed databases, remote root shells, zero-day CVEs)

---

## 6. Directory Structure

```text
port_scanner/
│
├── backend/
│   ├── app.py                 # Flask REST server & static hosting
│   ├── model.py               # ML training pipeline & inference engine
│   ├── analyzer.py            # Port intelligence & risk scoring engine
│   ├── xai.py                 # Local/Global Explainable AI module
│   ├── database.py            # SQLite schema & persistence helpers
│   ├── test_backend.py        # Automated test suite
│   └── requirements.txt       # Python dependencies
│
├── frontend/
│   ├── index.html             # Responsive cybersecurity dashboard SPA
│   ├── css/
│   │   └── style.css          # Dark cybersecurity glassmorphism styling
│   └── js/
│       ├── dashboard.js       # UI state, tabs, modals & PDF generator
│       ├── analyzer.js        # API controller & live activity feed
│       └── charts.js          # Chart.js gauge, doughnut & XAI bar charts
│
├── data/
│   ├── generate_dataset.py    # Synthetic realistic dataset generator
│   └── training_data.csv      # 3,000+ port intelligence records
│
├── models/
│   └── vulnerability_model.pkl# Serialized Random Forest classifier
│
├── database/
│   └── vulnerability.db       # SQLite scan & XAI database
│
└── README.md                  # Project documentation
```

---

## 7. Quick Start & Execution Guide

### Step 1: Install Dependencies
```bash
cd port_scanner
pip install -r backend/requirements.txt
```

### Step 2: Generate Dataset & Train ML Model
```bash
python data/generate_dataset.py
python backend/model.py
```

### Step 3: Run Automated Verification Tests
```bash
python backend/test_backend.py
```

### Step 4: Launch Flask Backend & Dashboard
```bash
python backend/app.py
```
Open your browser and navigate to: **`http://localhost:5000`**

---

## 8. Android Compatibility & Mobile Usage

The dashboard is engineered mobile-first to ensure accessibility from Android smartphones, tablets, and mobile field kits.

### Accessing via Android Browser (Chrome Mobile / Firefox Mobile)
1. Ensure your PC running the backend and your Android device are connected to the **same Wi-Fi / Local Area Network (LAN)**.
2. Identify your computer's local IP address (e.g. `192.168.1.15`).
3. Launch the server:
   ```bash
   python backend/app.py
   ```
4. On your Android phone, open Chrome or Firefox and navigate to:
   ```text
   http://192.168.1.15:5000
   ```
5. **Add to Home Screen (PWA Experience)**:
   * In Chrome Mobile, tap the **three dots menu ⋮** -> tap **"Add to Home screen"**.
   * The app will launch with a native full-screen app experience.

### Building as an Android APK (Capacitor / WebView)
To package this web dashboard into a standalone Android APK:
```bash
npm install @capacitor/core @capacitor/cli @capacitor/android
npx cap init "PortIntelXAI" "com.cyber.portintel" --web-dir "frontend"
npx cap add android
npx cap open android
```
Build and run the APK directly in Android Studio.

---

## 9. Demo Scenarios & Defensive Modes

The application includes four rich **Demo Threat Profiles** to allow comprehensive academic presentations without unauthorized active network scanning:

1. **Enterprise Web & Database Bastion (`192.168.1.10`)**:
   * Analyzes exposed MySQL (3306), Redis (6379), HTTP (80), OpenSSH (22), PostgreSQL (5432).
   * Highlights database exposure and cleartext transmission risks.
2. **Industrial SCADA / OT Node (`10.0.4.55`)**:
   * Evaluates unauthenticated Modbus-TCP (502), Telnet (23), VNC (5900), and SNMP (161).
   * Triggers critical industrial protocol isolation warnings.
3. **Cloud Native Microservices Node (`172.24.0.12`)**:
   * Assesses unauthenticated Docker Daemon API (2375), Elasticsearch (9200), and Kubernetes API (6443).
4. **Hardened Defense Perimeter (`10.10.10.1`)**:
   * Demonstrates a hardened security posture (TLS 1.3 HTTPS, Ed25519 OpenSSH, STARTTLS SMTP).

---

## 10. Defensive Cybersecurity Disclaimer

This framework is built strictly for **authorized defensive cybersecurity auditing, academic research, risk quantification, and defensive education**. It does not perform destructive exploitation, denial of service (DoS), or unauthorized penetration. Always ensure proper written authorization prior to assessing any networked device.
