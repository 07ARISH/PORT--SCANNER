"""
Explainable AI (XAI) Module for Network Vulnerability Detection through Port Intelligence.
Provides both Global Feature Importance and Local Instance Explanations
with Natural Language synthesis and defensive cybersecurity reasoning.
"""

# Base feature importance weights derived from the network risk classification model
DEFAULT_GLOBAL_IMPORTANCE = {
    "CVSS Score Baseline": 0.32,
    "Exposure Level (Public vs Internal)": 0.24,
    "Encryption Availability (TLS/SSL)": 0.16,
    "Service Version Risk & Age": 0.13,
    "Port State (Open/Filtered)": 0.08,
    "Banner & Cleartext Auth Flags": 0.05,
    "Transport Protocol": 0.02
}

def get_global_feature_importance():
    """Returns normalized global feature importances for UI visualization."""
    return [
        {"feature": k, "importance_pct": round(v * 100, 1)}
        for k, v in sorted(DEFAULT_GLOBAL_IMPORTANCE.items(), key=lambda item: item[1], reverse=True)
    ]

def explain_port_risk(port_data, prediction_label, confidence_score):
    """
    Computes local feature attribution and generates human-readable XAI reasoning
    for a specific port intelligence instance.
    """
    port = port_data.get("port", 0)
    service = port_data.get("service", "Unknown")
    protocol = port_data.get("protocol", "TCP")
    version = port_data.get("version", "Standard")
    state = port_data.get("state", "Open")
    cvss = float(port_data.get("cvss_score", 0.0))
    enc = 1 if port_data.get("encryption_detected") else 0
    exposure = port_data.get("exposure_level", "External")
    banner = port_data.get("banner", "")

    reasons = []
    local_contributions = []

    # 1. State check
    if state == "Closed":
        reasons.append({
            "feature": "Port State",
            "type": "Risk Reducer",
            "importance_pct": 85.0,
            "text": "Port is closed and does not listen to incoming socket connections."
        })
        ai_summary = f"Port {port} ({service}) is classified as Safe because the socket is closed, preventing remote network interaction."
        return {
            "reasons": reasons,
            "local_contributions": [{"feature": "Port State (Closed)", "impact": -80}],
            "ai_explanation": ai_summary
        }

    # 2. Database or Administrative Exposure
    db_admin_services = ["MySQL", "PostgreSQL", "MSSQL", "Oracle-DB", "Redis", "MongoDB", "Elasticsearch", "Telnet", "RDP", "VNC", "SMB", "Docker-Daemon"]
    if service in db_admin_services:
        if exposure == "External":
            reasons.append({
                "feature": "Exposure Level",
                "type": "Risk Booster",
                "importance_pct": 32.0,
                "text": f"Critical administrative/database service ({service}) is directly exposed to the public Internet."
            })
            local_contributions.append({"feature": "Public DB/Admin Exposure", "impact": 32})
        else:
            reasons.append({
                "feature": "Exposure Level",
                "type": "Neutral",
                "importance_pct": 12.0,
                "text": f"{service} is restricted to internal subnet/DMZ."
            })
            local_contributions.append({"feature": "Subnet Containment", "impact": -10})

    # 3. Encryption Status
    if enc == 0:
        reasons.append({
            "feature": "Encryption Availability",
            "type": "Risk Booster",
            "importance_pct": 24.0,
            "text": f"Unencrypted transport detected on {service} (credentials and payload transmitted in cleartext)."
        })
        local_contributions.append({"feature": "Missing Transport Encryption", "impact": 24})
    else:
        reasons.append({
            "feature": "Encryption Availability",
            "type": "Risk Reducer",
            "importance_pct": 18.0,
            "text": f"Encrypted session (TLS/SSH/HTTPS) actively protects transmission confidentiality."
        })
        local_contributions.append({"feature": "Active TLS/SSH Protection", "impact": -18})

    # 4. CVSS Baseline & Known CVE indicators
    if cvss >= 8.0:
        reasons.append({
            "feature": "CVSS Vulnerability Score",
            "type": "Risk Booster",
            "importance_pct": 28.0,
            "text": f"Elevated baseline CVSS vulnerability score of {cvss:.1f}/10.0 associated with service footprint."
        })
        local_contributions.append({"feature": f"High CVSS Score ({cvss:.1f})", "impact": 28})
    elif cvss >= 5.0:
        reasons.append({
            "feature": "CVSS Vulnerability Score",
            "type": "Risk Booster",
            "importance_pct": 16.0,
            "text": f"Moderate CVSS baseline score of {cvss:.1f}/10.0 detected."
        })
        local_contributions.append({"feature": f"Moderate CVSS Score ({cvss:.1f})", "impact": 16})
    else:
        reasons.append({
            "feature": "CVSS Vulnerability Score",
            "type": "Risk Reducer",
            "importance_pct": 14.0,
            "text": f"Low CVSS baseline ({cvss:.1f}/10.0) indicating hardened service posture."
        })
        local_contributions.append({"feature": "Minimal Known CVSS", "impact": -14})

    # 5. Banner Flags
    if "Cleartext" in banner or "Default Credentials" in banner or "Obsolete" in banner:
        reasons.append({
            "feature": "Banner Fingerprint",
            "type": "Risk Booster",
            "importance_pct": 12.0,
            "text": f"Service banner indicates '{banner}' susceptibility."
        })
        local_contributions.append({"feature": f"Banner: {banner}", "impact": 12})

    # 6. Synthesize Natural Language Academic Explanation
    if prediction_label in ["Critical", "High"]:
        core_factors = []
        if service in db_admin_services and exposure == "External":
            core_factors.append(f"an exposed {service} service")
        if enc == 0:
            core_factors.append("unencrypted cleartext transmission")
        if cvss >= 7.0:
            core_factors.append(f"an elevated CVSS baseline ({cvss:.1f}/10)")
        if "Default" in banner or "Cleartext" in banner:
            core_factors.append("susceptibility to credential attacks")

        factors_str = " combined with ".join(core_factors) if core_factors else "elevated vulnerability metrics"
        ai_summary = (
            f"Port {port} ({service}) is classified as {prediction_label} with {int(confidence_score * 100)}% confidence "
            f"because {factors_str} significantly expands the network attack surface and introduces actionable exploitation vectors."
        )
    elif prediction_label == "Medium":
        ai_summary = (
            f"Port {port} ({service}) is classified as Medium Risk with {int(confidence_score * 100)}% confidence. "
            f"While the service is operational, detected configuration attributes (CVSS: {cvss:.1f}) warrant defensive auditing and network segment isolation."
        )
    elif prediction_label == "Low":
        ai_summary = (
            f"Port {port} ({service}) is classified as Low Risk ({int(confidence_score * 100)}% confidence). "
            f"Standard security safeguards (such as encryption and contained exposure) limit direct vulnerability exploitation."
        )
    else: # Safe
        ai_summary = (
            f"Port {port} ({service}) is classified as Safe with high confidence. "
            f"The service employs modern cryptographic protocols, minimal exposure, and robust baseline configurations."
        )

    return {
        "reasons": reasons,
        "local_contributions": local_contributions,
        "ai_explanation": ai_summary
    }

def generate_defensive_recommendations(port, service, protocol, risk_level, encryption_detected):
    """
    Generates actionable defensive cybersecurity recommendations for a given port.
    Never provides destructive attack/exploit instructions.
    """
    recs = []

    if service == "FTP":
        recs = [
            "Disable legacy FTP (port 21) if unauthenticated or legacy file transfers are no longer needed.",
            "Migrate active file transfers to SFTP (SSH File Transfer Protocol on port 22) or FTPS with explicit TLS.",
            "Enforce strict firewall rules restricting access to authorized management IP ranges only.",
            "Implement brute-force authentication protection (e.g. Fail2Ban / IP rate limiting)."
        ]
    elif service == "Telnet":
        recs = [
            "Immediately deprecate Telnet (port 23); cleartext protocol exposes passwords to network sniffing.",
            "Replace Telnet with modern SSH (Secure Shell) version 2 utilizing Ed25519 or RSA-4096 keys.",
            "Block inbound port 23 traffic at the perimeter gateway firewall.",
            "Audit systems for legacy scripts relying on unencrypted automated Telnet logins."
        ]
    elif service in ["MySQL", "PostgreSQL", "MSSQL", "Oracle-DB"]:
        recs = [
            f"Never expose database management port ({port}) directly to the public Internet.",
            f"Bind {service} exclusively to localhost (127.0.0.1) or internal private VLAN interfaces.",
            "Require SSL/TLS encrypted connections for all authorized database client sessions.",
            "Enforce strong password entropy, disable default administrative accounts, and restrict user host grants."
        ]
    elif service in ["Redis", "MongoDB", "Elasticsearch"]:
        recs = [
            f"Restrict {service} access strictly behind VPN or private VPC subnets.",
            "Enable native authentication (e.g., Redis requirepass / MongoDB auth) and disable anonymous queries.",
            "Disable dangerous commands (e.g. Redis FLUSHALL, CONFIG) from external callers.",
            "Apply the latest vendor security patches to avoid known Remote Code Execution (RCE) flaws."
        ]
    elif service == "HTTP":
        recs = [
            "Deploy an automated HTTP-to-HTTPS 301 redirect rule to ensure encrypted communication.",
            "Install a valid TLS certificate from an authorized CA (e.g. Let's Encrypt / DigiCert).",
            "Enable HTTP Strict Transport Security (HSTS) response headers.",
            "Configure Web Application Firewall (WAF) to inspect malicious payloads and bot traffic."
        ]
    elif service in ["RDP", "VNC"]:
        recs = [
            "Place remote desktop endpoints behind a secure VPN gateway or Zero Trust Network Access (ZTNA) broker.",
            "Enforce Network Level Authentication (NLA) and Multi-Factor Authentication (MFA).",
            "Change standard listening ports and block public IPv4/IPv6 exposure via edge firewall rules.",
            "Implement account lockout policies after repeated failed login attempts."
        ]
    elif service == "SMB":
        recs = [
            "Block TCP port 445 and NetBIOS ports at the corporate perimeter firewall.",
            "Disable legacy SMBv1 protocol entirely across all endpoints and servers.",
            "Require SMB Signing and SMB Encryption (SMB 3.1.1) to prevent man-in-the-middle attacks.",
            "Ensure latest OS security updates (e.g. MS17-010 / EternalBlue mitigations) are fully applied."
        ]
    elif service == "SSH":
        recs = [
            "Disable root login over SSH (`PermitRootLogin no` in sshd_config).",
            "Enforce public-key authentication only (`PasswordAuthentication no`).",
            "Restrict SSH access using IP allowlisting or bastion host jump-servers.",
            "Upgrade OpenSSH to the latest release and disable deprecated cryptographic ciphers."
        ]
    elif service == "HTTPS":
        recs = [
            "Verify TLS 1.3/1.2 cipher suite configurations and disable SSLv3/TLS 1.0/1.1.",
            "Implement modern security headers (HSTS, Content-Security-Policy, X-Frame-Options).",
            "Conduct periodic SSL certificate validation and monitor expiration dates.",
            "Maintain automated security patching on reverse proxy/web server binaries (Nginx/Apache/Caddy)."
        ]
    else:
        if risk_level in ["High", "Critical"]:
            recs = [
                f"Audit business necessity for running {service} on port {port}.",
                "Isolate service within a dedicated network segment or DMZ.",
                "Apply the latest vendor patches to remediate known CVE vulnerabilities.",
                "Implement stateful firewall rules to permit traffic only from trusted source IPs."
            ]
        else:
            recs = [
                "Maintain regular patch management cycles for the running application daemon.",
                "Monitor network access logs and telemetry for anomalous connection spikes.",
                "Review firewall egress/ingress filtering rules periodically."
            ]

    return recs
