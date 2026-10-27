"""
Dataset Generator for Network Vulnerability Detection through Port Intelligence.
Generates synthetic yet highly realistic network telemetry dataset with realistic
cybersecurity port, protocol, service, exposure, and vulnerability characteristics.
"""

import os
import random
import pandas as pd
import numpy as np

# Seed for reproducibility
np.random.seed(42)
random.seed(42)

PORTS_KNOWLEDGE = [
    # port, protocol, service, default_enc, base_exposure, typical_cvss, default_banner
    (21, "TCP", "FTP", 0, "External", 7.5, "Cleartext Auth"),
    (22, "TCP", "SSH", 1, "External", 3.0, "None"),
    (23, "TCP", "Telnet", 0, "External", 8.8, "Cleartext Auth"),
    (25, "TCP", "SMTP", 0, "External", 5.5, "None"),
    (53, "UDP", "DNS", 0, "Internal", 3.5, "None"),
    (69, "UDP", "TFTP", 0, "Internal", 6.8, "Cleartext Auth"),
    (80, "TCP", "HTTP", 0, "External", 6.5, "Obsolete Cipher"),
    (88, "TCP", "Kerberos", 1, "Internal", 3.0, "None"),
    (110, "TCP", "POP3", 0, "External", 7.0, "Cleartext Auth"),
    (123, "UDP", "NTP", 0, "Internal", 2.5, "None"),
    (135, "TCP", "MSRPC", 0, "Internal", 7.2, "Default Credentials Risk"),
    (139, "TCP", "NetBIOS", 0, "Internal", 7.8, "Cleartext Auth"),
    (143, "TCP", "IMAP", 0, "External", 6.0, "Cleartext Auth"),
    (161, "UDP", "SNMP", 0, "Internal", 7.5, "Default Credentials Risk"),
    (389, "TCP", "LDAP", 0, "Internal", 6.2, "Cleartext Auth"),
    (443, "TCP", "HTTPS", 1, "External", 1.8, "None"),
    (445, "TCP", "SMB", 0, "External", 9.3, "Default Credentials Risk"),
    (465, "TCP", "SMTPS", 1, "External", 2.2, "None"),
    (502, "TCP", "Modbus", 0, "External", 9.0, "Cleartext Auth"),
    (587, "TCP", "SMTP-Submission", 1, "External", 2.8, "None"),
    (636, "TCP", "LDAPS", 1, "Internal", 2.0, "None"),
    (993, "TCP", "IMAPS", 1, "External", 1.9, "None"),
    (995, "TCP", "POP3S", 1, "External", 1.9, "None"),
    (1433, "TCP", "MSSQL", 0, "External", 8.6, "Default Credentials Risk"),
    (1521, "TCP", "Oracle-DB", 0, "External", 8.4, "Default Credentials Risk"),
    (2049, "TCP", "NFS", 0, "Internal", 7.0, "None"),
    (2375, "TCP", "Docker-Daemon", 0, "External", 9.8, "Cleartext Auth"),
    (3306, "TCP", "MySQL", 0, "External", 8.9, "Default Credentials Risk"),
    (3389, "TCP", "RDP", 1, "External", 7.8, "Obsolete Cipher"),
    (5432, "TCP", "PostgreSQL", 0, "External", 8.2, "Default Credentials Risk"),
    (5900, "TCP", "VNC", 0, "External", 8.5, "Cleartext Auth"),
    (6379, "TCP", "Redis", 0, "External", 9.2, "Default Credentials Risk"),
    (8080, "TCP", "HTTP-Proxy", 0, "External", 6.8, "Obsolete Cipher"),
    (8443, "TCP", "HTTPS-Alt", 1, "External", 2.5, "None"),
    (9200, "TCP", "Elasticsearch", 0, "External", 8.7, "Default Credentials Risk"),
    (27017, "TCP", "MongoDB", 0, "External", 9.0, "Default Credentials Risk"),
]

BANNER_TYPES = ["None", "Cleartext Auth", "Default Credentials Risk", "Obsolete Cipher", "Anonymized"]
EXPOSURE_TYPES = ["Internal", "External", "DMZ"]
PROTOCOLS = ["TCP", "UDP"]
PORT_STATES = ["Open", "Filtered", "Closed"]

def calculate_ground_truth_risk(port_state, cvss, exposure, enc, version_risk, known_vuln, service):
    if port_state == "Closed":
        return "Safe"
    
    # Calculate composite vulnerability risk index (0 - 100)
    score = 0.0
    
    # CVSS baseline contribution (up to 40 pts)
    score += (cvss / 10.0) * 40.0
    
    # Exposure contribution (up to 20 pts)
    if exposure == "External":
        score += 20.0
    elif exposure == "DMZ":
        score += 12.0
    else: # Internal
        score += 5.0
        
    # Encryption status (15 pts penalty for unencrypted)
    if enc == 0:
        score += 15.0
        
    # Service version risk (up to 15 pts)
    score += version_risk * 15.0
    
    # Known vulnerability indicator (10 pts)
    if known_vuln == 1:
        score += 10.0
        
    # High-risk database/remote administration ports exposed publicly
    if service in ["Telnet", "FTP", "SMB", "Docker-Daemon", "Redis", "MongoDB", "MySQL", "MSSQL", "VNC", "Modbus"] and exposure == "External":
        score += 10.0
        
    # Filtered state reduces active exploitability
    if port_state == "Filtered":
        score *= 0.65
        
    # Map score to multi-class label
    if score >= 75.0:
        return "Critical"
    elif score >= 55.0:
        return "High"
    elif score >= 35.0:
        return "Medium"
    elif score >= 18.0:
        return "Low"
    else:
        return "Safe"

def generate_dataset(num_samples=3000, output_path="../data/training_data.csv"):
    records = []
    
    # Generate balanced representative records from known port catalog
    for _ in range(num_samples):
        # 80% known common ports, 20% random/ephemeral ports
        if random.random() < 0.85:
            template = random.choice(PORTS_KNOWLEDGE)
            port, proto, service, base_enc, base_exp, base_cvss, base_banner = template
            
            # Add minor variations
            enc = base_enc if random.random() > 0.1 else (1 - base_enc)
            exposure = random.choice(EXPOSURE_TYPES) if random.random() < 0.25 else base_exp
            cvss = max(0.0, min(10.0, base_cvss + np.random.normal(0, 1.0)))
            banner = base_banner if random.random() > 0.2 else random.choice(BANNER_TYPES)
        else:
            port = random.randint(1024, 65535)
            proto = random.choice(PROTOCOLS)
            service = random.choice(["Custom-Service", "Unknown-App", "Web-Hook", "RPC-Node", "Peer2Peer", "Microservice"])
            enc = random.choice([0, 1])
            exposure = random.choice(EXPOSURE_TYPES)
            cvss = random.uniform(0.0, 9.5)
            banner = random.choice(BANNER_TYPES)
            
        port_state = random.choices(["Open", "Filtered", "Closed"], weights=[0.75, 0.15, 0.10])[0]
        version_risk = round(random.uniform(0.0, 1.0), 2)
        known_vuln = 1 if (cvss > 6.0 and random.random() > 0.3) else 0
        
        cvss = round(cvss, 1)
        
        risk_level = calculate_ground_truth_risk(
            port_state, cvss, exposure, enc, version_risk, known_vuln, service
        )
        
        records.append({
            "port": port,
            "protocol": proto,
            "service": service,
            "port_state": port_state,
            "service_version_risk": version_risk,
            "exposure_level": exposure,
            "known_vuln_indicator": known_vuln,
            "cvss_baseline": cvss,
            "banner_flags": banner,
            "encryption_detected": enc,
            "risk_level": risk_level
        })
        
    df = pd.DataFrame(records)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"[+] Successfully generated dataset with {len(df)} samples at '{output_path}'.")
    print("[+] Class distribution:")
    print(df['risk_level'].value_counts())
    return df

if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    out_file = os.path.join(current_dir, "training_data.csv")
    generate_dataset(3000, out_file)
