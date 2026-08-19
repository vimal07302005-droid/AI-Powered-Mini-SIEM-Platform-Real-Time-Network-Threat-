"""
scripts/generate_multi_format_logs.py: Generates realistic 300 multi-format sample logs
(CSV, JSON-lines, and Syslog format) into logs/ directory.
"""

import os
import json
import datetime
import random
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

os.makedirs(LOGS_DIR, exist_ok=True)

test_path = os.path.join(DATA_DIR, "KDDTest.csv")
feature_cols_path = os.path.join(BASE_DIR, "models", "feature_columns.json")

with open(feature_cols_path) as f:
    feature_cols = json.load(f)

cols = feature_cols + ["label", "difficulty"]
df = pd.read_csv(test_path, names=cols).fillna(0)

# Map NSL-KDD labels to threat categories
ATTACK_MAP = {
    "normal": "Normal", "neptune": "DDoS", "smurf": "DDoS", "back": "DDoS",
    "teardrop": "DDoS", "ipsweep": "Port Scan", "nmap": "Port Scan",
    "portsweep": "Port Scan", "satan": "Port Scan", "guess_passwd": "Brute Force",
    "buffer_overflow": "Botnet C2"
}

df["threat_type"] = df["label"].map(lambda x: ATTACK_MAP.get(str(x).strip("."), "Normal"))

# Balance sample to ~300 records
df_norm = df[df["threat_type"] == "Normal"].sample(n=134, random_state=42)
df_ddos = df[df["threat_type"] == "DDoS"].sample(n=97, random_state=42)
df_scan = df[df["threat_type"] == "Port Scan"].sample(n=39, random_state=42)
df_brute = df[df["threat_type"] == "Brute Force"].sample(n=28, random_state=42)
df_bot = df[df["threat_type"] == "Botnet C2"].sample(n=2, random_state=42)

df_sample = pd.concat([df_norm, df_ddos, df_scan, df_brute, df_bot]).sample(frac=1, random_state=123).reset_index(drop=True)

IP_POOLS = {
    "Normal": ["192.168.1.105", "192.168.1.142", "10.0.4.15", "172.16.0.22"],
    "DDoS": ["198.51.100.44", "203.0.113.88", "45.33.32.19", "185.220.101.5"],
    "Port Scan": ["185.220.101.45", "193.27.228.12", "93.184.216.34"],
    "Brute Force": ["192.0.2.77", "198.51.100.91", "203.0.113.140"],
    "Botnet C2": ["45.33.32.100", "185.220.101.99"],
}

SYSLOG_TAGS = {
    "Normal": "ALLOW",
    "Port Scan": "SCAN-DETECTED",
    "Brute Force": "AUTH-FAIL",
    "DDoS": "FLOOD-DETECTED",
    "Botnet C2": "ANOMALY-C2"
}

SEVERITY_MAP = {
    "Normal": "low",
    "Port Scan": "medium",
    "Brute Force": "high",
    "DDoS": "high",
    "Botnet C2": "critical"
}

now = datetime.datetime.now(datetime.timezone.utc)
records = []
syslog_lines = []

for idx, row in df_sample.iterrows():
    cat = row["threat_type"]
    src_ip = random.choice(IP_POOLS.get(cat, ["192.168.1.100"]))
    dst_ip = f"10.0.3.{random.randint(10, 250)}"
    dst_port = 80 if cat == "DDoS" else (22 if cat == "Brute Force" else random.choice([80, 443, 22, 21, 508]))
    ts_dt = now - datetime.timedelta(seconds=(300 - idx) * 3)
    ts_iso = ts_dt.isoformat()
    ts_syslog = ts_dt.strftime("%b %d %H:%M:%S")
    proto = str(row.get("protocol_type", "tcp")).upper()
    bytes_count = int(row.get("src_bytes", random.randint(40, 1500)))
    sev = SEVERITY_MAP.get(cat, "medium")

    rec = {
        "timestamp": ts_iso,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": proto.lower(),
        "service": str(row.get("service", "http")),
        "flag": str(row.get("flag", "SF")),
        "src_bytes": bytes_count,
        "dst_bytes": int(row.get("dst_bytes", 0)),
        "threat_type": cat,
        "severity": sev
    }
    records.append(rec)

    # Build syslog line
    tag = SYSLOG_TAGS.get(cat, "ALLOW")
    syslog_str = f"{ts_syslog} fw01 kernel: [{tag}] SRC={src_ip} DST={dst_ip} DPT={dst_port} PROTO={proto} LEN={bytes_count} SEVERITY={sev.upper()}"
    syslog_lines.append(syslog_str)

# 1. Write network_flows.csv
csv_path = os.path.join(LOGS_DIR, "network_flows.csv")
pd.DataFrame(records).to_csv(csv_path, index=False)

# 2. Write network_flows.json (JSON-lines format)
json_path = os.path.join(LOGS_DIR, "network_flows.json")
with open(json_path, "w", encoding="utf-8") as f:
    for rec in records:
        f.write(json.dumps(rec) + "\n")

# 3. Write firewall_syslog.log
log_path = os.path.join(LOGS_DIR, "firewall_syslog.log")
with open(log_path, "w", encoding="utf-8") as f:
    for s_line in syslog_lines:
        f.write(s_line + "\n")

print(f"[OK] Generated 300 realistic multi-format logs in {LOGS_DIR}:")
print(f"   - {csv_path}")
print(f"   - {json_path}")
print(f"   - {log_path}")
