"""
SENTRY SIEM - Ingestion Layer
================================
Reads logs in CSV, JSON-lines, or syslog-style text and normalizes every
record into one common schema, regardless of source format. This is the
"Ingestion layer" box in the architecture diagram.

Usage:
    python ingest.py logs/network_flows.csv
    python ingest.py logs/network_flows.json
    python ingest.py logs/firewall_syslog.log
"""

import csv
import json
import re
import sys
import os

# The common schema every log format gets normalized into.
NORMALIZED_FIELDS = [
    "timestamp", "src_ip", "dst_ip", "dst_port", "protocol",
    "service", "flag", "src_bytes", "dst_bytes", "threat_type", "severity",
]

SYSLOG_PATTERN = re.compile(
    r"^(?P<ts>\w+ \d+ \d+:\d+:\d+) \S+ \S+: \[(?P<tag>[\w-]+)\] "
    r"SRC=(?P<src>[\d.]+) DST=(?P<dst>[\d.]+) DPT=(?P<port>\d+) "
    r"PROTO=(?P<proto>\w+) LEN=(?P<len>\d+) SEVERITY=(?P<sev>\w+)"
)

SYSLOG_TAG_TO_CATEGORY = {
    "ALLOW": "Normal",
    "SCAN-DETECTED": "Port Scan",
    "AUTH-FAIL": "Brute Force",
    "FLOOD-DETECTED": "DDoS",
    "ANOMALY-C2": "Botnet C2",
}


def normalize_csv_row(row):
    return {
        "timestamp": row.get("timestamp", ""),
        "src_ip": row.get("src_ip", "192.168.1.100"),
        "dst_ip": row.get("dst_ip", "10.0.0.1"),
        "dst_port": int(row.get("dst_port", 80)),
        "protocol": row.get("protocol", row.get("protocol_type", "tcp")),
        "service": row.get("service", ""),
        "flag": row.get("flag", ""),
        "src_bytes": int(row.get("src_bytes", 0)),
        "dst_bytes": int(row.get("dst_bytes", 0)),
        "threat_type": row.get("threat_type", "Normal"),
        "severity": row.get("severity", "low"),
    }


def normalize_json_line(obj):
    # JSON records already carry the same fields as CSV in this project,
    # so normalization here is mostly pass-through — but a real deployment
    # ingesting third-party JSON logs (e.g. cloud provider flow logs) would
    # remap differently-named fields into NORMALIZED_FIELDS here.
    return {k: obj.get(k) for k in NORMALIZED_FIELDS}


def normalize_syslog_line(line):
    m = SYSLOG_PATTERN.match(line.strip())
    if not m:
        return None
    category = SYSLOG_TAG_TO_CATEGORY.get(m.group("tag"), "Botnet C2")
    return {
        "timestamp": m.group("ts"),
        "src_ip": m.group("src"),
        "dst_ip": m.group("dst"),
        "dst_port": int(m.group("port")),
        "protocol": m.group("proto").lower(),
        "service": None,          # not present in a raw firewall syslog line
        "flag": None,             # not present in a raw firewall syslog line
        "src_bytes": int(m.group("len")),
        "dst_bytes": None,
        "threat_type": category,
        "severity": m.group("sev").lower(),
    }


def ingest(path):
    normalized = []
    if path.endswith(".csv"):
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                normalized.append(normalize_csv_row(row))
    elif path.endswith(".json"):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    normalized.append(normalize_json_line(json.loads(line)))
    elif path.endswith(".log"):
        with open(path, encoding="utf-8") as f:
            for line in f:
                rec = normalize_syslog_line(line)
                if rec:
                    normalized.append(rec)
    else:
        raise ValueError(f"Unrecognized log format for: {path}")
    return normalized


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python ingest.py <path-to-log-file>")
        sys.exit(1)

    log_file = sys.argv[1]
    if not os.path.exists(log_file):
        print(f"Error: file not found: {log_file}")
        sys.exit(1)

    records = ingest(log_file)
    print(f"Ingested {len(records)} records from {log_file}, normalized to common schema:\n")
    for r in records[:5]:
        print(r)
    print(f"\n... and {max(0, len(records) - 5)} more.")

    from collections import Counter
    counts = Counter(r["threat_type"] for r in records)
    print("\nThreat type breakdown:")
    for k, v in counts.most_common():
        print(f"  {k:<12} {v}")
