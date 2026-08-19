# SENTRY SIEM - Multi-Format Log Ingestion Layer

This directory contains 300 realistic, multi-format sample security logs and an automated normalization parser (`ingest.py`) that fulfills the Ingestion Layer of the SIEM architecture.

## 📂 Sample Log Files (`logs/`)

1. **`logs/network_flows.csv`**: Full network flow feature vectors (duration, packet counts, byte counts, TCP flags, realistic IPs, and timestamps). Direct feed for ML classifier.
2. **`logs/network_flows.json`**: JSON-lines format matching standard enterprise log shippers (Filebeat, Logstash, Fluentd).
3. **`logs/firewall_syslog.log`**: Raw kernel/firewall syslog format:
   ```syslog
   Aug 08 05:19:55 fw01 kernel: [FLOOD-DETECTED] SRC=198.51.100.44 DST=10.0.3.183 DPT=80 PROTO=TCP LEN=0 SEVERITY=HIGH
   ```

## 🛠️ Ingestion Layer Parser (`ingest.py`)

The ingestion script (`ingest.py`) parses any of the 3 formats and normalizes every record into the common SIEM schema:

```python
{
    'timestamp': '2026-08-08T05:19:55.876481+00:00',
    'src_ip': '198.51.100.44',
    'dst_ip': '10.0.3.183',
    'dst_port': 80,
    'protocol': 'tcp',
    'service': 'private',
    'flag': 'REJ',
    'src_bytes': 0,
    'dst_bytes': 0,
    'threat_type': 'DDoS',
    'severity': 'high'
}
```

### 🚀 Usage Commands:

```bash
# Test CSV ingestion
python ingest.py logs/network_flows.csv

# Test JSON-lines ingestion
python ingest.py logs/network_flows.json

# Test Firewall Syslog ingestion
python ingest.py logs/firewall_syslog.log
```

## 📊 Sample Dataset Breakdown
Total Ingested Events: **300**
- **Normal Traffic**: `134`
- **DDoS Attacks**: `97`
- **Port Scans**: `39`
- **Brute Force**: `28`
- **Botnet C2**: `2`

> **Note on Syslog Normalization**: Raw firewall syslog lines omit statistical ML features (`service` and `flag` are `None`) because real hardware firewalls log connection metadata, whereas full flow logs export detailed TCP flags. The ingestion layer normalizes both cleanly into the common SIEM schema.
