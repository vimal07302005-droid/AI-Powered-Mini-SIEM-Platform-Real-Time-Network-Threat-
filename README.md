# SENTRY — AI-Powered Mini SIEM Platform

Real-time network threat classification and incident response, built as a
scaled-down but functionally real version of tools like Splunk or QRadar.

This is a working system, not just a mockup: a real ML model trained on
public intrusion-detection data, a FastAPI backend that classifies a
simulated live stream and persists incidents to SQLite, and a dashboard
that displays it all in real time.

## Architecture

```
Network traffic (NSL-KDD replay / live Scapy capture)
        |
Ingestion layer (normalizes to a common feature schema)
        |
ML threat classifier (Random Forest / XGBoost -> 5 categories)
        |
Rules engine (correlates repeated events, escalates severity)
        |
FastAPI backend (SQLite incident store + REST/WebSocket API)
        |
SIEM dashboard (live feed, alert stream, incident triage)
        |
   [analyst triage flows back via PATCH /api/incidents/:id]
```

## Project layout

```
siem_project/
├── data/                   NSL-KDD train/test CSVs (downloaded from GitHub mirror)
├── ml/
│   └── train_model.py      preprocessing + RF/XGBoost training + evaluation
├── models/                 trained pipelines, label encoder, metrics report
├── backend/
│   └── app.py              FastAPI service: inference, rules engine, SQLite, WS/REST
├── frontend/
│   └── siem_dashboard.html standalone dashboard (currently uses simulated data)
├── requirements.txt
└── README.md
```

## Setup

```bash
pip install -r requirements.txt

# 1. Train the model (only needed once; writes to models/)
python ml/train_model.py

# 2. Run the backend (classifies a replayed stream in real time,
#    stores incidents in backend/sentry.db)
cd backend
uvicorn app:app --reload --port 8000

# 3. Open the dashboard
#    frontend/siem_dashboard.html currently runs on generated demo data.
#    Point it at ws://localhost:8000/ws/stream and the REST endpoints
#    below to see it running on the real backend instead.
```

### Backend API

| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | GET | Service + loaded model name |
| `/api/incidents?status=&limit=` | GET | List incidents, optional status filter |
| `/api/incidents/{id}` | PATCH | Update `status` and/or `analyst_notes` |
| `/api/stats` | GET | Totals, breakdown by threat type, top attacker IPs |
| `/ws/stream` | WebSocket | Live feed of every classified flow, in real time |

## Dataset

[NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html) — an improved, de-duplicated
version of the classic KDD Cup 1999 intrusion detection dataset. 125,973
training rows / 22,544 test rows, 41 network-flow features (protocol, service,
flag, byte counts, connection-rate statistics, etc.), 22 raw attack labels.

The 22 raw labels are mapped into 5 SIEM-facing categories:

| Raw NSL-KDD family | Mapped category |
|---|---|
| normal | Normal |
| DoS (neptune, smurf, back, teardrop, pod, land, ...) | DDoS |
| Probe (satan, ipsweep, portsweep, nmap, ...) | Port Scan |
| R2L (guess_passwd, warezclient, ftp_write, ...) | Brute Force |
| U2R (buffer_overflow, rootkit, loadmodule, perl, ...) | Botnet C2 |

## Model results

Trained on the standard NSL-KDD `KDDTrain+` / `KDDTest+` split, which
deliberately includes attack variants in the test set that never appear in
training — this makes it a genuinely hard, realistic benchmark rather than
an inflated one.

| Model | Accuracy | Macro F1 | ROC-AUC (macro, OVR) |
|---|---|---|---|
| Random Forest | 73.9% | 0.479 | 0.934 |
| **XGBoost** | **78.1%** | **0.566** | **0.948** |

XGBoost is the better model on every metric and is what the backend loads
by default. Full precision/recall/F1 per class and the confusion matrices
are in `models/metrics_report.json`.

**Per-class recall (XGBoost):** Normal 0.97, DDoS 0.84, Port Scan 0.67,
Botnet C2 0.15, Brute Force 0.08.

## Limitations (be upfront about these — they're real and expected)

- **Class imbalance.** Brute Force (R2L) and Botnet C2 (U2R) attacks are
  under 1% of the training data combined, so recall on those categories is
  weak. This is a known, well-documented property of NSL-KDD, not a training
  bug — production systems handle this with SMOTE/class-weighting tuned
  further, anomaly-detection fallback models, or more balanced datasets
  (CICIDS2017, UNSW-NB15).
- **Simulated streaming.** The backend replays test-set rows with randomized
  IPs rather than capturing live packets. Swapping in a real Scapy/tshark
  capture means writing a feature extractor that reproduces the same 41
  NSL-KDD-style columns from raw packets — nontrivial, and the natural next
  step for this project.
- **Rules engine is intentionally simple.** One correlation rule (repeated
  scan-like hits from one source IP -> escalate to critical) is included to
  demonstrate ML + rules layering, not a production correlation engine.
- **No geolocation / auth / multi-tenant support.** Out of scope for a
  portfolio-scale build; noted as a natural extension.

## Suggested extensions

- Swap NSL-KDD for CICIDS2017 or UNSW-NB15 for more balanced, modern traffic
- Real packet capture -> feature extraction (Scapy/CICFlowMeter) for a true live demo
- Add a second model (e.g. autoencoder-based anomaly detector) as an ensemble
  member for the rare classes
- Containerize with Docker Compose (backend + a Postgres swap-in for SQLite)
