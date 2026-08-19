"""
SENTRY SIEM - Backend API
==========================
FastAPI service that:
  1. Loads the trained NSL-KDD threat classifier (from ../models/)
  2. Replays test-set flows as a simulated real-time stream (swap for live
     Scapy/tshark capture in production) and classifies each one
  3. Applies a lightweight rules engine on top of ML output for correlation
     (e.g. repeated Port Scan hits from the same source -> escalate severity)
  4. Persists incidents to SQLite and exposes REST + WebSocket endpoints
     for the dashboard to consume

Run:
    uvicorn app:app --reload --port 8000
"""

import asyncio
import io
import json
import os
import random
import sqlite3
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import joblib
import pandas as pd
from fastapi import FastAPI, File, Response, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

BASE_DIR = os.path.dirname(__file__)
MODEL_DIR = os.path.join(BASE_DIR, "..", "models")
DATA_DIR = os.path.join(BASE_DIR, "..", "data")
DB_PATH = os.path.join(BASE_DIR, "sentry.db")
FRONTEND_HTML = os.path.join(BASE_DIR, "..", "frontend", "siem_dashboard.html")


SEVERITY_BY_CATEGORY = {
    "Normal": "low",
    "Port Scan": "medium",
    "Brute Force": "high",
    "DDoS": "high",
    "Botnet C2": "critical",
}

# ---------------------------------------------------------------- storage --
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            dst_port INTEGER NOT NULL,
            threat_type TEXT NOT NULL,
            confidence REAL NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            analyst_notes TEXT DEFAULT '',
            correlated INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS system_stats (
            key TEXT PRIMARY KEY,
            value INTEGER NOT NULL
        )
    """)
    conn.execute("INSERT OR IGNORE INTO system_stats (key, value) VALUES ('total_flows_classified', 0)")
    conn.commit()
    conn.close()


# ---------------------------------------------------------------- model ----
class ThreatClassifier:
    def __init__(self):
        self.pipeline = None
        self.label_encoder = None
        self.feature_columns = None
        self.model_name = "none"
        self._load()

    def _load(self):
        xgb_path = os.path.join(MODEL_DIR, "xgb_model.joblib")
        rf_path = os.path.join(MODEL_DIR, "rf_model.joblib")
        if os.path.exists(xgb_path):
            self.pipeline = joblib.load(xgb_path)
            self.model_name = "XGBoost-v1"
        elif os.path.exists(rf_path):
            self.pipeline = joblib.load(rf_path)
            self.model_name = "RandomForest-v1"
        else:
            raise FileNotFoundError(
                "No trained model found. Run `python ml/train_model.py` first."
            )
        self.label_encoder = joblib.load(os.path.join(MODEL_DIR, "label_encoder.joblib"))
        with open(os.path.join(MODEL_DIR, "feature_columns.json")) as f:
            self.feature_columns = json.load(f)

    def predict(self, row: dict):
        """row: dict of the 41 NSL-KDD feature columns -> (category, confidence)"""
        df = pd.DataFrame([row])[self.feature_columns]
        proba = self.pipeline.predict_proba(df)[0]
        idx = proba.argmax()
        category = self.label_encoder.inverse_transform([idx])[0]
        confidence = float(proba[idx])
        return category, confidence

    def predict_batch(self, df: pd.DataFrame):
        """df: DataFrame containing the feature columns -> (categories_list, confidences_list)"""
        # If columns missing, attempt to map or select feature columns
        df_feat = df[self.feature_columns]
        probas = self.pipeline.predict_proba(df_feat)
        indices = probas.argmax(axis=1)
        categories = self.label_encoder.inverse_transform(indices)
        confidences = probas.max(axis=1)
        return categories, [float(c) for c in confidences]


classifier: ThreatClassifier | None = None


# ------------------------------------------------------- simulated stream --
def load_replay_pool():
    """Loads test-set rows balanced with ~85% normal traffic and ~15% threat attacks
    for realistic enterprise network flow monitoring."""
    path = os.path.join(DATA_DIR, "KDDTest.csv")
    cols = classifier.feature_columns + ["label", "difficulty"]
    df = pd.read_csv(path, names=cols)

    df_normal = df[df["label"].astype(str).str.startswith("normal")]
    df_attack = df[~df["label"].astype(str).str.startswith("normal")]

    n_norm = min(850, len(df_normal))
    n_att = min(150, len(df_attack))

    df_balanced = pd.concat([
        df_normal.sample(n=n_norm, random_state=42),
        df_attack.sample(n=n_att, random_state=42)
    ]).sample(frac=1, random_state=None)
    return df_balanced.to_dict("records")


STREAM_ENABLED = True

REALISTIC_IP_POOLS = {
    "Normal": ["192.168.1.105", "192.168.1.142", "10.0.4.15", "172.16.0.22"],
    "DDoS": ["198.51.100.44", "203.0.113.88", "45.33.32.19", "185.220.101.5"],
    "Port Scan": ["185.220.101.45", "193.27.228.12", "93.184.216.34"],
    "Brute Force": ["192.0.2.77", "198.51.100.91", "203.0.113.140"],
    "Botnet C2": ["45.33.32.100", "185.220.101.99"],
}

DESTINATION_IP_POOL = [
    "10.0.0.1",
    "10.0.0.5",
    "10.0.1.12",
    "10.0.2.44",
    "10.0.3.15",
    "10.0.5.60",
]


def get_traffic_ip(category: str) -> tuple[str, str]:
    pool = REALISTIC_IP_POOLS.get(category, ["192.168.1.100"])
    src_ip = random.choice(pool)
    dst_ip = random.choice(DESTINATION_IP_POOL)
    return src_ip, dst_ip


# rolling window per source IP for simple correlation rules
recent_events = defaultdict(lambda: deque(maxlen=20))


def apply_rules_engine(category: str, severity: str, src_ip: str) -> tuple[str, bool]:
    """Very small correlation layer on top of the ML output.
    Example rule: 3+ Port Scan / Brute Force hits from the same source IP
    within the rolling window => escalate to 'critical' and flag as correlated
    (simulating: 'repeated failed logins + port scan = brute-force campaign')."""
    now = time.time()
    recent_events[src_ip].append((now, category))
    window = [c for ts, c in recent_events[src_ip] if now - ts < 60]

    scan_like = sum(1 for c in window if c in ("Port Scan", "Brute Force"))
    if scan_like >= 3 and category != "Normal":
        return "critical", True
    return severity, False


ACTION_SUGGESTIONS = {
    "low": "Monitor",
    "medium": "Flag for review",
    "high": "Block source IP",
    "critical": "Block IP + isolate host + notify on-call",
}


# -------------------------------------------------------------- WS clients --
class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, message: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


MITRE_ATTACK_MAP = {
    "DDoS": "T1498 (Network Denial of Service)",
    "Port Scan": "T1595.002 (Reconnaissance: Vulnerability Scanning)",
    "Brute Force": "T1110 (Credential Access: Brute Force)",
    "Botnet C2": "T1071 (Application Layer Command & Control)",
    "Normal": "N/A (Benign Operation)",
}


USE_LIVE_CAPTURE = os.getenv("USE_LIVE_CAPTURE", "false").lower() in ("true", "1", "yes")

live_tracker = None
live_thread = None


async def stream_loop():
    """Background task: processes live captured packets (if USE_LIVE_CAPTURE=true)
    or pulls rows from the replay pool (~0.8-1.5s), classifies each flow, runs rules
    engine, stores incidents for threats, and broadcasts events to dashboard."""
    pool = load_replay_pool()
    i = 0
    while True:
        if not STREAM_ENABLED:
            await asyncio.sleep(1)
            continue

        live_flow = None
        if USE_LIVE_CAPTURE and live_tracker:
            try:
                live_flow = live_tracker.completed_queue.get_nowait()
            except Exception:
                live_flow = None

        if live_flow:
            features = {k: live_flow.get(k, 0) for k in classifier.feature_columns}
            category, confidence = classifier.predict(features)
            src_ip = live_flow.get("src_ip", "127.0.0.1")
            dst_ip = live_flow.get("dst_ip", "10.0.0.1")
            dst_port = live_flow.get("dst_port", 80)
            protocol = live_flow.get("protocol_type", "tcp")
        else:
            row = pool[i % len(pool)]
            i += 1
            features = {k: row[k] for k in classifier.feature_columns}
            category, confidence = classifier.predict(features)
            src_ip, dst_ip = get_traffic_ip(category)
            dst_port = 80 if category == "DDoS" else (22 if category == "Brute Force" else random.choice([80, 443, 22, 21, 8080]))
            protocol = row.get("protocol_type", "tcp")

        base_severity = SEVERITY_BY_CATEGORY.get(category, "medium")
        severity, correlated = apply_rules_engine(category, base_severity, src_ip)
        ts = datetime.now(timezone.utc).isoformat()

        risk_score = 10 if category == "Normal" else (45 if category == "Port Scan" else (65 if category == "Brute Force" else (85 if category == "DDoS" else 95)))
        if correlated:
            risk_score = 100

        event = {
            "type": "flow",
            "timestamp": ts,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "threat_type": category,
            "confidence": round(confidence, 4),
            "severity": severity,
            "risk_score": risk_score,
            "mitre_attack": MITRE_ATTACK_MAP.get(category, "T1498"),
            "correlated": correlated,
            "suggested_action": ACTION_SUGGESTIONS[severity],
        }

        conn = get_conn()
        conn.execute("UPDATE system_stats SET value = value + 1 WHERE key='total_flows_classified'")
        if category != "Normal":
            cur = conn.execute(
                """INSERT INTO incidents
                   (timestamp, src_ip, dst_ip, dst_port, threat_type, confidence, severity, status, correlated)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (ts, src_ip, dst_ip, dst_port, category, confidence, severity, "open", int(correlated)),
            )
            event["incident_id"] = cur.lastrowid
        conn.commit()
        conn.close()

        await manager.broadcast(event)
        await asyncio.sleep(random.uniform(0.5, 1.4) if not live_flow else 0.05)


# ------------------------------------------------------------------ app ----
@asynccontextmanager
async def lifespan(app: FastAPI):
    global classifier, live_tracker, live_thread
    init_db()
    classifier = ThreatClassifier()

    if USE_LIVE_CAPTURE:
        try:
            from live_capture import LiveFlowTracker, LiveCaptureSnifferThread
            live_tracker = LiveFlowTracker()
            live_thread = LiveCaptureSnifferThread(live_tracker)
            live_thread.start()
            print("[LIVE CAPTURE] Scapy sniffer thread started on active interface.")
        except Exception as e:
            print(f"[LIVE CAPTURE WARNING] Failed to start Scapy sniffer: {e}")
            print("[LIVE CAPTURE WARNING] Falling back to simulated replay pool.")

    task = asyncio.create_task(stream_loop())
    yield
    if live_thread:
        live_thread.stop()
    task.cancel()


app = FastAPI(
    title="AI-Powered Mini SIEM Platform: Real-Time Network Threat Classification and Incident Response System",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)


class IncidentUpdate(BaseModel):
    status: str | None = None
    analyst_notes: str | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/auth/login")
def login(req: LoginRequest):
    if req.username and req.password:
        return {
            "status": "success",
            "token": "sentry-session-sec-token-2026",
            "user": {
                "username": req.username,
                "name": "SOC Analyst Admin",
                "role": "Tier-3 Security Analyst",
            },
        }
    return {"status": "error", "message": "Invalid credentials"}


@app.get("/")
@app.get("/dashboard")
def get_dashboard():
    return FileResponse(FRONTEND_HTML)


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "model": classifier.model_name if classifier else "loading",
    }


@app.get("/api/incidents")
def list_incidents(status: str | None = None, limit: int = 100):
    conn = get_conn()
    if status and status != "all":
        rows = conn.execute(
            "SELECT * FROM incidents WHERE status=? ORDER BY id DESC LIMIT ?", (status, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.patch("/api/incidents/{incident_id}")
def update_incident(incident_id: int, update: IncidentUpdate):
    conn = get_conn()
    if update.status:
        conn.execute("UPDATE incidents SET status=? WHERE id=?", (update.status, incident_id))
    if update.analyst_notes is not None:
        conn.execute(
            "UPDATE incidents SET analyst_notes=? WHERE id=?", (update.analyst_notes, incident_id)
        )
    conn.commit()
    row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    conn.close()
    return dict(row) if row else {"error": "not found"}


@app.delete("/api/incidents")
def clear_incidents():
    conn = get_conn()
    conn.execute("DELETE FROM incidents")
    conn.execute("DELETE FROM sqlite_sequence WHERE name='incidents'")
    conn.execute("UPDATE system_stats SET value = 0 WHERE key='total_flows_classified'")
    conn.commit()
    conn.close()
    return {"status": "success", "message": "All incident records cleared and sequence reset to #1."}


@app.get("/api/stats")
def stats():
    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) c FROM incidents").fetchone()["c"]
    open_ = conn.execute("SELECT COUNT(*) c FROM incidents WHERE status='open'").fetchone()["c"]
    total_flows_row = conn.execute("SELECT value FROM system_stats WHERE key='total_flows_classified'").fetchone()
    total_flows = total_flows_row["value"] if total_flows_row else 0
    # Ensure total_flows is always >= total incidents
    if total_flows < total:
        total_flows = total

    by_type = conn.execute(
        "SELECT threat_type, COUNT(*) c FROM incidents GROUP BY threat_type"
    ).fetchall()
    top_ips = conn.execute(
        "SELECT src_ip, COUNT(*) c FROM incidents GROUP BY src_ip ORDER BY c DESC LIMIT 5"
    ).fetchall()
    conn.close()
    return {
        "total_incidents": total,
        "open_incidents": open_,
        "total_flows_classified": total_flows,
        "by_type": {r["threat_type"]: r["c"] for r in by_type},
        "top_attacker_ips": [{"ip": r["src_ip"], "count": r["c"]} for r in top_ips],
    }


@app.get("/api/metrics")
def metrics():
    metrics_file = os.path.join(MODEL_DIR, "metrics_report.json")
    if os.path.exists(metrics_file):
        with open(metrics_file) as f:
            return json.load(f)
    return {"error": "metrics report not found"}


@app.get("/api/report-data")
def report_data():
    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) c FROM incidents").fetchone()["c"]
    open_ = conn.execute("SELECT COUNT(*) c FROM incidents WHERE status='open'").fetchone()["c"]
    investigating_ = conn.execute("SELECT COUNT(*) c FROM incidents WHERE status='investigating'").fetchone()["c"]
    resolved_ = conn.execute("SELECT COUNT(*) c FROM incidents WHERE status='resolved'").fetchone()["c"]

    by_type_rows = conn.execute("SELECT threat_type, COUNT(*) c FROM incidents GROUP BY threat_type").fetchall()
    by_sev_rows = conn.execute("SELECT severity, COUNT(*) c FROM incidents GROUP BY severity").fetchall()
    top_ips_rows = conn.execute("SELECT src_ip, COUNT(*) c FROM incidents GROUP BY src_ip ORDER BY c DESC LIMIT 10").fetchall()
    recent_incidents = conn.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_incidents": total,
            "open_incidents": open_,
            "investigating_incidents": investigating_,
            "resolved_incidents": resolved_,
        },
        "by_type": {r["threat_type"]: r["c"] for r in by_type_rows},
        "by_severity": {r["severity"]: r["c"] for r in by_sev_rows},
        "top_attacker_ips": [{"ip": r["src_ip"], "count": r["c"]} for r in top_ips_rows],
        "recent_incidents": [dict(r) for r in recent_incidents],
        "model": classifier.model_name if classifier else "XGBoost-v1"
    }


@app.post("/api/upload-csv")
async def upload_csv(file: UploadFile = File(...)):
    contents = await file.read()
    try:
        # Check if CSV has header or raw columns
        df = pd.read_csv(io.BytesIO(contents))
        if not set(classifier.feature_columns).issubset(set(df.columns)):
            # Fallback for headerless NSL-KDD style CSVs
            cols = classifier.feature_columns + ["label", "difficulty"]
            df = pd.read_csv(io.BytesIO(contents), names=cols[:df.shape[1]])
    except Exception as e:
        return {"error": f"Failed to parse CSV file: {str(e)}"}

    if df.empty:
        return {"error": "Uploaded CSV file is empty"}

    try:
        categories, confidences = classifier.predict_batch(df)
    except Exception as e:
        return {"error": f"Batch inference failed: {str(e)}"}

    results = []
    by_type = defaultdict(int)
    conn = get_conn()
    now_ts = datetime.now(timezone.utc).isoformat()

    for idx, (cat, conf) in enumerate(zip(categories, confidences)):
        by_type[cat] += 1
        base_sev = SEVERITY_BY_CATEGORY.get(cat, "medium")
        src_ip = str(df.iloc[idx]["src_ip"]) if "src_ip" in df.columns else get_traffic_ip(cat)[0]
        dst_ip = str(df.iloc[idx]["dst_ip"]) if "dst_ip" in df.columns else random.choice(DESTINATION_IP_POOL)
        dst_port = int(df.iloc[idx]["dst_port"]) if "dst_port" in df.columns else random.randint(20, 9999)

        item = {
            "row": idx + 1,
            "threat_type": cat,
            "confidence": round(conf, 4),
            "severity": base_sev,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "suggested_action": ACTION_SUGGESTIONS.get(base_sev, "Monitor"),
        }
        results.append(item)

        # Log threat to SQLite DB
        if cat != "Normal":
            conn.execute(
                """INSERT INTO incidents
                   (timestamp, src_ip, dst_ip, dst_port, threat_type, confidence, severity, status, correlated)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (now_ts, src_ip, dst_ip, dst_port, cat, conf, base_sev, "open", 0),
            )

    conn.execute("UPDATE system_stats SET value = value + ? WHERE key='total_flows_classified'", (len(results),))
    conn.commit()
    conn.close()

    total = len(results)
    malicious = total - by_type.get("Normal", 0)

    return {
        "status": "success",
        "filename": file.filename,
        "total_rows": total,
        "malicious_rows": malicious,
        "by_type": dict(by_type),
        "results": results[:200],  # Return up to 200 preview rows
    }


@app.get("/api/export-incidents-csv")
def export_incidents_csv():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM incidents ORDER BY id DESC").fetchall()
    conn.close()

    df = pd.DataFrame([dict(r) for r in rows])
    if df.empty:
        csv_data = "id,timestamp,src_ip,dst_ip,dst_port,threat_type,confidence,severity,status,analyst_notes,correlated\n"
    else:
        csv_data = df.to_csv(index=False)

    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentry_incidents_export.csv"},
    )


@app.get("/api/sample-csv")
def sample_csv():
    path = os.path.join(DATA_DIR, "KDDTest.csv")
    cols = classifier.feature_columns + ["label", "difficulty"]
    df = pd.read_csv(path, names=cols).head(100)
    csv_data = df.to_csv(index=False)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentry_sample_network_flows.csv"},
    )


@app.websocket("/ws/stream")
async def websocket_stream(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()  # keepalive / ignore client pings
    except WebSocketDisconnect:
        manager.disconnect(ws)
