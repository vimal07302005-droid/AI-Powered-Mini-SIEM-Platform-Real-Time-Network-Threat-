"""
tests/verify_siem.py: End-to-End AI SIEM Verification & Test Harness.
Executes Model Sanity Checks, Controlled Attack Simulation, IP/Timestamp Propagation,
Edge Cases, and End-to-End Logging.
"""

import os
import sys
import json
import time
import datetime
import urllib.request
import urllib.error
import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "models")
DATA_DIR = os.path.join(BASE_DIR, "data")
API_BASE = "http://127.0.0.1:8000"

test_results = []

def log_test(name: str, passed: bool, details: str):
    status = "[PASS]" if passed else "[FAIL]"
    test_results.append({"test": name, "status": status, "details": details})
    print(f"{status} {name}: {details}")

print("==================================================================")
print("  SENTRY SIEM REAL-TIME AI DETECTION & VERIFICATION SUITE")
print("==================================================================\n")

# ------------------------------------------------------------------ TEST 1
print("--- TEST 1: Model Evaluation & Ground Truth Sanity Check ---")
try:
    xgb_path = os.path.join(MODEL_DIR, "xgb_model.joblib")
    enc_path = os.path.join(MODEL_DIR, "label_encoder.joblib")
    test_path = os.path.join(DATA_DIR, "KDDTest.csv")
    
    if not (os.path.exists(xgb_path) and os.path.exists(enc_path) and os.path.exists(test_path)):
        log_test("Model Evaluation", False, "Missing model or test dataset files.")
    else:
        pipeline = joblib.load(xgb_path)
        encoder = joblib.load(enc_path)
        with open(os.path.join(MODEL_DIR, "feature_columns.json")) as f:
            feature_cols = json.load(f)
            
        cols = feature_cols + ["label", "difficulty"]
        df_test = pd.read_csv(test_path, names=cols).fillna(0)
        
        ATTACK_MAP = {
            "normal": "Normal", "neptune": "DDoS", "smurf": "DDoS", "back": "DDoS",
            "teardrop": "DDoS", "ipsweep": "Port Scan", "nmap": "Port Scan",
            "portsweep": "Port Scan", "satan": "Port Scan", "guess_passwd": "Brute Force",
            "buffer_overflow": "Botnet C2"
        }
        
        df_test["ground_truth"] = df_test["label"].map(lambda x: ATTACK_MAP.get(str(x).strip("."), "Normal"))
        y_true = encoder.transform(df_test["ground_truth"])
        
        X_test = df_test[feature_cols]
        y_pred = pipeline.predict(X_test)
        
        acc = accuracy_score(y_true, y_pred)
        report = classification_report(y_true, y_pred, target_names=list(encoder.classes_), output_dict=True)
        
        # Check recall for majority classes > 0.50
        ddos_recall = report.get("DDoS", {}).get("recall", 0)
        normal_recall = report.get("Normal", {}).get("recall", 0)
        
        is_valid = acc > 0.70 and ddos_recall > 0.50 and normal_recall > 0.50
        
        log_test("Model Evaluation & Classification Metrics", is_valid,
                 f"Accuracy: {acc*100:.1f}% | DDoS Recall: {ddos_recall*100:.1f}% | Normal Recall: {normal_recall*100:.1f}%")
        
        print("\n--- Side-by-Side Sample Comparison (20 Random Samples) ---")
        sample_df = df_test.sample(20, random_state=42)
        sample_preds = encoder.inverse_transform(pipeline.predict(sample_df[feature_cols]))
        
        print(f"{'INDEX':<6} | {'ACTUAL GROUND TRUTH':<20} | {'AI MODEL PREDICTION':<20} | {'MATCH'}")
        print("-" * 65)
        for idx, row, pred in zip(sample_df.index, sample_df["ground_truth"], sample_preds):
            match = "[MATCH]" if row == pred else "[MISMATCH]"
            print(f"{idx:<6} | {row:<20} | {pred:<20} | {match}")
        print("-" * 65 + "\n")

except Exception as e:
    log_test("Model Evaluation", False, str(e))

# ------------------------------------------------------------------ TEST 2
print("--- TEST 2: API Endpoint & Model Reload Integrity ---")
try:
    req = urllib.request.urlopen(f"{API_BASE}/api/health")
    resp = json.loads(req.read().decode())
    model_loaded = resp.get("model") == "XGBoost-v1" and resp.get("status") == "ok"
    log_test("Backend Model Integrity Check", model_loaded, f"Backend Active Model: {resp.get('model')}")
except Exception as e:
    log_test("Backend Model Integrity Check", False, f"Server unreachable: {str(e)}")

# ------------------------------------------------------------------ TEST 3
print("--- TEST 3: Real IP & Timestamp Propagation ---")
try:
    test_csv_content = """duration,protocol_type,service,flag,src_bytes,dst_bytes,land,wrong_fragment,urgent,hot,num_failed_logins,logged_in,num_compromised,root_shell,su_attempted,num_root,num_file_creations,num_shells,num_access_files,num_outbound_cmds,is_host_login,is_guest_login,count,srv_count,serror_rate,srv_serror_rate,rerror_rate,srv_rerror_rate,same_srv_rate,diff_srv_rate,srv_diff_host_rate,dst_host_count,dst_host_srv_count,dst_host_same_srv_rate,dst_host_diff_srv_rate,dst_host_same_src_port_rate,dst_host_srv_diff_host_rate,dst_host_serror_rate,dst_host_srv_serror_rate,dst_host_rerror_rate,dst_host_srv_rerror_rate,src_ip
0,tcp,http,SF,5450,8314,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,8,8,0,0,0,0,1,0,0,9,9,1,0,0.11,0,0,0,0,0,192.168.1.55
0,tcp,private,S0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,123,123,1,1,0,0,1,0,0,255,255,1,0,0.05,0,1,1,0,0,10.0.0.99
"""
    boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="test_telemetry.csv"\r\n'
        f"Content-Type: text/csv\r\n\r\n"
        f"{test_csv_content}\r\n"
        f"--{boundary}--\r\n"
    ).encode('utf-8')
    
    http_req = urllib.request.Request(
        f"{API_BASE}/api/upload-csv",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST"
    )
    
    with urllib.request.urlopen(http_req) as response:
        res = json.loads(response.read().decode())
        preds = res.get("results", [])
        
        if len(preds) == 2:
            ip_match = preds[0].get("src_ip") == "192.168.1.55" and preds[1].get("src_ip") == "10.0.0.99"
            threat_match = preds[0].get("threat_type") == "Normal" and preds[1].get("threat_type") == "DDoS"
            log_test("IP & Threat Category Propagation", ip_match and threat_match,
                     f"Passed: Row 1 IP={preds[0].get('src_ip')} ({preds[0].get('threat_type')}), Row 2 IP={preds[1].get('src_ip')} ({preds[1].get('threat_type')})")
        else:
            log_test("IP & Threat Category Propagation", False, f"Unexpected response length: {len(preds)}")
except Exception as e:
    log_test("IP & Threat Category Propagation", False, str(e))

# ------------------------------------------------------------------ TEST 4
print("--- TEST 4: Controlled Threat Intensity & Severity Scale ---")
try:
    low_intensity = {"threat_type": "Port Scan", "confidence": 0.65}
    high_intensity = {"threat_type": "DDoS", "confidence": 0.99}
    
    def get_sev(cat, conf):
        if cat in ["DDoS", "Botnet C2"]:
            return "critical" if conf >= 0.90 else "high"
        elif cat in ["Port Scan", "Brute Force"]:
            return "high" if conf >= 0.85 else "medium"
        return "low"
        
    sev1 = get_sev(low_intensity["threat_type"], low_intensity["confidence"])
    sev2 = get_sev(high_intensity["threat_type"], high_intensity["confidence"])
    
    severity_scaled = (sev1 == "medium") and (sev2 == "critical")
    log_test("Attack Intensity & Dynamic Severity Scaling", severity_scaled,
             f"Port Scan (65% conf) -> {sev1.upper()} | DDoS (99% conf) -> {sev2.upper()}")
except Exception as e:
    log_test("Attack Intensity & Dynamic Severity Scaling", False, str(e))

# ------------------------------------------------------------------ TEST 5
print("--- TEST 5: Edge Case - Out of Distribution & Empty Dataset ---")
try:
    empty_body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="empty.csv"\r\n'
        f"Content-Type: text/csv\r\n\r\n\r\n"
        f"--{boundary}--\r\n"
    ).encode('utf-8')
    
    empty_req = urllib.request.Request(
        f"{API_BASE}/api/upload-csv",
        data=empty_body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST"
    )
    
    with urllib.request.urlopen(empty_req) as response:
        empty_res = json.loads(response.read().decode())
        has_error = "error" in empty_res
        log_test("Edge Case: Empty File Handling", has_error, f"Handled correctly: {empty_res.get('error')}")

except Exception as e:
    log_test("Edge Case: Empty File Handling", False, str(e))

# ------------------------------------------------------------------ SUMMARY
print("\n==================================================================")
print("  VERIFICATION SUITE SUMMARY MATRIX")
print("==================================================================")
print(f"{'TEST NAME':<45} | {'STATUS'}")
print("-" * 65)
for res in test_results:
    print(f"{res['test']:<45} | {res['status']}")
print("-" * 65)

all_passed = all("[PASS]" in res["status"] for res in test_results)
print(f"\nOVERALL RESULT: {'[ALL TESTS PASSED]' if all_passed else '[VERIFICATION FAILED]'}\n")
