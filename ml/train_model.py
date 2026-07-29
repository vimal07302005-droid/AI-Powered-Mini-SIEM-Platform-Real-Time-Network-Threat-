"""
SENTRY SIEM - Threat Classification Model Training
====================================================
Trains and compares a Random Forest and an XGBoost classifier on the
NSL-KDD network intrusion dataset, mapping the 22 raw attack labels
into 5 SIEM-facing categories: Normal, Port Scan, DDoS, Brute Force, Botnet C2.

Usage:
    python train_model.py

Outputs (written to ../models/):
    - rf_model.joblib          trained Random Forest pipeline (encoder + scaler + model)
    - xgb_model.joblib         trained XGBoost pipeline
    - label_encoder.joblib     encodes/decodes the 5 threat categories
    - metrics_report.json      precision/recall/F1/ROC-AUC/confusion matrix for both models
    - feature_columns.json     ordered list of feature names the model expects
"""

import json
import os
import time
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score, f1_score
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
import joblib

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
os.makedirs(MODEL_DIR, exist_ok=True)

# NSL-KDD has no header row; these are the 41 feature names + label + difficulty
COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label"
]

# Map the 22 raw NSL-KDD attack labels into the 5 SIEM-facing categories
# used by the dashboard.
CATEGORY_MAP = {
    "normal": "Normal",
    # DoS family -> DDoS
    "neptune": "DDoS", "smurf": "DDoS", "back": "DDoS", "teardrop": "DDoS",
    "pod": "DDoS", "land": "DDoS", "apache2": "DDoS", "udpstorm": "DDoS",
    "processtable": "DDoS", "mailbomb": "DDoS",
    # Probe family -> Port Scan
    "satan": "Port Scan", "ipsweep": "Port Scan", "portsweep": "Port Scan",
    "nmap": "Port Scan", "mscan": "Port Scan", "saint": "Port Scan",
    # R2L family (remote-to-local credential/access attacks) -> Brute Force
    "warezclient": "Brute Force", "guess_passwd": "Brute Force",
    "warezmaster": "Brute Force", "imap": "Brute Force", "ftp_write": "Brute Force",
    "multihop": "Brute Force", "phf": "Brute Force", "spy": "Brute Force",
    "xlock": "Brute Force", "xsnoop": "Brute Force", "snmpguess": "Brute Force",
    "snmpgetattack": "Brute Force", "httptunnel": "Brute Force",
    "sendmail": "Brute Force", "named": "Brute Force", "worm": "Brute Force",
    # U2R family (privilege escalation / rootkit-style) -> Botnet C2
    "buffer_overflow": "Botnet C2", "rootkit": "Botnet C2", "loadmodule": "Botnet C2",
    "perl": "Botnet C2", "sqlattack": "Botnet C2", "xterm": "Botnet C2",
    "ps": "Botnet C2",
}


def load_dataset(path):
    df = pd.read_csv(path, names=COLUMNS)
    # NSL-KDD train/test files carry a trailing "difficulty" column with no header;
    # if column count is 43, the 42nd is the label and 43rd is difficulty.
    if df.shape[1] == 43:
        df.columns = COLUMNS[:-1] + ["label", "difficulty"]
        df = df.drop(columns=["difficulty"])
    df["label"] = df["label"].str.replace(".", "", regex=False).str.strip()
    df["threat_category"] = df["label"].map(CATEGORY_MAP).fillna("Botnet C2")
    return df


def build_pipeline(model):
    categorical = ["protocol_type", "service", "flag"]
    numeric = [c for c in COLUMNS[:-1] if c not in categorical]

    preprocessor = ColumnTransformer(transformers=[
        ("num", StandardScaler(), numeric),
        ("cat", OneHotEncoder(handle_unknown="ignore"), categorical),
    ])
    return Pipeline(steps=[("preprocess", preprocessor), ("model", model)]), numeric + categorical


def evaluate(name, pipeline, X_test, y_test, label_encoder):
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)

    report = classification_report(y_test, y_pred, target_names=label_encoder.classes_, output_dict=True)
    cm = confusion_matrix(y_test, y_pred).tolist()
    macro_f1 = f1_score(y_test, y_pred, average="macro")

    try:
        roc_auc = roc_auc_score(y_test, y_proba, multi_class="ovr", average="macro")
    except ValueError:
        roc_auc = None

    print(f"\n=== {name} ===")
    print(f"Macro F1: {macro_f1:.4f}   ROC-AUC (macro, OVR): {roc_auc}")
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

    return {
        "classification_report": report,
        "confusion_matrix": cm,
        "labels": list(label_encoder.classes_),
        "macro_f1": macro_f1,
        "roc_auc_macro_ovr": roc_auc,
    }


def main():
    print("Loading NSL-KDD dataset...")
    train_df = load_dataset(os.path.join(DATA_DIR, "KDDTrain.csv"))
    test_df = load_dataset(os.path.join(DATA_DIR, "KDDTest.csv"))
    print(f"Train rows: {len(train_df)}   Test rows: {len(test_df)}")
    print("Category distribution (train):")
    print(train_df["threat_category"].value_counts())

    label_encoder = LabelEncoder()
    label_encoder.fit(sorted(set(train_df["threat_category"]) | set(test_df["threat_category"])))

    X_train = train_df.drop(columns=["label", "threat_category"])
    y_train = label_encoder.transform(train_df["threat_category"])
    X_test = test_df.drop(columns=["label", "threat_category"])
    y_test = label_encoder.transform(test_df["threat_category"])

    metrics_report = {}

    # ---------------- Random Forest baseline ----------------
    rf = RandomForestClassifier(
        n_estimators=200, max_depth=20, n_jobs=-1, random_state=42, class_weight="balanced"
    )
    rf_pipeline, feature_cols = build_pipeline(rf)
    t0 = time.time()
    rf_pipeline.fit(X_train, y_train)
    print(f"\nRandom Forest trained in {time.time()-t0:.1f}s")
    metrics_report["random_forest"] = evaluate("Random Forest", rf_pipeline, X_test, y_test, label_encoder)
    joblib.dump(rf_pipeline, os.path.join(MODEL_DIR, "rf_model.joblib"))

    # ---------------- XGBoost comparison ----------------
    if HAS_XGB:
        xgb = XGBClassifier(
            n_estimators=300, max_depth=8, learning_rate=0.15,
            tree_method="hist", eval_metric="mlogloss", n_jobs=-1, random_state=42
        )
        xgb_pipeline, _ = build_pipeline(xgb)
        t0 = time.time()
        xgb_pipeline.fit(X_train, y_train)
        print(f"\nXGBoost trained in {time.time()-t0:.1f}s")
        metrics_report["xgboost"] = evaluate("XGBoost", xgb_pipeline, X_test, y_test, label_encoder)
        joblib.dump(xgb_pipeline, os.path.join(MODEL_DIR, "xgb_model.joblib"))
    else:
        print("\nxgboost not installed - skipping XGBoost comparison (pip install xgboost --break-system-packages)")

    joblib.dump(label_encoder, os.path.join(MODEL_DIR, "label_encoder.joblib"))
    with open(os.path.join(MODEL_DIR, "feature_columns.json"), "w") as f:
        json.dump(list(X_train.columns), f, indent=2)
    with open(os.path.join(MODEL_DIR, "metrics_report.json"), "w") as f:
        json.dump(metrics_report, f, indent=2)

    print(f"\nSaved models + metrics to {os.path.abspath(MODEL_DIR)}")


if __name__ == "__main__":
    main()
