# ml/train_model.py
# ─────────────────────────────────────────────────────────────
# MODULE 7: AI/ML DETECTION LAYER
#
# WHY ML FOR NETWORK SECURITY?
#   Rule-based detection (what we built so far) is great
#   but has limitations:
#     → Only detects KNOWN attack patterns
#     → Attacker can craft packets that bypass rules
#     → Cannot adapt to new attack variants
#
#   ML adds BEHAVIORAL detection:
#     → Learns what NORMAL traffic looks like
#     → Flags anything statistically abnormal
#     → Adapts to new patterns over time
#
# WHAT WE BUILD:
#   Random Forest classifier trained on packet features:
#     protocol     → what protocol is this? (ARP/DNS/TCP/UDP)
#     pkt_len      → how big is the packet?
#     arp_op       → ARP request or reply?
#     tcp_flags    → SYN? SYN-ACK? just ACK?
#     dns_resp     → is this a DNS response?
#     pkt_rate     → how many packets/sec from source?
#     unique_ports → how many different ports hit?
#
# WHY RANDOM FOREST?
#   → Handles mixed data types well
#   → Robust to noisy network data
#   → Fast prediction (important for real-time)
#   → Gives feature importance (explainable)
#   → Works well with imbalanced classes
# ─────────────────────────────────────────────────────────────

import pandas as pd
import numpy as np
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (classification_report,
                             confusion_matrix, accuracy_score)

BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "ml", "model.pkl")


def generate_dataset(n_samples: int = 6000) -> pd.DataFrame:
    """
    Generate synthetic labeled network traffic.

    In real deployment replace this with:
      - Your own captured PCAP files parsed with Scapy
      - NSL-KDD dataset (classic IDS benchmark)
      - CIC-IDS2017 (modern realistic dataset)
      - Download: https://www.unb.ca/cic/datasets/

    Features explanation:
      protocol     : 0=ARP, 1=DNS, 2=TCP, 3=UDP, 4=ICMP
      pkt_len      : packet size in bytes
      arp_op       : 0=none, 1=request, 2=reply
      tcp_flags    : 0=none, 2=SYN, 18=SYN-ACK, 16=ACK
      dns_resp     : 0=query or not DNS, 1=DNS response
      pkt_rate     : packets per second from this source
      unique_ports : unique destination ports in 1 sec window
      label        : 0=normal, 1=malicious
    """
    np.random.seed(42)

    # ── Normal traffic (75%) ─────────────────────────────────
    n = int(n_samples * 0.75)
    normal = pd.DataFrame({
        "protocol"    : np.random.choice([1,2,3], n),
        "pkt_len"     : np.random.normal(400, 150, n).clip(40, 1500),
        "arp_op"      : np.zeros(n),
        "tcp_flags"   : np.random.choice([0,2,18,16], n),
        "dns_resp"    : np.random.choice([0,1], n),
        "pkt_rate"    : np.random.normal(15, 8, n).clip(1, 60),
        "unique_ports": np.random.randint(1, 4, n),
        "label"       : 0
    })

    # ── ARP Spoofing traffic (8%) ────────────────────────────
    # Characteristics:
    #   protocol=ARP, op=2 (replies), high rate, small packets
    a = int(n_samples * 0.08)
    arp_spoof = pd.DataFrame({
        "protocol"    : np.zeros(a),
        "pkt_len"     : np.random.normal(60, 5, a).clip(42, 80),
        "arp_op"      : np.full(a, 2),
        "tcp_flags"   : np.zeros(a),
        "dns_resp"    : np.zeros(a),
        "pkt_rate"    : np.random.normal(90, 20, a).clip(60, 200),
        "unique_ports": np.zeros(a),
        "label"       : 1
    })

    # ── DNS Spoofing traffic (7%) ────────────────────────────
    # Characteristics:
    #   protocol=DNS, dns_resp=1, high rate
    d = int(n_samples * 0.07)
    dns_spoof = pd.DataFrame({
        "protocol"    : np.ones(d),
        "pkt_len"     : np.random.normal(120, 30, d),
        "arp_op"      : np.zeros(d),
        "tcp_flags"   : np.zeros(d),
        "dns_resp"    : np.ones(d),
        "pkt_rate"    : np.random.normal(70, 15, d),
        "unique_ports": np.zeros(d),
        "label"       : 1
    })

    # ── Port Scan traffic (5%) ───────────────────────────────
    # Characteristics:
    #   TCP SYN only, many unique ports, low pkt size
    s = int(n_samples * 0.05)
    port_scan = pd.DataFrame({
        "protocol"    : np.full(s, 2),
        "pkt_len"     : np.random.normal(60, 5, s).clip(40, 80),
        "arp_op"      : np.zeros(s),
        "tcp_flags"   : np.full(s, 2),
        "dns_resp"    : np.zeros(s),
        "pkt_rate"    : np.random.normal(60, 15, s),
        "unique_ports": np.random.randint(50, 1000, s),
        "label"       : 1
    })

    # ── Packet Flood traffic (5%) ────────────────────────────
    # Characteristics:
    #   Very high packet rate from single source
    f = int(n_samples * 0.05)
    flood = pd.DataFrame({
        "protocol"    : np.random.choice([2,3], f),
        "pkt_len"     : np.random.normal(100, 30, f),
        "arp_op"      : np.zeros(f),
        "tcp_flags"   : np.random.choice([2,0], f),
        "dns_resp"    : np.zeros(f),
        "pkt_rate"    : np.random.normal(300, 50, f).clip(150, 1000),
        "unique_ports": np.random.randint(1, 3, f),
        "label"       : 1
    })

    # Combine and shuffle
    df = pd.concat(
        [normal, arp_spoof, dns_spoof, port_scan, flood],
        ignore_index=True
    )
    return df.sample(frac=1, random_state=42).reset_index(drop=True)


def train():
    print("=" * 55)
    print("  MODULE 7: ML MODEL TRAINING")
    print("=" * 55)

    print("\n[ML] Generating training dataset...")
    df = generate_dataset(6000)

    print(f"[ML] Dataset size: {len(df)} samples")
    print(f"[ML] Class distribution:")
    print(f"     Normal   : {(df.label==0).sum()} samples")
    print(f"     Malicious: {(df.label==1).sum()} samples")

    X = df.drop("label", axis=1)
    y = df["label"]

    # 80% train, 20% test, stratified split
    # Stratified = keeps same class ratio in train/test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    print(f"\n[ML] Training on {len(X_train)} samples...")
    print(f"[ML] Testing on  {len(X_test)} samples...")

    # Random Forest with class balancing
    model = RandomForestClassifier(
        n_estimators=100,    # 100 decision trees
        max_depth=10,        # limit tree depth (prevent overfitting)
        class_weight="balanced",  # handle imbalanced classes
        random_state=42,
        n_jobs=-1            # use all CPU cores
    )

    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    # ── Results ──────────────────────────────────────────────
    acc = accuracy_score(y_test, y_pred)
    print(f"\n[ML] ✅ Accuracy: {acc*100:.2f}%")

    print("\n[ML] Classification Report:")
    print(classification_report(
        y_test, y_pred,
        target_names=["Normal", "Malicious"]
    ))

    print("[ML] Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"       Predicted Normal  Malicious")
    print(f"Actual Normal     {cm[0][0]:5d}  {cm[0][1]:5d}")
    print(f"Actual Malicious  {cm[1][0]:5d}  {cm[1][1]:5d}")

    print("\n[ML] Feature Importances (what matters most):")
    features = X.columns.tolist()
    importances = model.feature_importances_
    for feat, imp in sorted(zip(features, importances),
                            key=lambda x: -x[1]):
        bar = "█" * int(imp * 50)
        print(f"  {feat:15s}: {imp:.4f} {bar}")

    # Save model
    joblib.dump(model, MODEL_PATH)
    print(f"\n[ML] ✅ Model saved to: {MODEL_PATH}")
    print("[ML] Training complete!\n")


if __name__ == "__main__":
    train()
