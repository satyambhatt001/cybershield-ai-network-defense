import joblib
import os
import pandas as pd

BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "ml", "model.pkl")


class MLPredictor:

    def __init__(self):
        if os.path.exists(MODEL_PATH):
            self.model = joblib.load(MODEL_PATH)
            self.ready = True
            print("[ML] Model loaded and ready.")
        else:
            self.ready = False
            print("[ML] No model found.")
            print("[ML] Run: python3 ml/train_model.py")

    def predict(self, features: dict) -> dict:
        if not self.ready:
            return {
                "label"     : -1,
                "confidence": 0.0,
                "verdict"   : "MODEL_NOT_LOADED"
            }

        X = pd.DataFrame([{
            "protocol"    : features.get("protocol",     2),
            "pkt_len"     : features.get("pkt_len",    200),
            "arp_op"      : features.get("arp_op",       0),
            "tcp_flags"   : features.get("tcp_flags",    0),
            "dns_resp"    : features.get("dns_resp",     0),
            "pkt_rate"    : features.get("pkt_rate",    10),
            "unique_ports": features.get("unique_ports", 1),
        }])

        label      = self.model.predict(X)[0]
        proba      = self.model.predict_proba(X)[0]
        confidence = proba[label]

        return {
            "label"     : int(label),
            "confidence": round(float(confidence), 3),
            "verdict"   : "MALICIOUS" if label == 1 else "NORMAL"
        }
