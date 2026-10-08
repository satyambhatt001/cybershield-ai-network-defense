import os

# ── Network Interface ──────────────────────────────────────────
INTERFACE = "en0"

# ── Trusted DNS Server ─────────────────────────────────────────
# Updated to match your actual local router/hotspot DNS
TRUSTED_DNS_SERVER = "172.20.10.1"

# ── Gateway IP ────────────────────────────────────────────────
# Updated to match your actual gateway
GATEWAY_IP = "172.20.10.1"

# ── Thresholds ─────────────────────────────────────────────────
PACKET_RATE_THRESHOLD = 100

# ── File Paths ─────────────────────────────────────────────────
BASE_DIR           = os.path.dirname(os.path.abspath(__file__))
ALERT_LOG          = os.path.join(BASE_DIR, "data", "alerts.log")
TRAFFIC_LOG        = os.path.join(BASE_DIR, "data", "traffic.log")
ARP_TABLE_FILE     = os.path.join(BASE_DIR, "data", "arp_table.json")
MODEL_PATH         = os.path.join(BASE_DIR, "ml", "model.pkl")

# ── Dashboard ──────────────────────────────────────────────────
DASHBOARD_HOST     = "0.0.0.0"
DASHBOARD_PORT     = 5050

# ── Response ───────────────────────────────────────────────────
AUTO_BLOCK         = False    # Keep FALSE during testing!

# ── Whitelist ──────────────────────────────────────────────────
WHITELIST          = ["172.20.10.1", "127.0.0.1"]