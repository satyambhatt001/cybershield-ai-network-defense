# main.py
# ─────────────────────────────────────────────────────────────
# ENTRY POINT — Cyber Defense Agent
#
# This file ties ALL modules together:
#   Module 1 → Packet Capture Engine
#   Module 2 → ARP Spoof Detector
#   Module 3 → DNS Spoof Detector
#   Module 4 → Traffic Analyzer
#   Module 5 → Response Engine
#   Module 6 → Flask Dashboard
#   Module 7 → ML Predictor
#
# HOW THREADING WORKS HERE:
#   Thread 1 → Flask dashboard (runs in background)
#   Thread 2 → ML status printer (runs in background)
#   Main     → Packet capture (runs forever in foreground)
#
# WHY ROOT IS REQUIRED:
#   Raw sockets need root permission in Linux
#   iptables commands need root permission
#   Promiscuous mode needs root permission
#   Run with: sudo python3 main.py
# ─────────────────────────────────────────────────────────────

import threading
import time
import sys
import os
from datetime import datetime


def check_root():
    """Raw sockets + iptables both require root."""
    if os.geteuid() != 0:
        print("\n" + "=" * 55)
        print("  ❌ ERROR: Must run as root!")
        print("=" * 55)
        print("  Raw packet capture requires root privileges.")
        print("  Please run:")
        print()
        print("    sudo python3 main.py")
        print()
        sys.exit(1)


def check_venv():
    """Make sure we are running inside the venv."""
    if sys.prefix == sys.base_prefix:
        print("\n⚠ WARNING: Virtual environment not active!")
        print("  Run: source venv/bin/activate")
        print("  Then: sudo $(which python3) main.py\n")


def print_banner():
    """Print startup banner."""
    print("\n" + "=" * 60)
    print("    🛡  AI-POWERED CYBER DEFENSE AGENT  🛡")
    print("    MITM Attack Detection & Response System")
    print("=" * 60)
    print(f"  Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Interface : {config.INTERFACE}")
    print(f"  Gateway   : {config.GATEWAY_IP}")
    print(f"  DNS Trust : {config.TRUSTED_DNS_SERVER}")
    print(f"  Auto-Block: {config.AUTO_BLOCK}")
    print(f"  Dashboard : http://localhost:{config.DASHBOARD_PORT}")
    print("=" * 60)
    print()

def start_dashboard():
    """
    Run Flask dashboard in a background daemon thread.
    Daemon thread = auto-killed when main program exits.
    """
    try:
        from dashboard.app import app
        import logging
        
        # Modern way to suppress Flask startup messages
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)

        print(f"[*] Dashboard starting on "
              f"http://localhost:{config.DASHBOARD_PORT}")
        
        app.run(
            host=config.DASHBOARD_HOST,
            port=config.DASHBOARD_PORT,
            debug=False,
            use_reloader=False
        )
    except Exception as e:
        print(f"[!] Dashboard error: {e}")


def start_ml_monitor():
    """
    Background thread that runs ML predictions
    on recent alerts every 30 seconds.
    Adds ML verdict to the alert log.
    """
    try:
        from ml.predict import MLPredictor
        from core.logger import read_alerts, log_alert

        ml = MLPredictor()
        if not ml.ready:
            print("[ML] Skipping ML monitor — no model found.")
            print("[ML] Train with: python3 ml/train_model.py")
            return

        print("[ML] ML monitor active — analyzing traffic...")

        while True:
            time.sleep(30)   # Check every 30 seconds

            # Read recent alerts and run ML on them
            alerts = read_alerts(10)
            for alert in alerts:
                if alert.get("ml_checked"):
                    continue   # Already processed

                # Extract features from alert type
                features = _alert_to_features(alert)
                if features:
                    result = ml.predict(features)
                    if result["verdict"] == "MALICIOUS":
                        print(f"  [ML] 🤖 Confirmed malicious: "
                              f"{alert.get('type')} "
                              f"(confidence: {result['confidence']})")

    except Exception as e:
        print(f"[ML] Monitor error: {e}")


def _alert_to_features(alert: dict) -> dict:
    """Convert an alert dict to ML feature dict."""
    alert_type = alert.get("type", "")

    if alert_type == "ARP_SPOOF":
        return {
            "protocol": 0, "pkt_len": 60,
            "arp_op": 2, "tcp_flags": 0,
            "dns_resp": 0, "pkt_rate": 90,
            "unique_ports": 0
        }
    elif alert_type == "DNS_SPOOF":
        return {
            "protocol": 1, "pkt_len": 120,
            "arp_op": 0, "tcp_flags": 0,
            "dns_resp": 1, "pkt_rate": 70,
            "unique_ports": 0
        }
    elif alert_type == "PORT_SCAN":
        return {
            "protocol": 2, "pkt_len": 60,
            "arp_op": 0, "tcp_flags": 2,
            "dns_resp": 0, "pkt_rate": 65,
            "unique_ports": 500
        }
    elif alert_type == "PACKET_FLOOD":
        return {
            "protocol": 2, "pkt_len": 100,
            "arp_op": 0, "tcp_flags": 0,
            "dns_resp": 0, "pkt_rate": 300,
            "unique_ports": 1
        }
    return None


def verify_interface():
    """
    Verify the configured interface exists on macOS.
    macOS uses 'ifconfig' instead of Linux 'ip link show'
    """
    import subprocess
    try:
        result = subprocess.run(["ifconfig", config.INTERFACE], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"\n❌ ERROR: Interface '{config.INTERFACE}' not found!")
            print(f"Edit config.py and ensure INTERFACE is set to 'en0' (or your active network interface)")
            sys.exit(1)
        else:
            print(f"[*] Interface '{config.INTERFACE}' verified ✅")
    except Exception as e:
        print(f"\n[!] Could not run ifconfig to verify interface: {e}")


def main():
    # ── Step 1: Safety checks ─────────────────────────────────
    check_root()
    check_venv()

    # ── Step 2: Import config (after root check) ──────────────
    global config
    import config

    # ── Step 3: Print banner ──────────────────────────────────
    print_banner()

    # ── Step 4: Verify interface exists ──────────────────────
    verify_interface()

    # ── Step 5: Create data directory ────────────────────────
    os.makedirs("data", exist_ok=True)
    print("[*] Data directory ready ✅")

    # ── Step 6: Start Flask dashboard in background ───────────
    print("[*] Starting Flask dashboard...")
    dash_thread = threading.Thread(
        target=start_dashboard,
        daemon=True,
        name="DashboardThread"
    )
    dash_thread.start()
    time.sleep(2)   # Give Flask time to start
    print(f"[*] Dashboard ready → "
          f"http://localhost:{config.DASHBOARD_PORT} ✅")

    # ── Step 7: Start ML monitor in background ────────────────
    print("[*] Starting ML monitor...")
    ml_thread = threading.Thread(
        target=start_ml_monitor,
        daemon=True,
        name="MLMonitorThread"
    )
    ml_thread.start()
    print("[*] ML monitor ready ✅")

    # ── Step 8: Start packet capture (main thread) ────────────
    print()
    print("[*] All systems ready. Starting packet capture...\n")
    time.sleep(1)

    from core.packet_capture import PacketCaptureEngine
    engine = PacketCaptureEngine()

    try:
        engine.start()   # Blocks forever until Ctrl+C

    except KeyboardInterrupt:
        print("\n\n" + "=" * 60)
        print("  🛑 Shutting down Cyber Defense Agent...")
        print("=" * 60)
        engine.stop()

        # Print final summary
        print(f"\n  📊 SESSION SUMMARY")
        print(f"  {'─'*40}")
        print(f"  Packets captured : {engine.packet_count}")
        print(f"  ARP alerts       : "
              f"{len(engine.arp_detector.get_alerts())}")
        print(f"  DNS alerts       : "
              f"{len(engine.dns_detector.get_alerts())}")
        print(f"  Traffic alerts   : "
              f"{len(engine.traffic_analyzer.get_alerts())}")
        print(f"  IPs blocked      : "
              f"{len(engine.response_engine.get_blocked_ips())}")
        print(f"  Blocked IPs      : "
              f"{engine.response_engine.get_blocked_ips()}")
        print(f"  {'─'*40}")
        print(f"  Log file : data/alerts.log")
        print(f"  ARP table: data/arp_table.json")
        print()
        print("  Goodbye! 👋")
        print("=" * 60 + "\n")
        sys.exit(0)


if __name__ == "__main__":
    main()