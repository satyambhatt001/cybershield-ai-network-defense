import os
import json
import subprocess
from datetime import datetime
from scapy.all import srp, Ether, ARP
import config
from core.logger import log_alert

class ARPSpoofDetector:
    def __init__(self):
        self.arp_table = {}
        self.alert_history = []

    def build_initial_table(self):
        print("[ARP] Building trusted ARP table (macOS mode)...")
        try:
            # macOS uses 'arp -a' instead of Linux 'ip neigh'
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                # macOS output format: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ether]
                parts = line.split()
                if len(parts) >= 4 and "at" in parts:
                    ip = parts[1].strip("()")
                    mac = parts[3].lower()
                    if mac != "(incomplete)":
                        self.arp_table[ip] = mac
                        print(f"  [TRUSTED] {ip} → {mac}")
        except Exception as e:
            print(f"  [!] Could not read ARP cache: {e}")

        os.makedirs(os.path.dirname(config.ARP_TABLE_FILE), exist_ok=True)
        with open(config.ARP_TABLE_FILE, "w") as f:
            json.dump(self.arp_table, f, indent=2)
        print(f"[ARP] Table ready: {len(self.arp_table)} trusted entries\n")

    def check(self, sender_ip: str, sender_mac: str):
        sender_mac = sender_mac.lower()
        if sender_ip not in self.arp_table:
            self.arp_table[sender_ip] = sender_mac
            print(f"  [ARP] New host learned: {sender_ip} → {sender_mac}")
            return None

        known_mac = self.arp_table[sender_ip]
        if known_mac == sender_mac:
            return None

        severity = "CRITICAL" if sender_ip == config.GATEWAY_IP else "HIGH"
        alert = {
            "type"          : "ARP_SPOOF",
            "severity"      : severity,
            "timestamp"     : datetime.now().isoformat(),
            "attacker_ip"   : sender_ip,
            "attacker_mac"  : sender_mac,
            "legitimate_mac": known_mac,
            "message"       : (
                f"ARP SPOOFING DETECTED! IP {sender_ip} claims MAC {sender_mac} "
                f"but trusted MAC is {known_mac}. "
                f"{'*** GATEWAY TARGETED ***' if severity == 'CRITICAL' else ''}"
            )
        }
        self.alert_history.append(alert)
        log_alert(alert)
        print("\n" + "!" * 60)
        print(f"  ⚠  ALERT: {alert['message']}")
        print("!" * 60 + "\n")
        return alert

    def get_table(self): return self.arp_table
    def get_alerts(self): return self.alert_history