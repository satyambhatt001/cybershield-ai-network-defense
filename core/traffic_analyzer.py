# core/traffic_analyzer.py
# ─────────────────────────────────────────────────────────────
# MODULE 4: TRAFFIC ANALYSIS ENGINE
#
# WHAT IT DOES:
#   Detects BEHAVIORAL anomalies beyond specific attacks:
#
#   1. PACKET FLOOD
#      Normal: 10-50 packets/sec from one IP
#      Attack: 500+ packets/sec = DoS attempt
#      Detection: count packets per IP per second
#
#   2. PORT SCAN
#      Normal: connect to 1-2 ports (80, 443)
#      Attack: SYN to 100s of ports = Nmap scan
#      Detection: count unique destination ports per IP
#      TCP SYN flag = 0x02 (connect attempt, no prior handshake)
#
#   3. ARP STORM
#      Normal: few ARP requests per minute
#      Attack: 100s per second = ARP scanner or storm
#      Detection: count ARP packets per source MAC
#
# HOW SLIDING WINDOW WORKS:
#   We count events in 1-second buckets
#   At end of each second → check if any threshold exceeded
#   Reset counters → start fresh next second
#   This is how real IDS tools like Snort work
# ─────────────────────────────────────────────────────────────

import time
from collections import defaultdict
from datetime import datetime
from scapy.all import IP, ARP, TCP, ICMP
import config
from core.logger import log_alert


class TrafficAnalyzer:

    def __init__(self):
        # Per-IP packet counter in current time window
        # Format: {"192.168.1.99": 450}
        self.packet_counts   = defaultdict(int)

        # Per-IP set of destination ports hit (port scan detection)
        # Format: {"192.168.1.99": {22, 23, 80, 443, 8080, ...}}
        self.port_scan_track = defaultdict(set)

        # Per-MAC ARP packet counter
        # Format: {"de:ad:be:ef:00:01": 120}
        self.arp_count       = defaultdict(int)

        self.window_start    = time.time()
        self.WINDOW_SIZE     = 1.0    # 1 second sliding window
        self.alert_history   = []

    # ── Called for EVERY packet captured ────────────────────────
    def analyze(self, packet):
        """
        This function is called by PacketCaptureEngine
        for every single packet on the wire.

        We just COUNT here. Threshold checking happens
        at end of each time window.
        """
        now = time.time()

        # ── End of time window → check thresholds & reset ────────
        if now - self.window_start > self.WINDOW_SIZE:
            self._check_thresholds()
            # Reset all counters for next window
            self.packet_counts   = defaultdict(int)
            self.port_scan_track = defaultdict(set)
            self.arp_count       = defaultdict(int)
            self.window_start    = now

        # ── Count IP packets ──────────────────────────────────────
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            self.packet_counts[src_ip] += 1

            # ── Port scan detection ───────────────────────────────
            # TCP SYN flag = 0x02
            # Port scanner sends SYN to many ports → we see
            # one IP hitting many unique destination ports
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                # flags == 2 means ONLY SYN bit is set
                # (not SYN-ACK which would be flags == 18)
                if tcp.flags == 0x02:
                    self.port_scan_track[src_ip].add(tcp.dport)

        # ── Count ARP packets per MAC ─────────────────────────────
        # Normal hosts send very few ARP requests
        # Scanner/attacker floods ARP → high count from one MAC
        if packet.haslayer(ARP):
            src_mac = packet[ARP].hwsrc
            self.arp_count[src_mac] += 1

    # ── Check all counters against thresholds ───────────────────
    def _check_thresholds(self):
        """
        Called once per second.
        Compares counters against configured thresholds.
        Raises alerts if exceeded.
        """

        # ── Check 1: Packet flood ─────────────────────────────────
        for ip, count in self.packet_counts.items():
            if count > config.PACKET_RATE_THRESHOLD:
                self._raise_alert(
                    alert_type = "PACKET_FLOOD",
                    source     = ip,
                    message    = (
                        f"PACKET FLOOD from {ip}: "
                        f"{count} packets/sec "
                        f"(threshold: {config.PACKET_RATE_THRESHOLD})"
                    )
                )

        # ── Check 2: Port scan ────────────────────────────────────
        # If one IP hit more than 20 unique ports in 1 second
        # → definitely a port scan (nmap default = very fast)
        for ip, ports in self.port_scan_track.items():
            if len(ports) > 20:
                self._raise_alert(
                    alert_type = "PORT_SCAN",
                    source     = ip,
                    message    = (
                        f"PORT SCAN from {ip}: "
                        f"{len(ports)} unique ports in 1 second. "
                        f"Sample: {list(ports)[:8]}"
                    )
                )

        # ── Check 3: ARP storm ────────────────────────────────────
        # More than 50 ARP packets/sec from one MAC = storm/scan
        for mac, count in self.arp_count.items():
            if count > 50:
                self._raise_alert(
                    alert_type = "ARP_STORM",
                    source     = mac,
                    message    = (
                        f"ARP STORM from MAC {mac}: "
                        f"{count} ARP packets/sec"
                    )
                )

    # ── Create and log an alert ──────────────────────────────────
    def _raise_alert(self, alert_type: str,
                     source: str, message: str):
        alert = {
            "type"     : alert_type,
            "severity" : "MEDIUM",
            "timestamp": datetime.now().isoformat(),
            "source"   : source,
            "message"  : message,
        }
        self.alert_history.append(alert)
        log_alert(alert)
        print(f"\n  [ALERT] {message}")

    def get_alerts(self):
        return self.alert_history

    def get_stats(self):
        """Return current window stats (for dashboard)"""
        return {
            "packet_counts"  : dict(self.packet_counts),
            "port_scan_track": {k: list(v) for k, v
                                in self.port_scan_track.items()},
            "arp_count"      : dict(self.arp_count),
        }
