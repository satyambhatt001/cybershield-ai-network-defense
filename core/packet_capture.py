# core/packet_capture.py
# ─────────────────────────────────────────────────────────────
# MODULE 1: PACKET CAPTURE ENGINE
#
# HOW RAW PACKET CAPTURE WORKS:
#
#   Normal app:  [App] → [OS TCP/IP Stack] → [NIC]
#   Scapy:       [Scapy] → [Raw Socket] → [NIC Driver]
#
#   Scapy bypasses the OS network stack completely.
#   It reads raw frames directly from the NIC driver.
#   This is how Wireshark works too.
#
# PROMISCUOUS MODE:
#   Normally NIC only accepts:
#     → Frames addressed to its own MAC
#     → Broadcast frames (ff:ff:ff:ff:ff:ff)
#   In promiscuous mode NIC accepts ALL frames on segment
#   Required for network monitoring / IDS
#
# BPF FILTER (Berkeley Packet Filter):
#   Filter string compiled to kernel bytecode
#   Runs IN the kernel — very fast
#   Only matching packets wake up Python
#   "arp or udp port 53" = only ARP + DNS traffic
#   This saves enormous CPU on busy networks
#
# ETHERNET FRAME STRUCTURE:
#   ┌──────────┬──────────┬───────────┬──────────────────┐
#   │ Dst MAC  │ Src MAC  │ EtherType │ Payload          │
#   │ (6 bytes)│ (6 bytes)│ (2 bytes) │ ARP/IP/etc       │
#   │          │          │ 0x0806=ARP│                  │
#   │          │          │ 0x0800=IP │                  │
#   └──────────┴──────────┴───────────┴──────────────────┘
# ─────────────────────────────────────────────────────────────

import threading
import time
from datetime import datetime
from scapy.all import sniff, ARP, DNS, IP, TCP, UDP, Ether

import config
from core.arp_detector     import ARPSpoofDetector
from core.dns_detector     import DNSSpoofDetector
from core.traffic_analyzer import TrafficAnalyzer
from core.response_engine  import ResponseEngine


class PacketCaptureEngine:
    """
    Central engine that:
    1. Captures every packet on the wire
    2. Dispatches to correct detector module
    3. Passes alerts to response engine
    """

    def __init__(self):
        # Initialize all detector modules
        self.arp_detector     = ARPSpoofDetector()
        self.dns_detector     = DNSSpoofDetector()
        self.traffic_analyzer = TrafficAnalyzer()
        self.response_engine  = ResponseEngine()

        self.packet_count = 0
        self.start_time   = time.time()
        self.running      = False

    # ── Callback: called for EVERY captured packet ───────────────
    def _process_packet(self, packet):
        """
        Scapy calls this function once per captured packet.
        This is the heart of the entire system.

        Packet layer access in Scapy:
          packet[Ether]  → MAC src/dst, EtherType
          packet[IP]     → IP src/dst, protocol, TTL
          packet[TCP]    → ports, flags, seq/ack numbers
          packet[ARP]    → op, sender IP/MAC, target IP/MAC
          packet[DNS]    → query/response, questions, answers
        """
        self.packet_count += 1

        # ── Feed to traffic analyzer (every packet) ───────────────
        # Analyzer tracks rates and behavioral patterns
        self.traffic_analyzer.analyze(packet)

        # ── Handle ARP packets ────────────────────────────────────
        # EtherType 0x0806 = ARP
        # ARP never leaves local subnet (not routed)
        # op=1 → Request (who has this IP?)
        # op=2 → Reply   (I have this IP, my MAC is...)
        if packet.haslayer(ARP):
            self._handle_arp(packet)

        # ── Handle DNS packets ────────────────────────────────────
        # UDP port 53 = DNS
        # qr=0 → Query (client asking)
        # qr=1 → Response (server answering) ← we monitor this
        if packet.haslayer(DNS) and packet.haslayer(IP):
            self._handle_dns(packet)

        # ── Print status every 100 packets ───────────────────────
        if self.packet_count % 100 == 0:
            self._print_status()

    # ── Handle ARP packet ────────────────────────────────────────
    def _handle_arp(self, packet):
        """
        ARP SPOOFING RECAP:
          Normal ARP reply:
            192.168.1.1 is at aa:bb:cc:dd:ee:ff  (real gateway MAC)

          Spoofed ARP reply (attacker sends this):
            192.168.1.1 is at de:ad:be:ef:00:01  (attacker MAC)

          Victim updates ARP cache → traffic goes to attacker.

          We detect this by comparing the claimed MAC
          against our trusted IP→MAC table.
        """
        arp = packet[ARP]

        # We only care about REPLIES (op=2)
        # Requests (op=1) are harmless broadcasts
        if arp.op == 2:
            sender_ip  = arp.psrc   # IP address in the ARP reply
            sender_mac = arp.hwsrc  # MAC address in the ARP reply

            alert = self.arp_detector.check(sender_ip, sender_mac)
            if alert:
                self.response_engine.handle_alert(alert)

    # ── Handle DNS packet ────────────────────────────────────────
    def _handle_dns(self, packet):
        """
        DNS SPOOFING RECAP:
          Normal DNS response:
            Source IP = 8.8.8.8 (Google DNS)
            Answer: google.com = 142.250.80.4 (real IP)

          Spoofed DNS response (attacker sends this):
            Source IP = 192.168.1.99 (attacker)
            Answer: google.com = 10.0.0.1 (fake IP)

          We detect this by checking if DNS response
          came from our trusted DNS server IP.
        """
        dns = packet[DNS]
        # qr=1 means this is a RESPONSE (not a query)
        # ancount > 0 means it has at least one answer
        if dns.qr == 1 and dns.ancount > 0:
            src_ip = packet[IP].src

            alert = self.dns_detector.check(packet, src_ip)
            if alert:
                self.response_engine.handle_alert(alert)

    # ── Print live status ────────────────────────────────────────
    def _print_status(self):
        elapsed = time.time() - self.start_time
        rate    = self.packet_count / elapsed if elapsed > 0 else 0
        ts      = datetime.now().strftime("%H:%M:%S")
        blocked = len(self.response_engine.get_blocked_ips())

        print(f"[{ts}] Packets: {self.packet_count} | "
              f"Rate: {rate:.1f} pkt/s | "
              f"Blocked IPs: {blocked} | "
              f"Alerts: {len(self.arp_detector.get_alerts()) + len(self.dns_detector.get_alerts())}")

    # ── Start sniffing ───────────────────────────────────────────
    def start(self):
        """
        scapy.sniff() key parameters:
          iface  → which network interface to listen on
          prn    → callback function for each packet
          store  → False = don't store in RAM (process on the fly)
          filter → BPF filter (kernel-level, very efficient)

        BPF filter "arp or udp port 53":
          arp         → capture all ARP frames
          udp port 53 → capture DNS queries/responses only
          This ignores HTTP, HTTPS, SSH etc → saves CPU
        """
        self.running = True

        print("=" * 60)
        print("  CYBER DEFENSE AGENT — PACKET CAPTURE STARTED")
        print("=" * 60)
        print(f"  Interface  : {config.INTERFACE}")
        print(f"  BPF Filter : 'arp or udp port 53'")
        print(f"  Auto-Block : {config.AUTO_BLOCK}")
        print(f"  Gateway    : {config.GATEWAY_IP}")
        print("=" * 60)
        print()

        # Build trusted ARP table before we start sniffing
        print("[*] Step 1: Building trusted ARP table...")
        self.arp_detector.build_initial_table()

        print("[*] Step 2: Starting live packet capture...")
        print("[*] Watching for ARP spoof + DNS spoof attacks...")
        print("[*] Press Ctrl+C to stop\n")

        # Start sniffing — this blocks forever until Ctrl+C
        sniff(
            iface=config.INTERFACE,
            prn=self._process_packet,
            store=False,
            filter="arp or udp port 53"
        )

    def stop(self):
        self.running = False
        print("\n[*] Packet capture stopped.")
        print(f"[*] Total packets captured: {self.packet_count}")
        print(f"[*] Total IPs blocked: "
              f"{len(self.response_engine.get_blocked_ips())}")
