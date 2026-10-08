# core/dns_detector.py
# ─────────────────────────────────────────────────────────────
# MODULE 3: DNS SPOOF DETECTION
#
# HOW DNS WORKS (step by step):
#
#   1. You type www.google.com in browser
#   2. Your PC sends UDP packet to DNS server port 53:
#      "What is the IP of www.google.com?"
#   3. DNS server replies:
#      "www.google.com = 142.250.80.4"
#   4. Your PC connects to 142.250.80.4
#
# DNS SPOOFING ATTACK:
#   Attacker is already in MITM position (via ARP spoof)
#   They intercept your DNS query
#   They reply FIRST with fake IP: "google.com = attacker_IP"
#   Your PC connects to attacker's server instead!
#   Attacker shows fake login page → steals credentials
#
# HOW WE DETECT IT:
#   Method 1: Check WHERE the DNS reply came from
#             Valid replies only come from TRUSTED_DNS_SERVER
#             Reply from unknown IP = SPOOFED
#   Method 2: Cache known-good IPs for each domain
#             If domain suddenly resolves differently = ALERT
# ─────────────────────────────────────────────────────────────

from datetime import datetime
from scapy.all import DNS, DNSRR, IP, DNSQR
import config
from core.logger import log_alert


class DNSSpoofDetector:

    def __init__(self):
        self.alert_history = []

        # Cache of domain → known good IPs
        # Built up as we see legitimate DNS responses
        # Format: {"www.google.com.": {"142.250.80.4", "142.250.80.5"}}
        self.trusted_dns_cache = {}

    # ── Main check function ──────────────────────────────────────
    def check(self, packet, src_ip: str):
        """
        Called for every DNS RESPONSE (qr=1) on the wire.

        A DNS response packet structure:
          IP layer  → src=DNS_server_IP, dst=client_IP
          UDP layer → src_port=53, dst_port=random
          DNS layer → qr=1 (response), ancount=number of answers
          DNSQR     → the question (domain queried)
          DNSRR     → the answer (IP address)
        """
        dns = packet[DNS]

        # Get the domain that was queried
        if dns.qd is None:
            return None

        # Domain name (bytes → string)
        domain = dns.qd.qname
        if isinstance(domain, bytes):
            domain = domain.decode()

        # ── Check 1: Did reply come from trusted DNS server? ─────
        #
        # NORMAL:  DNS reply arrives from 8.8.8.8 (Google DNS)
        # SPOOFED: DNS reply arrives from 192.168.1.99 (attacker)
        #
        # If src_ip is NOT our trusted DNS server → SPOOFED!
        if src_ip != config.TRUSTED_DNS_SERVER:
            resolved_ips = self._extract_ips(dns)

            alert = {
                "type"        : "DNS_SPOOF",
                "severity"    : "HIGH",
                "timestamp"   : datetime.now().isoformat(),
                "domain"      : domain,
                "attacker_ip" : src_ip,
                "fake_ips"    : list(resolved_ips),
                "message"     : (
                    f"DNS SPOOFING DETECTED! "
                    f"Response for '{domain}' came from {src_ip} "
                    f"but trusted DNS is {config.TRUSTED_DNS_SERVER}. "
                    f"Fake IPs returned: {resolved_ips}"
                )
            }

            self.alert_history.append(alert)
            log_alert(alert)

            print("\n" + "!" * 60)
            print(f"  ⚠  ALERT: {alert['message']}")
            print("!" * 60 + "\n")

            return alert

        # ── Check 2: IP changed for known domain? ────────────────
        #
        # We've seen this domain resolved correctly before.
        # If it now resolves to a COMPLETELY different IP → suspicious.
        # Note: CDNs rotate IPs legitimately, so we log as WARNING only.
        resolved_ips = self._extract_ips(dns)

        if domain in self.trusted_dns_cache:
            known_ips   = self.trusted_dns_cache[domain]
            new_ips     = resolved_ips - known_ips

            if new_ips:
                print(f"  [DNS WARNING] {domain} has new IPs: {new_ips} "
                      f"(previously: {known_ips}) — could be CDN rotation")
            # Update cache with new IPs (CDN rotation is legitimate)
            self.trusted_dns_cache[domain].update(resolved_ips)
        else:
            # First time seeing this domain → cache it as trusted
            self.trusted_dns_cache[domain] = resolved_ips
            print(f"  [DNS] Cached: {domain} → {resolved_ips}")

        return None

    # ── Extract IP addresses from DNS Answer section ─────────────
    def _extract_ips(self, dns) -> set:
        """
        DNS Answer section contains Resource Records (RRs).
        Each RR has: name, type, class, TTL, rdata

        Type 1 = A record = IPv4 address
        We walk the linked list of answers extracting all A records.

        Scapy DNS answer chain:
          dns.an → first answer
          dns.an.payload → second answer
          dns.an.payload.payload → third answer
          ... and so on
        """
        ips = set()
        answer = dns.an

        while answer and hasattr(answer, "rrname"):
            # type 1 = DNS A record (IPv4 address)
            if hasattr(answer, "type") and answer.type == 1:
                if hasattr(answer, "rdata"):
                    ips.add(answer.rdata)
            # Move to next answer in chain
            answer = answer.payload if hasattr(answer, "payload") else None
            if answer and not hasattr(answer, "rrname"):
                break

        return ips

    def get_alerts(self):
        return self.alert_history

    def get_cache(self):
        return self.trusted_dns_cache
