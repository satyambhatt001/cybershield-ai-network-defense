import os
from datetime import datetime
import config
from core.logger import log_alert

class ResponseEngine:
    def __init__(self):
        self.blocked_ips = set()
        self.action_log  = []

    def handle_alert(self, alert: dict):
        alert_type = alert.get("type")
        if alert_type == "ARP_SPOOF": self._respond_arp_spoof(alert)
        elif alert_type == "DNS_SPOOF": self._respond_dns_spoof(alert)
        elif alert_type in ("PACKET_FLOOD", "PORT_SCAN", "ARP_STORM"): self._respond_flood(alert)

    def _respond_arp_spoof(self, alert: dict):
        attacker_ip = alert.get("attacker_ip")
        print(f"\n[RESPONSE] ARP Spoof mitigation started for: {attacker_ip}")
        if attacker_ip and attacker_ip not in config.WHITELIST:
            self._iptables_block(attacker_ip)
        self._log_action("ARP_BLOCK", attacker_ip, alert["message"])

    def _respond_dns_spoof(self, alert: dict):
        attacker_ip = alert.get("attacker_ip")
        print(f"\n[RESPONSE] DNS Spoof mitigation started for rogue DNS: {attacker_ip}")
        if attacker_ip and attacker_ip not in config.WHITELIST:
            self._iptables_block(attacker_ip)
        self._log_action("DNS_BLOCK", attacker_ip, alert["message"])

    def _respond_flood(self, alert: dict):
        source = alert.get("source", alert.get("attacker_ip"))
        print(f"\n[RESPONSE] Flood/Scan mitigation started for: {source}")
        if source and source not in config.WHITELIST:
            print(f"  [macOS Simulation] Rate-limited {source} to 10 pkt/s via pfctl")
        self._log_action("RATE_LIMIT", source, alert["message"])

    def _iptables_block(self, ip: str):
        if ip in self.blocked_ips: return
        self.blocked_ips.add(ip)
        print(f"  [macOS Simulation] Firewall rule applied: DROP {ip}")
        print(f"  (On Linux this would execute: iptables -I INPUT -s {ip} -j DROP)")

    def unblock_ip(self, ip: str):
        self.blocked_ips.discard(ip)
        print(f"  [macOS Simulation] Unblocked: {ip}")

    def _log_action(self, action: str, target: str, detail: str):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "action"   : action,
            "target"   : target,
            "detail"   : detail,
        }
        self.action_log.append(entry)
        log_alert(entry)

    def get_blocked_ips(self): return list(self.blocked_ips)
    def get_action_log(self): return self.action_log