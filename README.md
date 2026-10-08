# 🛡️ CyberShield
## AI-Powered Network Defense & MITM Detection System

CyberShield is a real-time network security system that monitors live network traffic, detects common network attacks, classifies suspicious activity using a Random Forest ML model, and provides automated defensive responses through Linux firewall controls.

### Core Capabilities

- Real-time packet capture
- ARP spoofing detection
- DNS spoofing detection
- Port scan detection
- Packet flooding detection
- ARP storm detection
- Random Forest-based traffic classification
- Real-time security alerts
- Suspicious IP blocking
- Live security dashboard
- Structured security logging

---

# 🏗️ System Architecture

```text
                 Network Traffic
                       │
                       ▼
              ┌─────────────────┐
              │  Packet Capture │
              │     Scapy       │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  BPF Filtering │
              │ ARP / DNS etc. │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Traffic Analysis│
              └────────┬────────┘
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
      Rule-Based Detection    ML Detection
             │             Random Forest
             └─────────┬─────────┘
                       ▼
              ┌─────────────────┐
              │ Threat Analysis │
              │ Severity/Score  │
              └────────┬────────┘
                       │
              ┌────────┴────────┐
              ▼                 ▼
       Alert Engine       Response Engine
              │                 │
              ▼                 ▼
       Live Dashboard       iptables
                                │
                                ▼
                           IP Blocking