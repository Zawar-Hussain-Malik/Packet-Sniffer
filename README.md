# 🔍 Network Packet Sniffer

A Python-based network sniffer that captures and analyses live network traffic using raw sockets. Built for educational purposes to understand how data flows across a network and how packets are structured.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## ✨ Features

| Feature | Description |
|---|---|
| 📦 **Packet Capture** | Captures live IPv4 traffic using raw sockets |
| 🔬 **Protocol Parsing** | Decodes IP, TCP, UDP, and ICMP headers |
| 🎨 **Rich Terminal UI** | Colour-coded output with ANSI escape codes |
| 🔎 **Filtering** | Filter by protocol, host IP, or port number |
| 📊 **Live Statistics** | Session summary with protocol breakdown, top IPs, and top ports |
| 💾 **Logging** | Export captured packets to CSV or JSON-lines |
| 🔢 **Hex Dump** | Optional hex + ASCII dump of packet payloads |
| 🏷️ **Service Labels** | Identifies well-known ports (HTTP, HTTPS, DNS, SSH, etc.) |
| 🏁 **TCP Flag Badges** | Visual badges for SYN, ACK, FIN, RST, PSH, etc. |

---

## 📋 Prerequisites

- **Python 3.10+** (uses `match`-free syntax, so 3.10+ for type hints)
- **Administrator / Root privileges** (raw sockets require elevated permissions)
- No external dependencies — uses only the Python standard library

---

## 🚀 Quick Start

### 1. Run as Administrator

**Windows:**
```powershell
# Open PowerShell as Administrator, then:
python d:\Task1\sniffer.py
```

**Linux / macOS:**
```bash
sudo python3 sniffer.py
```

### 2. Capture with Filters

```bash
# Only TCP packets
python sniffer.py -p tcp

# Only DNS traffic (UDP port 53)
python sniffer.py -p udp --port 53

# Filter by specific host
python sniffer.py --host 192.168.1.1

# Capture exactly 50 packets with hex dump
python sniffer.py -c 50 -x

# Specify network interface (Windows)
python sniffer.py -i 192.168.1.100
```

### 3. Save to File

```bash
# Save as CSV
python sniffer.py -o capture.csv

# Save as JSON-lines
python sniffer.py -o capture.jsonl -f json
```

### 4. Stop Capture

Press **Ctrl+C** at any time. The sniffer will display a detailed session statistics summary before exiting.

---

## 📖 Command-Line Options

| Option | Description |
|---|---|
| `-p`, `--protocol` | Filter by protocol: `tcp`, `udp`, or `icmp` |
| `--host HOST` | Filter by source or destination IP |
| `--port PORT` | Filter by source or destination port |
| `-c`, `--count N` | Stop after capturing N packets (0 = unlimited) |
| `-x`, `--hexdump` | Show hex dump of payload data |
| `-i`, `--interface IP` | Bind to a specific interface IP (Windows) |
| `-o`, `--output FILE` | Log packets to a file |
| `-f`, `--output-format` | Output format: `csv` (default) or `json` |

---

## 🏗️ How It Works

```
┌─────────────────────────────────────────────────┐
│                Raw Socket                        │
│  (captures all IPv4 packets on the interface)    │
└──────────────────┬──────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────┐
│            IP Header Parser                      │
│  Version, IHL, TTL, Protocol, Src/Dst IP         │
└──────────────────┬──────────────────────────────┘
                   │
          ┌────────┼────────┐
          ▼        ▼        ▼
     ┌────────┐ ┌──────┐ ┌──────┐
     │  TCP   │ │ UDP  │ │ ICMP │
     │ Parser │ │Parser│ │Parser│
     └────┬───┘ └──┬───┘ └──┬───┘
          │        │        │
          └────────┼────────┘
                   ▼
     ┌─────────────────────────────┐
     │   Filter → Display → Log   │
     └─────────────────────────────┘
```

### Packet Structure (IPv4)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
│Version│  IHL  │    DSCP   │ECN│         Total Length              │
├───────┴───────┼───────────┴───┼───────────────────────────────────┤
│  Identification               │Flags│    Fragment Offset          │
├───────────────┼───────────────┼─────┴─────────────────────────────┤
│  Time to Live │   Protocol    │       Header Checksum             │
├───────────────┴───────────────┼───────────────────────────────────┤
│                       Source IP Address                            │
├───────────────────────────────────────────────────────────────────┤
│                    Destination IP Address                          │
└───────────────────────────────────────────────────────────────────┘
```

---

## 📊 Session Statistics Example

When you stop the sniffer (Ctrl+C), you'll see a summary like:

```
──────────────────────────────────────────────────────────────────
  📊  SESSION STATISTICS
──────────────────────────────────────────────────────────────────
  ⏱  Duration ............ 45.2 s
  📦 Total Packets ....... 1,247
  📏 Total Bytes ......... 892,410 (871.5 KB)
  ⚡ Packets/sec ......... 27.6
  📶 Throughput .......... 19.3 KB/s

  Protocol Breakdown:
    TCP        834  ( 66.9%)  █████████████
    UDP        389  ( 31.2%)  ██████
    ICMP        24  (  1.9%)  

  Top 5 Source IPs:
    192.168.1.100      →   523 packets
    10.0.0.1           →   201 packets
    ...
──────────────────────────────────────────────────────────────────
```

---

## ⚠️ Important Notes

1. **Administrator/Root required** — Raw sockets are a privileged operation
2. **Educational use only** — Sniffing network traffic on networks you don't own is illegal
3. **Windows** — Uses `SIO_RCVALL` for promiscuous mode; works on Windows 10+
4. **Linux** — Uses `PF_PACKET` with `SOCK_RAW` for raw Ethernet frames
5. **No external dependencies** — 100% Python standard library
