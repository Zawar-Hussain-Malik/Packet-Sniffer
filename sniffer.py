#!/usr/bin/env python3
"""
+================================================================+
|                    NETWORK PACKET SNIFFER                       |
|         Capture - Analyse - Understand Network Traffic          |
+================================================================+

A basic network sniffer built with Python raw sockets.
Captures live traffic and decodes IP, TCP, UDP, and ICMP headers.

[!] Requires Administrator / Root privileges to run.
"""

import socket
import struct
import sys
import os
import time
import argparse
import signal
import json
import csv
from datetime import datetime
from collections import defaultdict
from threading import Event

# ─────────────────────────────────────────────────────────────────
# ANSI colour helpers (Windows ≥ 10 / any modern terminal)
# ─────────────────────────────────────────────────────────────────
class Colors:
    """ANSI escape‑code palette for terminal output."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    ITALIC  = "\033[3m"

    # Foreground
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"

    # Background
    BG_RED    = "\033[41m"
    BG_GREEN  = "\033[42m"
    BG_BLUE   = "\033[44m"
    BG_CYAN   = "\033[46m"
    BG_YELLOW = "\033[43m"

    @staticmethod
    def enable_windows_ansi():
        """Enable virtual‑terminal processing on Windows 10+."""
        if os.name == "nt":
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(
                    kernel32.GetStdHandle(-11), 7  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
                )
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────
# Protocol number → human‑readable name mapping
# ─────────────────────────────────────────────────────────────────
PROTOCOL_MAP = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}

# Well‑known port → service name (subset)
SERVICE_MAP = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP-S", 68: "DHCP-C",
    80: "HTTP", 110: "POP3", 119: "NNTP", 123: "NTP",
    143: "IMAP", 161: "SNMP", 194: "IRC", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1433: "MSSQL", 1434: "MSSQL-B", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# TCP flag bitmasks
TCP_FLAGS = {
    "FIN": 0x01, "SYN": 0x02, "RST": 0x04,
    "PSH": 0x08, "ACK": 0x10, "URG": 0x20,
    "ECE": 0x40, "CWR": 0x80,
}

# ICMP type → description
ICMP_TYPES = {
    0: "Echo Reply", 3: "Destination Unreachable",
    4: "Source Quench", 5: "Redirect",
    8: "Echo Request", 9: "Router Advertisement",
    10: "Router Solicitation", 11: "Time Exceeded",
    12: "Parameter Problem", 13: "Timestamp Request",
    14: "Timestamp Reply", 17: "Address Mask Request",
    18: "Address Mask Reply",
}


# ─────────────────────────────────────────────────────────────────
# Packet Parsers
# ─────────────────────────────────────────────────────────────────
def parse_ip_header(raw: bytes) -> dict | None:
    """Parse the IPv4 header (first 20+ bytes of a captured packet)."""
    if len(raw) < 20:
        return None

    iph = struct.unpack("!BBHHHBBH4s4s", raw[:20])

    version_ihl = iph[0]
    version     = version_ihl >> 4
    ihl         = version_ihl & 0x0F          # header length in 32‑bit words
    header_len  = ihl * 4                      # header length in bytes

    if version != 4:
        return None

    return {
        "version":     version,
        "ihl":         ihl,
        "header_len":  header_len,
        "tos":         iph[1],
        "total_len":   iph[2],
        "id":          iph[3],
        "flags_frag":  iph[4],
        "ttl":         iph[5],
        "protocol":    iph[6],
        "checksum":    iph[7],
        "src_ip":      socket.inet_ntoa(iph[8]),
        "dst_ip":      socket.inet_ntoa(iph[9]),
    }


def parse_tcp_header(raw: bytes, offset: int) -> dict | None:
    """Parse a TCP header starting at *offset* bytes into *raw*."""
    if len(raw) < offset + 20:
        return None

    tcph = struct.unpack("!HHLLBBHHH", raw[offset:offset + 20])
    data_offset = (tcph[4] >> 4) * 4  # TCP header length in bytes

    raw_flags = tcph[5]
    flags = [name for name, mask in TCP_FLAGS.items() if raw_flags & mask]

    return {
        "src_port":    tcph[0],
        "dst_port":    tcph[1],
        "seq":         tcph[2],
        "ack":         tcph[3],
        "data_offset": data_offset,
        "flags":       flags,
        "window":      tcph[6],
        "checksum":    tcph[7],
        "urg_ptr":     tcph[8],
        "payload_offset": offset + data_offset,
    }


def parse_udp_header(raw: bytes, offset: int) -> dict | None:
    """Parse a UDP header starting at *offset*."""
    if len(raw) < offset + 8:
        return None

    udph = struct.unpack("!HHHH", raw[offset:offset + 8])
    return {
        "src_port":  udph[0],
        "dst_port":  udph[1],
        "length":    udph[2],
        "checksum":  udph[3],
        "payload_offset": offset + 8,
    }


def parse_icmp_header(raw: bytes, offset: int) -> dict | None:
    """Parse an ICMP header starting at *offset*."""
    if len(raw) < offset + 8:
        return None

    icmph = struct.unpack("!BBHI", raw[offset:offset + 8])
    return {
        "type":     icmph[0],
        "code":     icmph[1],
        "checksum": icmph[2],
        "rest":     icmph[3],
        "type_desc": ICMP_TYPES.get(icmph[0], f"Unknown({icmph[0]})"),
    }


# ─────────────────────────────────────────────────────────────────
# Pretty Hex‑dump
# ─────────────────────────────────────────────────────────────────
def hexdump(data: bytes, length: int = 16, indent: str = "  ") -> str:
    """Return a classic hex‑dump string (offset | hex | ASCII)."""
    lines = []
    for i in range(0, min(len(data), 256), length):  # cap at 256 bytes
        chunk = data[i:i + length]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{indent}{Colors.GRAY}{i:04x}{Colors.RESET}  "
                      f"{Colors.CYAN}{hex_part:<{length * 3}}{Colors.RESET} "
                      f"{Colors.DIM}{ascii_part}{Colors.RESET}")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────
# Display helpers
# ─────────────────────────────────────────────────────────────────
def service_label(port: int) -> str:
    """Map a port number to a service label (if known)."""
    svc = SERVICE_MAP.get(port)
    return f" ({svc})" if svc else ""


def protocol_color(proto_name: str) -> str:
    """Pick a colour for the protocol tag."""
    return {
        "TCP":  Colors.GREEN,
        "UDP":  Colors.BLUE,
        "ICMP": Colors.YELLOW,
    }.get(proto_name, Colors.MAGENTA)


def flag_badges(flags: list[str]) -> str:
    """Render TCP flags as colourful badges."""
    badge_colors = {
        "SYN": Colors.BG_GREEN,
        "ACK": Colors.BG_BLUE,
        "FIN": Colors.BG_RED,
        "RST": Colors.BG_RED,
        "PSH": Colors.BG_CYAN,
        "URG": Colors.BG_YELLOW,
    }
    badges = []
    for f in flags:
        bg = badge_colors.get(f, "")
        badges.append(f"{bg}{Colors.WHITE}{Colors.BOLD} {f} {Colors.RESET}")
    return " ".join(badges)


# ─────────────────────────────────────────────────────────────────
# Statistics Tracker
# ─────────────────────────────────────────────────────────────────
class Stats:
    """Accumulates simple traffic statistics."""

    def __init__(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts = defaultdict(int)
        self.top_sources = defaultdict(int)
        self.top_destinations = defaultdict(int)
        self.port_hits = defaultdict(int)
        self.start_time = time.time()

    def record(self, ip: dict, proto_name: str, raw_len: int,
               src_port: int = 0, dst_port: int = 0):
        self.total_packets += 1
        self.total_bytes += raw_len
        self.protocol_counts[proto_name] += 1
        self.top_sources[ip["src_ip"]] += 1
        self.top_destinations[ip["dst_ip"]] += 1
        if src_port:
            self.port_hits[src_port] += 1
        if dst_port:
            self.port_hits[dst_port] += 1

    def elapsed(self) -> float:
        return time.time() - self.start_time

    def summary(self) -> str:
        """Build a colourful summary block."""
        elapsed = self.elapsed()
        pps = self.total_packets / elapsed if elapsed > 0 else 0
        bps = self.total_bytes / elapsed if elapsed > 0 else 0

        sep = f"{Colors.GRAY}{'-' * 62}{Colors.RESET}"
        lines = [
            "",
            sep,
            f"  {Colors.BOLD}{Colors.CYAN}[*]  SESSION STATISTICS{Colors.RESET}",
            sep,
            f"  [T] Duration ............ {elapsed:,.1f} s",
            f"  [P] Total Packets ....... {self.total_packets:,}",
            f"  [B] Total Bytes ......... {self.total_bytes:,} ({self.total_bytes / 1024:,.1f} KB)",
            f"  [S] Packets/sec ......... {pps:,.1f}",
            f"  [R] Throughput .......... {bps / 1024:,.1f} KB/s",
            "",
            f"  {Colors.BOLD}Protocol Breakdown:{Colors.RESET}",
        ]
        for proto, count in sorted(self.protocol_counts.items(),
                                    key=lambda x: -x[1]):
            pct = count / self.total_packets * 100 if self.total_packets else 0
            bar_len = int(pct / 5)
            bar = f"{protocol_color(proto)}{'█' * bar_len}{Colors.RESET}"
            lines.append(f"    {proto:<8} {count:>6}  ({pct:5.1f}%)  {bar}")

        lines.append("")
        lines.append(f"  {Colors.BOLD}Top 5 Source IPs:{Colors.RESET}")
        for ip, cnt in sorted(self.top_sources.items(),
                               key=lambda x: -x[1])[:5]:
            lines.append(f"    {ip:<18} → {cnt:>5} packets")

        lines.append("")
        lines.append(f"  {Colors.BOLD}Top 5 Destination IPs:{Colors.RESET}")
        for ip, cnt in sorted(self.top_destinations.items(),
                               key=lambda x: -x[1])[:5]:
            lines.append(f"    {ip:<18} → {cnt:>5} packets")

        lines.append("")
        lines.append(f"  {Colors.BOLD}Top 5 Ports:{Colors.RESET}")
        for port, cnt in sorted(self.port_hits.items(),
                                 key=lambda x: -x[1])[:5]:
            lines.append(f"    {port:<6}{service_label(port):<14} → {cnt:>5} hits")

        lines.append(sep)
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────
# Packet Logger (CSV / JSON)
# ─────────────────────────────────────────────────────────────────
class PacketLogger:
    """Optional file logger — writes each packet as CSV or JSON‑lines."""

    def __init__(self, path: str | None, fmt: str = "csv"):
        self.path = path
        self.fmt = fmt
        self._fh = None
        self._writer = None

        if path:
            self._fh = open(path, "w", newline="", encoding="utf-8")
            if fmt == "csv":
                self._writer = csv.writer(self._fh)
                self._writer.writerow([
                    "timestamp", "protocol", "src_ip", "src_port",
                    "dst_ip", "dst_port", "length", "info",
                ])

    def log(self, ts: str, proto: str, src_ip: str, src_port: int,
            dst_ip: str, dst_port: int, length: int, info: str):
        if not self._fh:
            return
        if self.fmt == "csv":
            self._writer.writerow([
                ts, proto, src_ip, src_port, dst_ip, dst_port, length, info,
            ])
        else:
            json.dump({
                "timestamp": ts, "protocol": proto,
                "src_ip": src_ip, "src_port": src_port,
                "dst_ip": dst_ip, "dst_port": dst_port,
                "length": length, "info": info,
            }, self._fh)
            self._fh.write("\n")
        self._fh.flush()

    def close(self):
        if self._fh:
            self._fh.close()


# ─────────────────────────────────────────────────────────────────
# Core Sniffer
# ─────────────────────────────────────────────────────────────────
class NetworkSniffer:
    """
    Captures IPv4 packets using raw sockets and decodes their headers.

    Supports:
      • TCP, UDP, ICMP header parsing
      • Protocol / IP / port filtering
      • Hex‑dump of payload
      • Live statistics
      • CSV / JSON packet logging
    """

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.stats = Stats()
        self.stop_event = Event()
        self.logger = PacketLogger(args.output, args.output_format)
        self.packet_count = 0

    # ── Socket setup ──────────────────────────────────────────────
    def _create_socket(self) -> socket.socket:
        """Create and configure a raw socket appropriate for the OS."""
        if os.name == "nt":
            # Windows: raw socket bound to a local interface
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            host = self.args.interface or socket.gethostbyname(socket.gethostname())
            sock.bind((host, 0))
            # Include IP headers
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # Enable promiscuous mode
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            # Linux: PF_PACKET gives Ethernet frames; we skip the 14‑byte
            # Ethernet header later.  macOS doesn't support PF_PACKET, so
            # fall back to IPPROTO_IP on macOS.
            try:
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                     socket.ntohs(0x0003))  # ETH_P_ALL
                self._is_linux_raw = True
            except (AttributeError, OSError):
                # macOS / other UNIX
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                     socket.IPPROTO_IP)
                self._is_linux_raw = False
        return sock

    # ── Filtering ─────────────────────────────────────────────────
    def _passes_filter(self, ip: dict, proto_name: str,
                       src_port: int = 0, dst_port: int = 0) -> bool:
        """Return True if the packet matches the user‑supplied filters."""
        if self.args.protocol and proto_name.lower() != self.args.protocol.lower():
            return False
        if self.args.host:
            if ip["src_ip"] != self.args.host and ip["dst_ip"] != self.args.host:
                return False
        if self.args.port:
            if src_port != self.args.port and dst_port != self.args.port:
                return False
        return True

    # ── Display a single packet ──────────────────────────────────
    def _display_packet(self, pkt_num: int, ts: str, ip: dict,
                        proto_name: str, detail: dict | None,
                        raw: bytes):
        C = Colors
        pc = protocol_color(proto_name)

        # Packet number + timestamp
        print(f"\n{C.BOLD}{C.WHITE}{'=' * 62}{C.RESET}")
        print(f"  {C.BOLD}#{pkt_num:<5}{C.RESET}  "
              f"{C.DIM}{ts}{C.RESET}  "
              f"{pc}{C.BOLD} {proto_name} {C.RESET}")

        # IP layer
        print(f"  {C.BOLD}IP{C.RESET}   {C.GREEN}{ip['src_ip']}{C.RESET}"
              f"  →  {C.RED}{ip['dst_ip']}{C.RESET}"
              f"  │ TTL={ip['ttl']}  Len={ip['total_len']}"
              f"  ID=0x{ip['id']:04X}")

        src_port = dst_port = 0
        info = ""

        if proto_name == "TCP" and detail:
            src_port = detail["src_port"]
            dst_port = detail["dst_port"]
            payload_len = len(raw) - detail["payload_offset"]
            fb = flag_badges(detail["flags"])
            info = f"Seq={detail['seq']}  Ack={detail['ack']}  Win={detail['window']}  Flags=[{', '.join(detail['flags'])}]"
            print(f"  {C.BOLD}TCP{C.RESET}  "
                  f":{src_port}{service_label(src_port)}  →  "
                  f":{dst_port}{service_label(dst_port)}")
            print(f"       Seq={detail['seq']}  Ack={detail['ack']}  "
                  f"Win={detail['window']}  Payload={payload_len}B")
            print(f"       Flags: {fb}")

        elif proto_name == "UDP" and detail:
            src_port = detail["src_port"]
            dst_port = detail["dst_port"]
            info = f"Len={detail['length']}"
            print(f"  {C.BOLD}UDP{C.RESET}  "
                  f":{src_port}{service_label(src_port)}  →  "
                  f":{dst_port}{service_label(dst_port)}"
                  f"  │ Len={detail['length']}")

        elif proto_name == "ICMP" and detail:
            info = f"Type={detail['type']} ({detail['type_desc']})  Code={detail['code']}"
            print(f"  {C.BOLD}ICMP{C.RESET} Type={detail['type']} "
                  f"({C.YELLOW}{detail['type_desc']}{C.RESET})  "
                  f"Code={detail['code']}")
        else:
            info = f"Protocol #{ip['protocol']}"
            print(f"  {C.BOLD}PROTO{C.RESET} #{ip['protocol']}")

        # Optional hex dump
        if self.args.hexdump:
            start = ip["header_len"]
            if detail and "payload_offset" in detail:
                start = detail["payload_offset"]
            payload = raw[start:]
            if payload:
                print(f"  {C.BOLD}Payload ({len(payload)} bytes):{C.RESET}")
                print(hexdump(payload))

        # Log
        self.logger.log(ts, proto_name, ip["src_ip"], src_port,
                        ip["dst_ip"], dst_port, ip["total_len"], info)

    # ── Main capture loop ────────────────────────────────────────
    def run(self):
        """Start capturing packets until interrupted or the count limit is reached."""
        C = Colors
        C.enable_windows_ansi()

        # Banner
        print(f"""
{C.BOLD}{C.CYAN}+==============================================================+
|              [*]  NETWORK  PACKET  SNIFFER  [*]              |
+==============================================================+{C.RESET}
{C.DIM}  Capture - Decode - Analyse -- IPv4 / TCP / UDP / ICMP
  Press Ctrl+C to stop and view session statistics.{C.RESET}
""")

        # Show active filters
        if self.args.protocol or self.args.host or self.args.port:
            filters = []
            if self.args.protocol:
                filters.append(f"protocol={self.args.protocol.upper()}")
            if self.args.host:
                filters.append(f"host={self.args.host}")
            if self.args.port:
                filters.append(f"port={self.args.port}")
            print(f"  {C.BOLD}Active Filters:{C.RESET} {', '.join(filters)}")

        if self.args.output:
            print(f"  {C.BOLD}Logging to:{C.RESET} {self.args.output} ({self.args.output_format})")

        if self.args.count:
            print(f"  {C.BOLD}Capture limit:{C.RESET} {self.args.count} packets")

        print(f"\n{C.GRAY}{'-' * 62}{C.RESET}")
        print(f"  {C.BOLD}Waiting for packets ...{C.RESET}\n")

        # Create raw socket
        try:
            sock = self._create_socket()
        except PermissionError:
            print(f"\n{C.RED}{C.BOLD}  [X] Permission denied!{C.RESET}")
            print(f"  {C.YELLOW}Run this script as Administrator (Windows) or root (Linux/macOS).{C.RESET}\n")
            sys.exit(1)
        except OSError as e:
            print(f"\n{C.RED}{C.BOLD}  [X] Socket error: {e}{C.RESET}")
            sys.exit(1)

        sock.settimeout(1.0)  # allow periodic check for stop_event

        # Graceful shutdown
        def _sigint_handler(sig, frame):
            self.stop_event.set()

        signal.signal(signal.SIGINT, _sigint_handler)

        try:
            while not self.stop_event.is_set():
                # Check packet limit
                if self.args.count and self.packet_count >= self.args.count:
                    break

                # Receive
                try:
                    raw, addr = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    continue

                # On Linux PF_PACKET sockets we get an Ethernet frame;
                # skip the 14‑byte Ethernet header to reach the IP header.
                eth_offset = 0
                if hasattr(self, "_is_linux_raw") and self._is_linux_raw:
                    if len(raw) < 14:
                        continue
                    # EtherType at bytes 12‑13; 0x0800 = IPv4
                    ether_type = struct.unpack("!H", raw[12:14])[0]
                    if ether_type != 0x0800:
                        continue
                    eth_offset = 14

                packet_data = raw[eth_offset:]

                # Parse IP header
                ip = parse_ip_header(packet_data)
                if ip is None:
                    continue

                proto_num = ip["protocol"]
                proto_name = PROTOCOL_MAP.get(proto_num, f"OTHER({proto_num})")
                detail = None
                src_port = dst_port = 0

                if proto_num == 6:   # TCP
                    detail = parse_tcp_header(packet_data, ip["header_len"])
                    if detail:
                        src_port = detail["src_port"]
                        dst_port = detail["dst_port"]
                elif proto_num == 17:  # UDP
                    detail = parse_udp_header(packet_data, ip["header_len"])
                    if detail:
                        src_port = detail["src_port"]
                        dst_port = detail["dst_port"]
                elif proto_num == 1:   # ICMP
                    detail = parse_icmp_header(packet_data, ip["header_len"])

                # Apply filters
                if not self._passes_filter(ip, proto_name, src_port, dst_port):
                    continue

                self.packet_count += 1
                ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                self.stats.record(ip, proto_name, len(raw), src_port, dst_port)
                self._display_packet(self.packet_count, ts, ip,
                                     proto_name, detail, packet_data)

        finally:
            # Cleanup
            if os.name == "nt":
                try:
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except Exception:
                    pass
            sock.close()
            self.logger.close()

            # Print statistics
            if self.stats.total_packets > 0:
                print(self.stats.summary())
            else:
                print(f"\n  {C.YELLOW}No packets captured.{C.RESET}")


            print(f"\n  {C.GREEN}{C.BOLD}[OK] Sniffer stopped.{C.RESET}\n")


# ─────────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Network Packet Sniffer -- capture & analyse live traffic",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  python sniffer.py                          # capture all traffic
  python sniffer.py -p tcp                   # only TCP packets
  python sniffer.py -p udp --port 53         # DNS traffic only
  python sniffer.py --host 192.168.1.1       # filter by host
  python sniffer.py -c 100 -x               # capture 100 packets with hex dump
  python sniffer.py -o capture.csv           # log packets to CSV
  python sniffer.py -o capture.jsonl -f json # log packets to JSON-lines
        """,
    )
    parser.add_argument("-p", "--protocol", choices=["tcp", "udp", "icmp"],
                        help="Filter by protocol (tcp, udp, icmp)")
    parser.add_argument("--host", type=str,
                        help="Filter by source OR destination IP address")
    parser.add_argument("--port", type=int,
                        help="Filter by source OR destination port")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Stop after N packets (0 = unlimited)")
    parser.add_argument("-x", "--hexdump", action="store_true",
                        help="Show hex dump of packet payload")
    parser.add_argument("-i", "--interface", type=str, default="",
                        help="IP address of the interface to sniff on (Windows)")
    parser.add_argument("-o", "--output", type=str, default=None,
                        help="Save captured packets to a file")
    parser.add_argument("-f", "--output-format", choices=["csv", "json"],
                        default="csv",
                        help="Output file format (default: csv)")
    args = parser.parse_args()

    sniffer = NetworkSniffer(args)
    sniffer.run()


if __name__ == "__main__":
    main()
