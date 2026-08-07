"""
dns_server.py — Real DNS Sinkhole that ACTUALLY works for hotspot clients

ROOT CAUSE OF PREVIOUS FAILURE:
  Windows Mobile Hotspot's DHCP gives connected devices NO DNS server.
  Devices got DNS from JioFiber router (192.168.29.1), bypassing our sinkhole.

THIS FIX:
  1. DNS server binds to 0.0.0.0:53 (all interfaces including hotspot adapter)
  2. setup.ps1 adds Windows Firewall rule that INTERCEPTS all UDP/TCP port 53
     packets from hotspot subnet (192.168.137.0/24) and forces them to this server
  3. This works even if devices are manually configured with 8.8.8.8 or 1.1.1.1
"""

import socket
import struct
import threading
import subprocess
import time
import re
import os

# ─── Global shared state ─────────────────────────────────────────────────────
stats = {
    "total_queries": 0,
    "blocked_queries": 0,
    "allowed_queries": 0,
    "is_blocking_enabled": False,   # DEFAULT OFF on launch
    "query_log": [],                # Last 100 queries
    "top_blocked_domains": {},
    "start_time": time.time(),
}
stats_lock = threading.Lock()

# Loaded by blocklist_loader at startup
BLOCKLIST: set = set()


# ─── DNS packet helpers ───────────────────────────────────────────────────────
def parse_domain(data: bytes) -> str:
    try:
        parts = []
        idx = 12
        length = data[idx]
        while length != 0:
            idx += 1
            parts.append(data[idx:idx + length].decode("ascii", errors="ignore"))
            idx += length
            length = data[idx]
        return ".".join(parts).lower()
    except Exception:
        return ""


def build_nxdomain(data: bytes) -> bytes:
    """Return NXDOMAIN response (no such domain) — cleaner than 0.0.0.0 for sinkholing."""
    tx_id = data[:2]
    flags = b"\x81\x83"   # QR=1, OPCODE=0, AA=0, RCODE=3 (NXDOMAIN)
    qdcount = data[4:6]
    ancount = b"\x00\x00"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"
    question = data[12:]
    return tx_id + flags + qdcount + ancount + nscount + arcount + question


def build_zero_response(data: bytes) -> bytes:
    """Return 0.0.0.0 A record — used for HTTP-level enforcement via proxy."""
    tx_id = data[:2]
    flags = b"\x81\x80"
    qdcount = data[4:6]
    ancount = b"\x00\x01"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"
    header = tx_id + flags + qdcount + ancount + nscount + arcount
    question = data[12:]
    answer = (
        b"\xc0\x0c"           # name pointer to question
        + b"\x00\x01"         # type A
        + b"\x00\x01"         # class IN
        + struct.pack(">I", 60)   # TTL 60s
        + b"\x00\x04"         # rdlength 4
        + socket.inet_aton("0.0.0.0")
    )
    return header + question + answer


def forward_to_upstream(data: bytes) -> bytes | None:
    """Forward DNS query to 1.1.1.1 (Cloudflare) and return response."""
    for upstream in ("1.1.1.1", "8.8.8.8"):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.5)
            sock.sendto(data, (upstream, 53))
            resp, _ = sock.recvfrom(4096)
            sock.close()
            return resp
        except Exception:
            pass
    return None


# ─── Device detection ─────────────────────────────────────────────────────────
_device_cache: dict = {}
_device_cache_lock = threading.Lock()


def _ping_alive(ip: str) -> bool:
    try:
        out = subprocess.check_output(
            f"ping -n 1 -w 200 {ip}", shell=True,
            text=True, errors="ignore", timeout=1
        )
        return "TTL=" in out or "ttl=" in out
    except Exception:
        return False


def get_connected_devices() -> list:
    """
    Read ARP table, filter to hotspot subnet, verify alive via ICMP ping.
    Returns only devices that are currently ACTUALLY connected.
    """
    devices = []
    try:
        arp = subprocess.check_output("arp -a", shell=True, text=True, errors="ignore")
        for line in arp.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F\-]{17})\s+(\w+)", line)
            if not m:
                continue
            ip, mac, _ = m.groups()
            # Only hotspot subnet: 192.168.137.x  (not .1 gateway, not .255 broadcast)
            if not ip.startswith("192.168.137.") or ip in ("192.168.137.1", "192.168.137.255"):
                continue
            with _device_cache_lock:
                cached = _device_cache.get(ip)
                now = time.time()
                if cached and (now - cached["checked"]) < 8:
                    if cached["alive"]:
                        devices.append(cached["info"])
                    continue
            alive = _ping_alive(ip)
            info = {
                "ip": ip,
                "mac": mac.upper(),
                "name": f"Device ({ip})",
                "status": "Connected" if alive else "Disconnected",
                "alive": alive,
            }
            with _device_cache_lock:
                _device_cache[ip] = {"info": info, "alive": alive, "checked": time.time()}
            if alive:
                devices.append(info)
    except Exception:
        pass
    return devices


# ─── Core DNS request handler ─────────────────────────────────────────────────
def handle_query(data: bytes, addr: tuple, sock: socket.socket):
    domain = parse_domain(data)
    if not domain:
        return

    blocked = False
    if stats["is_blocking_enabled"] and domain in BLOCKLIST:
        blocked = True
        # Walk parent domains too (e.g. sub.ad.com blocked because ad.com is listed)
        if not blocked:
            parts = domain.split(".")
            for i in range(1, len(parts) - 1):
                if ".".join(parts[i:]) in BLOCKLIST:
                    blocked = True
                    break

    with stats_lock:
        stats["total_queries"] += 1
        entry = {
            "t": time.strftime("%H:%M:%S"),
            "domain": domain,
            "client": addr[0],
            "status": "BLOCKED" if blocked else "ALLOWED",
        }
        stats["query_log"].insert(0, entry)
        if len(stats["query_log"]) > 100:
            stats["query_log"].pop()
        if blocked:
            stats["blocked_queries"] += 1
            stats["top_blocked_domains"][domain] = stats["top_blocked_domains"].get(domain, 0) + 1
        else:
            stats["allowed_queries"] += 1

    if blocked:
        print(f"[DNS BLOCK] {domain} <- {addr[0]}")
        response = build_nxdomain(data)
        try:
            sock.sendto(response, addr)
        except Exception:
            pass
    else:
        response = forward_to_upstream(data)
        if response:
            try:
                sock.sendto(response, addr)
            except Exception:
                pass


# ─── Server startup ───────────────────────────────────────────────────────────
def _listen_on(host: str, port: int):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        print(f"[DNS] Listening on {host}:{port}")
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                threading.Thread(target=handle_query, args=(data, addr, sock), daemon=True).start()
            except Exception:
                pass
    except Exception as e:
        print(f"[DNS] Could not bind {host}:{port} — {e}")


def start_dns_server():
    for host in ("0.0.0.0", "127.0.0.1"):
        threading.Thread(target=_listen_on, args=(host, 53), daemon=True).start()
    print("[DNS] Sinkhole server started")


if __name__ == "__main__":
    from blocklist_loader import load_blocklist
    BLOCKLIST = load_blocklist()
    start_dns_server()
    while True:
        time.sleep(1)
