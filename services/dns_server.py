import socket
import struct
import threading
import subprocess
import time
import re
import os
import json

real_stats = {
    "total_queries": 0,
    "blocked_queries": 0,
    "query_log": [],
    "top_blocked_domains": {},
    "is_blocking_enabled": True,
    "ssai_enabled": True
}

BLOCKLIST = set()

def load_blocklists():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    blocklist_dir = os.path.join(base_dir, "blocklists", "smart-tv")
    
    if os.path.exists(blocklist_dir):
        for root, _, files in os.walk(blocklist_dir):
            for file in files:
                if file.endswith(".txt"):
                    filepath = os.path.join(root, file)
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                domain = line.replace("||", "").replace("^", "").strip()
                                if domain:
                                    BLOCKLIST.add(domain.lower())
    print(f"[DNS-Server] Loaded {len(BLOCKLIST)} real blocklist domains.")

load_blocklists()

def parse_domain(data):
    try:
        domain_parts = []
        idx = 12
        length = data[idx]
        while length != 0:
            idx += 1
            domain_parts.append(data[idx:idx+length].decode('utf-8', errors='ignore'))
            idx += length
            length = data[idx]
        return ".".join(domain_parts)
    except Exception:
        return ""

def build_dns_response(data, ip_result="0.0.0.0"):
    tx_id = data[:2]
    flags = b"\x81\x80"
    qdcount = data[4:6]
    ancount = b"\x00\x01"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"
    
    header = tx_id + flags + qdcount + ancount + nscount + arcount
    question = data[12:]
    
    answer_name = b"\xc0\x0c"
    answer_type_class = b"\x00\x01\x00\x01"
    ttl = struct.pack(">I", 60)
    rdlength = struct.pack(">H", 4)
    rdata = socket.inet_aton(ip_result)
    
    return header + question + answer_name + answer_type_class + ttl + rdlength + rdata

def forward_dns_query(data, upstream_ip="1.1.1.1", upstream_port=53):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(data, (upstream_ip, upstream_port))
        resp, _ = sock.recvfrom(512)
        sock.close()
        return resp
    except Exception:
        return None

def is_domain_blocked(domain):
    if not real_stats["is_blocking_enabled"]:
        return False
    domain = domain.lower()
    if domain in BLOCKLIST:
        return True
    for blocked in BLOCKLIST:
        if domain.endswith("." + blocked) or blocked in domain:
            return True
    return False

def get_real_connected_devices():
    devices = []
    try:
        output = subprocess.check_output("arp -a", shell=True, text=True, errors="ignore")
        lines = output.splitlines()
        for line in lines:
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})\s+(\w+)', line)
            if match:
                ip, mac, dev_type = match.groups()
                if ip.startswith("192.168.137.") and not ip.endswith(".1") and not ip.endswith(".255"):
                    devices.append({
                        "ip": ip,
                        "mac": mac.upper(),
                        "type": dev_type,
                        "name": f"Hotspot Device ({ip})",
                        "status": "Connected to Laptop Hotspot"
                    })
    except Exception as e:
        print(f"[DNS-Server] Error reading ARP table: {e}")
    return devices

def handle_dns_client(data, addr, server_socket):
    domain = parse_domain(data)
    if not domain:
        return

    real_stats["total_queries"] += 1
    client_ip = addr[0]
    timestamp = time.strftime("%H:%M:%S")

    if is_domain_blocked(domain):
        real_stats["blocked_queries"] += 1
        real_stats["top_blocked_domains"][domain] = real_stats["top_blocked_domains"].get(domain, 0) + 1
        
        log_entry = {
            "status": "BLOCKED",
            "domain": domain,
            "ip": client_ip,
            "time": timestamp
        }
        real_stats["query_log"].insert(0, log_entry)
        if len(real_stats["query_log"]) > 50:
            real_stats["query_log"].pop()
            
        print(f"[DNS Sinkhole] BLOCKED: {domain} from {client_ip}")
        response = build_dns_response(data, "0.0.0.0")
        server_socket.sendto(response, addr)
    else:
        log_entry = {
            "status": "ALLOWED",
            "domain": domain,
            "ip": client_ip,
            "time": timestamp
        }
        real_stats["query_log"].insert(0, log_entry)
        if len(real_stats["query_log"]) > 50:
            real_stats["query_log"].pop()

        response = forward_dns_query(data)
        if response:
            server_socket.sendto(response, addr)
        else:
            fallback_resp = build_dns_response(data, "0.0.0.0")
            server_socket.sendto(fallback_resp, addr)

def start_dns_server(host="0.0.0.0", port=53):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server_socket.bind((host, port))
        print("===================================================")
        print(f"[DNS-Server] REAL DNS Sinkhole Listening on UDP {host}:{port}")
        print("===================================================")
        while True:
            data, addr = server_socket.recvfrom(512)
            threading.Thread(target=handle_dns_client, args=(data, addr, server_socket), daemon=True).start()
    except Exception as e:
        print(f"[DNS-Server Warning] Could not bind to port {port}: {e}")

if __name__ == "__main__":
    start_dns_server()
