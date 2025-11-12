#!/usr/bin/env python3
"""
network_scanner.py

Async, configurable network scanner with simple anomaly detection and JSON/CSV export.

Usage examples:
  sudo python3 network_scanner.py --network 192.168.1.0/24 --mode arp
  python3 network_scanner.py --hosts 192.168.1.10 192.168.1.20 --ports 22,80,443,8080
"""

import argparse
import asyncio
import csv
import ipaddress
import json
import socket
import sys
import time
from collections import defaultdict
from typing import List, Dict, Any

# Optional import: scapy for ARP discovery
try:
    from scapy.all import ARP, Ether, srp, conf  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

# ---------- Configuration ----------
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 139, 143, 161, 162, 389, 443, 445,
    587, 631, 636, 993, 995, 3306, 3389, 5900, 8080, 8443
]
# Add more common ports if desired

# ---------- Utilities ----------
def now_ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

# ---------- Discovery ----------
def arp_discover(network_cidr: str, timeout: int = 2) -> List[str]:
    """
    ARP discovery using scapy. Requires root privileges on most platforms.
    Returns list of IP strings.
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy not available for ARP discovery.")
    conf.verb = 0
    net = network_cidr
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=net)
    ans, _ = srp(ether/arp, timeout=timeout, retry=1)
    hosts = [rcv.psrc for snd, rcv in ans]
    return hosts

async def icmp_ping(ip: str, timeout: float = 1.0) -> bool:
    """
    Non-privileged ICMP check using a TCP connect to port 80 or 443 as a fallback,
    because raw ICMP may require privileges.
    Returns True if host appears up.
    """
    # Try a tiny TCP connection to common ports as a reachability check
    for p in (80, 443, 22):
        try:
            fut = asyncio.open_connection(ip, p)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            pass
    return False

async def ping_sweep(network: str, concurrency: int = 200) -> List[str]:
    """
    Ping sweep over an IPv4 network using asyncio-based TCP reachability checks.
    """
    net = ipaddress.ip_network(network, strict=False)
    ips = [str(ip) for ip in net.hosts()]
    alive = []
    sem = asyncio.Semaphore(concurrency)

    async def worker(ip):
        async with sem:
            up = await icmp_ping(ip)
            if up:
                alive.append(ip)

    tasks = [worker(ip) for ip in ips]
    await asyncio.gather(*tasks)
    return alive

# ---------- Port scanning ----------
async def tcp_connect_scan(ip: str, ports: List[int], timeout: float = 1.0, concurrency: int = 400) -> Dict[int, Dict[str, Any]]:
    """
    Asynchronous TCP connect scan + banner grab.
    Returns dict: port -> {open: bool, banner: str or None, latency_ms: float}
    """
    results = {}
    sem = asyncio.Semaphore(concurrency)

    async def probe_port(port):
        start = time.time()
        async with sem:
            try:
                fut = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(fut, timeout=timeout)
                latency = (time.time() - start) * 1000.0
                banner = None
                # Try to grab a short banner (non-blocking)
                try:
                    writer.write(b"\r\n")
                    await writer.drain()
                    await asyncio.sleep(0.1)
                    n = await asyncio.wait_for(reader.read(1024), timeout=0.2)
                    if n:
                        try:
                            banner = n.decode(errors="ignore").strip()
                        except Exception:
                            banner = repr(n)
                except Exception:
                    pass
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
                results[port] = {"open": True, "banner": banner, "latency_ms": round(latency, 2)}
            except Exception:
                results[port] = {"open": False, "banner": None, "latency_ms": None}

    tasks = [probe_port(p) for p in ports]
    await asyncio.gather(*tasks)
    return results

# ---------- Heuristics / Anomaly detection ----------
def simple_anomaly_score(scan_result: Dict[str, Any], common_ports=DEFAULT_PORTS) -> Dict[str, Any]:
    """
    Very simple heuristic scoring:
      - More open ports -> higher score
      - Uncommon open ports (not in common_ports) increase score
    Returns dict with 'score' and 'notes'.
    """
    host_open_ports = []
    for p, info in scan_result["ports"].items():
        if info.get("open"):
            host_open_ports.append(int(p))

    score = 0.0
    notes = []
    n_open = len(host_open_ports)
    score += n_open * 1.0
    if n_open == 0:
        notes.append("No open ports detected.")
    else:
        uncommon = [p for p in host_open_ports if p not in common_ports]
        if uncommon:
            score += len(uncommon) * 2.0
            notes.append(f"Uncommon open ports: {uncommon}")
        if 22 in host_open_ports and 22 not in common_ports:
            notes.append("SSH open.")
    # Normalize to 0-10-ish
    score = min(score, 10.0)
    return {"score": round(score, 2), "notes": notes, "open_ports": host_open_ports}

# ---------- Orchestrator ----------
class NetworkScanner:
    def __init__(self, network=None, hosts: List[str] = None, ports: List[int] = None,
                 use_arp: bool = True, concurrency: int = 400, timeout: float = 1.0):
        self.network = network
        self.hosts = hosts or []
        self.ports = ports or DEFAULT_PORTS
        self.use_arp = use_arp
        self.concurrency = concurrency
        self.timeout = timeout
        self.results = {}

    async def discover(self):
        if self.hosts:
            print(f"[{now_ts()}] Using provided hosts: {self.hosts}")
            return self.hosts
        if self.network is None:
            raise ValueError("Either network CIDR or hosts must be provided.")
        # Try ARP first for local networks
        if self.use_arp and SCAPY_AVAILABLE:
            try:
                print(f"[{now_ts()}] Running ARP discovery on {self.network} (scapy)")
                hosts = arp_discover(self.network)
                print(f"[{now_ts()}] ARP discovered {len(hosts)} hosts")
                if hosts:
                    self.hosts = hosts
                    return hosts
            except Exception as e:
                print(f"[{now_ts()}] ARP discovery failed: {e} — falling back to ping sweep")
        # Fallback to ping sweep
        print(f"[{now_ts()}] Running ping sweep on {self.network}")
        hosts = await ping_sweep(self.network, concurrency=min(self.concurrency, 500))
        print(f"[{now_ts()}] Ping sweep discovered {len(hosts)} hosts")
        self.hosts = hosts
        return hosts

    async def scan_host(self, ip: str):
        # Run port scan
        ports_sorted = sorted(set(self.ports))
        port_map = await tcp_connect_scan(ip, ports_sorted, timeout=self.timeout, concurrency=self.concurrency)
        # Build host result
        host_res = {
            "ip": ip,
            "ports": {str(p): port_map.get(p, {"open": False, "banner": None, "latency_ms": None}) for p in ports_sorted},
            "scanned_at": now_ts()
        }
        # Anomaly heuristics
        host_res["anomaly"] = simple_anomaly_score(host_res)
        self.results[ip] = host_res
        print(f"[{now_ts()}] Scanned {ip}: {len([p for p in host_res['ports'] if host_res['ports'][p]['open']])} open ports")
        return host_res

    async def run(self):
        hosts = await self.discover()
        if not hosts:
            print(f"[{now_ts()}] No hosts found to scan.")
            return {}
        print(f"[{now_ts()}] Scanning {len(hosts)} hosts with up to {self.concurrency} concurrency...")
        # Cap concurrency of host-level tasks
        sem = asyncio.Semaphore(self.concurrency)
        async def host_worker(ip):
            async with sem:
                return await self.scan_host(ip)
        tasks = [host_worker(ip) for ip in hosts]
        await asyncio.gather(*tasks)
        return self.results

    def export_json(self, path="scan_results.json"):
        with open(path, "w") as f:
            json.dump({"scanned_at": now_ts(), "results": self.results}, f, indent=2)
        print(f"[{now_ts()}] Exported JSON -> {path}")

    def export_csv(self, path="scan_results.csv"):
        # CSV: host, port, open, banner, latency_ms, anomaly_score, notes
        rows = []
        for ip, info in self.results.items():
            anomaly = info.get("anomaly", {})
            for port, pinfo in info["ports"].items():
                rows.append({
                    "host": ip,
                    "port": port,
                    "open": pinfo["open"],
                    "banner": pinfo["banner"],
                    "latency_ms": pinfo["latency_ms"],
                    "anomaly_score": anomaly.get("score"),
                    "anomaly_notes": "; ".join(anomaly.get("notes", []))
                })
        fieldnames = ["host", "port", "open", "banner", "latency_ms", "anomaly_score", "anomaly_notes"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        print(f"[{now_ts()}] Exported CSV -> {path}")

# ---------- CLI ----------
def parse_ports(s: str) -> List[int]:
    parts = s.split(",")
    ports = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if "-" in p:
            a,b = p.split("-")
            ports.extend(range(int(a), int(b)+1))
        else:
            ports.append(int(p))
    return sorted(set(ports))

def main():
    parser = argparse.ArgumentParser(description="Async Network Scanner (authorized use only).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--network", "-n", help="Target network in CIDR (e.g., 192.168.1.0/24)")
    group.add_argument("--hosts", "-H", nargs="+", help="Explicit host IPs to scan")
    parser.add_argument("--mode", choices=["arp", "ping"], default="arp",
                        help="Discovery mode. ARP is fast for LANs (requires scapy/root). Ping uses TCP probes.")
    parser.add_argument("--ports", "-p", default=",".join(map(str, DEFAULT_PORTS)),
                        help="Comma-separated ports or ranges (e.g., 1-1024,80,443).")
    parser.add_argument("--concurrency", "-c", type=int, default=400, help="Overall concurrency (default 400).")
    parser.add_argument("--timeout", type=float, default=1.0, help="Per-connection timeout (seconds).")
    parser.add_argument("--json", default="scan_results.json", help="JSON output path")
    parser.add_argument("--csv", default="scan_results.csv", help="CSV output path")
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    hosts = args.hosts or None
    use_arp = (args.mode == "arp")
    scanner = NetworkScanner(network=args.network, hosts=hosts, ports=ports, use_arp=use_arp,
                             concurrency=args.concurrency, timeout=args.timeout)

    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        print("Interrupted by user.")
    scanner.export_json(args.json)
    scanner.export_csv(args.csv)
    print("Done.")

if __name__ == "__main__":
    main()


# --- Add this to the bottom of network_scanner.py ---

import asyncio
from typing import Optional, List, Dict, Any

async def _run_scan(network: Optional[str] = None,
                    hosts: Optional[List[str]] = None,
                    ports: Optional[List[int]] = None,
                    use_arp: bool = True,
                    concurrency: int = 400,
                    timeout: float = 1.0) -> Dict[str, Any]:
    """
    Async helper that wraps NetworkScanner.run() and returns raw results.

    :param network: CIDR string (e.g. '192.168.1.0/24') or None if specifying hosts directly.
    :param hosts: List of IPs to scan directly (bypasses discovery).
    :param ports: List of ports to scan (defaults to DEFAULT_PORTS).
    :param use_arp: If True and scapy is available, use ARP for discovery.
    :param concurrency: Maximum number of concurrent host/port probes.
    :param timeout: Per-connection timeout in seconds.
    :return: Dictionary keyed by IP with scan details and anomaly scores.
    """
    scanner = NetworkScanner(network=network,
                             hosts=hosts,
                             ports=ports,
                             use_arp=use_arp,
                             concurrency=concurrency,
                             timeout=timeout)
    await scanner.run()
    return scanner.results

def scan_agent(network: Optional[str] = None,
               hosts: Optional[List[str]] = None,
               ports: Optional[List[int]] = None,
               use_arp: bool = True,
               concurrency: int = 400,
               timeout: float = 1.0) -> Dict[str, Any]:
    """
    Synchronous wrapper for clients who want to call this module like an agent.
    Blocks until the async scan completes and returns the scan results.

    Usage:
        from network_scanner import scan_agent
        results = scan_agent(network='192.168.1.0/24', ports=[22, 80, 443])
        # process results...
    """
    if not network and not hosts:
        raise ValueError("You must provide either a network CIDR or a list of hosts to scan.")
    return asyncio.run(_run_scan(network=network,
                                 hosts=hosts,
                                 ports=ports,
                                 use_arp=use_arp,
                                 concurrency=concurrency,
                                 timeout=timeout))


