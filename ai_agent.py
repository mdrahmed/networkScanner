#!/usr/bin/env python3
"""
ai_agent.py

Wrapper "AI agent" that loads & runs network_scanner.py's NetworkScanner,
then performs a small vulnerability & executable-service analysis and
outputs a human-friendly report + agent_report.json.

Usage examples:
  python3 ai_agent.py --network 192.168.1.0/24 --mode ping --ports 22,80,443
  python3 ai_agent.py --hosts 192.168.1.10 192.168.1.20 --ports 1-1024
"""

import argparse
import asyncio
import importlib.util
import json
import os
import sys
import textwrap
from typing import Dict, Any, List

# ---------------------------
# Lightweight local "vuln DB"
# ---------------------------
# Map substrings that may appear in banners -> short vuln description.
# Expand to include things you care about.
KNOWN_VULNS = {
    "apache/2.4.49": "CVE-2021-41773 (path traversal / RCE in some configs)",
    "apache/2.4.50": "CVE-2021-44224 (mod_proxy) / check vendor advisory",
    "nginx/1.18.0": "Potential old nginx; check CVEs for your version",
    "openssh_7.2": "Older OpenSSH; search CVE listings for this version",
    "openssh_8.2": "OpenSSH 8.2 - check for vendor patches",
    "proftpd": "ProFTPD versions historically had path traversal/RCE CVEs",
    "ssh-2.0-": "SSH banner (version present) - consider hardening",
    "mysql": "MySQL server - ensure authentication & bind-address config",
    "mariadb": "MariaDB server - ensure authentication & patching",
    "tomcat": "Apache Tomcat - look for CVEs for the reported version",
    "php": "PHP visible in headers -> watch for vulnerable frameworks/plugins",
    "iis": "Microsoft IIS - check Windows patch level",
    "vsftpd": "vsftpd - older versions had backdoor CVEs",
    "samba": "SMB/Samba service - dangerous if exposed publicly",
    "redis": "Redis default config allows unauth access on many installs",
    "elasticsearch": "Elasticsearch can be exploited if exposed (RCE/remote code)"
}

# Ports that commonly allow interactive/remote command execution or sensitive access
EXECUTABLE_PORTS = {
    21,   # FTP
    22,   # SSH
    23,   # Telnet
    25,   # SMTP (can be abused)
    80,   # HTTP (web app -> RCE via vuln)
    443,  # HTTPS (web app)
    139,  # NetBIOS
    445,  # SMB
    3389, # RDP
    5900, # VNC
    3306, # MySQL
    5432, # PostgreSQL
    6379, # Redis
    27017 # MongoDB
}

# ---------------------------
# Helpers
# ---------------------------
def load_scanner_module(path: str):
    """Dynamically load network_scanner.py as a module and return it."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Scanner file not found: {path}")
    spec = importlib.util.spec_from_file_location("network_scanner", path)
    mod = importlib.util.module_from_spec(spec)
    loader = spec.loader
    assert loader is not None
    loader.exec_module(mod)
    return mod

def analyze_results(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Take NetworkScanner.results (ip -> host_res) and produce an analysis report.
    """
    report = {"summary": {"hosts_scanned": len(results)}, "hosts": []}
    high_risk_hosts = []

    for ip, host in results.items():
        host_report = {
            "ip": ip,
            "open_ports": [],
            "vulns": [],
            "executable_ports": [],
            "anomaly_score": None,
            "notes": []
        }
        # anomaly score if present
        anomaly = host.get("anomaly")
        if anomaly and "score" in anomaly:
            host_report["anomaly_score"] = anomaly["score"]

        # iterate ports (keys are strings in network_scanner)
        for port_str, pinfo in host.get("ports", {}).items():
            port = int(port_str)
            if pinfo.get("open"):
                banner = pinfo.get("banner") or ""
                host_report["open_ports"].append({"port": port, "banner": banner, "latency_ms": pinfo.get("latency_ms")})

                # check known vuln patterns
                banner_l = banner.lower()
                for pattern, info in KNOWN_VULNS.items():
                    if pattern in banner_l:
                        host_report["vulns"].append({"port": port, "banner": banner.strip(), "match": pattern, "info": info})

                # executable/service port heuristic
                if port in EXECUTABLE_PORTS:
                    host_report["executable_ports"].append(port)

        # heuristics / notes
        if host_report["vulns"]:
            host_report["notes"].append(f"{len(host_report['vulns'])} matching known vuln patterns")
        if host_report["executable_ports"]:
            host_report["notes"].append(f"Executable/sensitive ports exposed: {host_report['executable_ports']}")
        if not host_report["open_ports"]:
            host_report["notes"].append("No open ports found.")
        if host_report["anomaly_score"] is not None and host_report["anomaly_score"] >= 6.0:
            host_report["notes"].append("High anomaly score (investigate).")
            high_risk_hosts.append(ip)

        report["hosts"].append(host_report)

    report["summary"]["high_risk_count"] = len(high_risk_hosts)
    report["summary"]["high_risk_hosts"] = high_risk_hosts
    return report

def print_human_report(analysis: Dict[str, Any]):
    print("\n" + "="*60)
    print("AI Agent Scan Report")
    print("="*60)
    print(f"Hosts scanned: {analysis['summary']['hosts_scanned']}")
    print(f"High-risk hosts: {len(analysis['summary'].get('high_risk_hosts', []))}")
    print("-"*60)

    for h in analysis["hosts"]:
        print(f"Host: {h['ip']}")
        if h["open_ports"]:
            for p in h["open_ports"]:
                banner = p["banner"] or "<no banner>"
                print(f"  - Port {p['port']} open (latency={p.get('latency_ms')} ms) Banner: {banner}")
        else:
            print("  - No open ports found.")
        if h["vulns"]:
            for v in h["vulns"]:
                print(f"    ! Vulnerability match on port {v['port']}: {v['match']} -> {v['info']}")
        if h["executable_ports"]:
            print(f"    ! Executable/sensitive ports: {h['executable_ports']}")
        if h["anomaly_score"] is not None:
            print(f"    - Anomaly score: {h['anomaly_score']}")
        if h["notes"]:
            for note in h["notes"]:
                print(f"    - Note: {note}")
        print("-"*60)

# ---------------------------
# Main agent logic
# ---------------------------
def build_scanner_from_args(scanner_mod, args) -> Any:
    """Given the imported scanner module and parsed args, construct NetworkScanner."""
    NetworkScanner = getattr(scanner_mod, "NetworkScanner", None)
    if NetworkScanner is None:
        raise RuntimeError("Loaded scanner module does not expose NetworkScanner class")

    ports = scanner_mod.parse_ports(args.ports) if hasattr(scanner_mod, "parse_ports") else []
    hosts = args.hosts or None
    use_arp = (args.mode == "arp")
    scanner = NetworkScanner(network=args.network, hosts=hosts, ports=ports,
                             use_arp=use_arp, concurrency=args.concurrency, timeout=args.timeout)
    return scanner

async def run_scan_and_analyze(scanner) -> Dict[str, Any]:
    # run scanner.run() (it's async)
    results = await scanner.run()
    # results should be the dict of hosts -> host_res
    analysis = analyze_results(results)
    return analysis

def main():
    parser = argparse.ArgumentParser(description="AI agent wrapper for network_scanner.py")
    parser.add_argument("--scanner-path", default="network_scanner.py", help="Path to network_scanner.py")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--network", "-n", help="Target network in CIDR (e.g., 192.168.1.0/24)")
    group.add_argument("--hosts", "-H", nargs="+", help="Explicit host IPs to scan")
    parser.add_argument("--mode", choices=["arp", "ping"], default="arp",
                        help="Discovery mode for scanner")
    parser.add_argument("--ports", "-p", default=None,
                        help="Ports string (e.g., '22,80,443' or '1-1024'). If omitted, scanner default used.")
    parser.add_argument("--concurrency", "-c", type=int, default=200, help="Scanner concurrency")
    parser.add_argument("--timeout", type=float, default=1.0, help="Per-connection timeout")
    parser.add_argument("--out", default="agent_report.json", help="Agent JSON output path")
    args = parser.parse_args()

    # load scanner module
    try:
        scanner_mod = load_scanner_module(args.scanner_path)
    except Exception as e:
        print(f"Error loading scanner module: {e}")
        sys.exit(1)

    # borrow default ports from the scanner if user didn't specify
    if not args.ports:
        # scanner module should expose DEFAULT_PORTS and parse_ports
        if hasattr(scanner_mod, "DEFAULT_PORTS"):
            args.ports = ",".join(map(str, getattr(scanner_mod, "DEFAULT_PORTS")))
        else:
            args.ports = "22,80,443"

    # build the scanner instance
    try:
        scanner = build_scanner_from_args(scanner_mod, args)
    except Exception as e:
        print(f"Error building scanner: {e}")
        sys.exit(1)

    # run & analyze
    try:
        analysis = asyncio.run(run_scan_and_analyze(scanner))
    except KeyboardInterrupt:
        print("Scan interrupted by user.")
        analysis = {"summary": {"hosts_scanned": 0}, "hosts": []}
    except Exception as e:
        print(f"Error during scan: {e}")
        sys.exit(1)

    # print & save analysis
    print_human_report(analysis)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(analysis, f, indent=2)
    print(f"\nAgent JSON report written to: {args.out}")

if __name__ == "__main__":
    main()


