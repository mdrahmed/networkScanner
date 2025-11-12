## AI Agent — Network Scan & Vulnerability Reporter
This ai agent can scan the network to discover live hosts, identify open ports and services, and surface likely risky or vulnerable findings.

Key features
 - Fast LAN discovery (ARP or TCP-based ping sweep) and async TCP connect port scanning.
 - Simple banner grabbing and protocol-aware fingerprints (HTTP, SSH, FTP, etc.).
 - Local CVE-pattern matching (configurable) to flag likely vulnerable software.
 - Heuristics to mark executable/sensitive services (SSH, RDP, SMB, databases).
 - Exports results to agent_report.json and prints a concise, prioritized report.
 - Designed for safe, authorized testing on your own hosts (not for scanning external systems).
