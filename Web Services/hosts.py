#!/usr/bin/env python3
"""
discover_hosts_pretty.py

Discover which hosts are up in a network (CIDR or list) using ICMP ping or TCP probe,
and print a clean, readable report showing only responsive hosts.

Usage examples:
  # Scan a /24 network using ping
  python discover_hosts_pretty.py --network 192.168.0.0/24

  # Scan a few IPs
  python discover_hosts_pretty.py --ips 192.168.0.1 192.168.0.5

  # If ICMP is blocked, try TCP fallback on port 2221
  python discover_hosts_pretty.py --network 192.168.0.0/24 --tcp-port 2221

  # Save the report to a file
  python discover_hosts_pretty.py --network 192.168.0.0/24 --outfile hosts_report.txt
"""

# -*- coding: utf-8 -*-

import sys
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

import argparse
import ipaddress
import platform
import subprocess
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, Dict

DEFAULT_TIMEOUT = 1.0
DEFAULT_WORKERS = 200


def ips_from_network(network: str) -> Iterable[str]:
    """Generate all usable IPs in a network."""
    net = ipaddress.ip_network(network, strict=False)
    return (str(addr) for addr in net.hosts())


def ping_ip(ip: str, timeout: float) -> bool:
    """Ping the IP using the system ping command. Returns True if ping succeeds."""
    system = platform.system().lower()
    try:
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
        else:
            w = max(1, int(timeout))
            cmd = ["ping", "-c", "1", "-W", str(w), ip]
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False


def tcp_probe(ip: str, port: int, timeout: float) -> bool:
    """Try a TCP connection to ip:port. Returns True if connection succeeds."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def is_host_up(ip: str, timeout: float, tcp_port: int = None) -> bool:
    """Return True if host responds to ping or (if provided) TCP probe."""
    if ping_ip(ip, timeout):
        return True
    if tcp_port is not None:
        return tcp_probe(ip, tcp_port, timeout)
    return False


def scan_ips(ips: Iterable[str], timeout: float, workers: int, tcp_port: int = None) -> Dict[str, bool]:
    """Scan multiple IPs concurrently."""
    results = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        future_to_ip = {ex.submit(is_host_up, ip, timeout, tcp_port): ip for ip in ips}
        for fut in as_completed(future_to_ip):
            ip = future_to_ip[fut]
            try:
                results[ip] = fut.result()
            except Exception:
                results[ip] = False
    return results


def parse_args():
    p = argparse.ArgumentParser(description="Discover which hosts are up in a network or list.")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--network", "-n", help="CIDR network to scan (e.g. 192.168.0.0/24)")
    group.add_argument("--ips", "-i", nargs="+", help="One or more IPs to scan")
    p.add_argument("--timeout", "-t", type=float, default=DEFAULT_TIMEOUT, help="Timeout seconds (default 1.0)")
    p.add_argument("--workers", "-w", type=int, default=DEFAULT_WORKERS, help="Concurrent workers (default 200)")
    p.add_argument("--outfile", "-o", help="Write pretty output to file (optional). If omitted prints to stdout.")
    p.add_argument("--tcp-port", type=int, help="Optional TCP port to probe if ICMP ping fails (e.g. 2221).")
    return p.parse_args()


def pretty_format_open(results: Dict[str, bool], tcp_port: int = None) -> str:
    """Return a formatted text report showing only reachable hosts."""
    up_hosts = [ip for ip, ok in results.items() if ok]

    report_lines = []
    report_lines.append("🛰️  Host Discovery Report")
    report_lines.append("=" * 33)
    probe_method = "ICMP Ping"
    if tcp_port:
        probe_method += f" (TCP fallback: {tcp_port})"
    report_lines.append(f"Scanning for active hosts using {probe_method}\n")

    if not up_hosts:
        report_lines.append("❌ No responsive hosts found.")
        return "\n".join(report_lines)

    header = "IP Address".ljust(18) + "Status\n" + "-" * 30
    report_lines.append(header)

    for ip in sorted(up_hosts, key=lambda s: tuple(int(x) for x in s.split('.'))):
        report_lines.append(f"{ip.ljust(18)} ✅ Host is Up")

    return "\n".join(report_lines)


def main():
    args = parse_args()

    if args.network:
        targets = list(ips_from_network(args.network))
    else:
        targets = args.ips

    if not targets:
        print("No targets found. Exiting.")
        return

    results = scan_ips(targets, args.timeout, args.workers, args.tcp_port)
    out_text = pretty_format_open(results, args.tcp_port)

    if args.outfile:
        with open(args.outfile, "w") as fh:
            fh.write(out_text)
        print(f"Wrote report to {args.outfile}")
    else:
        print(out_text)


if __name__ == "__main__":
    main()