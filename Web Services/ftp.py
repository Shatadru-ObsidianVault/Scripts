#!/usr/bin/env python3
"""
scan_port2221_pretty.py

Scan a network or list of IPs for a single TCP port (default 2221) and
display a clean report showing only hosts where the port is open.

Usage examples:
  # Scan a /24 network (default port 2221)
  python scan_port2221_pretty.py --network 192.168.0.0/24

  # Scan a single IP
  python scan_port2221_pretty.py --ips 192.168.0.165

  # Scan an explicit list of IPs
  python scan_port2221_pretty.py --ips 192.168.0.10 192.168.0.20 192.168.0.165

  # Scan and write output to file
  python scan_port2221_pretty.py --network 192.168.0.0/24 --outfile result.txt
"""

# -*- coding: utf-8 -*-

import sys
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

import argparse
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, Dict

DEFAULT_PORT = 2221
DEFAULT_TIMEOUT = 1.0
DEFAULT_WORKERS = 100


def check_port(ip: str, port: int = DEFAULT_PORT, timeout: float = DEFAULT_TIMEOUT) -> bool:
    """Return True if TCP port is open on ip."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False


def ips_from_network(network: str) -> Iterable[str]:
    """Generate host IPs from a CIDR network (exclude network & broadcast)."""
    net = ipaddress.ip_network(network, strict=False)
    for addr in net.hosts():
        yield str(addr)


def scan_ips(ips: Iterable[str], port: int, timeout: float, workers: int) -> Dict[str, bool]:
    """Scan IPs concurrently; return only which ports are open."""
    results = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        future_to_ip = {ex.submit(check_port, ip, port, timeout): ip for ip in ips}
        for fut in as_completed(future_to_ip):
            ip = future_to_ip[fut]
            try:
                results[ip] = fut.result()
            except Exception:
                results[ip] = False
    return results


def parse_args():
    p = argparse.ArgumentParser(description="Scan IPs for a TCP port and show only hosts with port open.")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--network", "-n", help="CIDR network to scan (e.g. 192.168.0.0/24)")
    group.add_argument("--ips", "-i", nargs="+", help="One or more IPs to scan")
    p.add_argument("--port", "-p", type=int, default=DEFAULT_PORT, help=f"TCP port to scan (default {DEFAULT_PORT})")
    p.add_argument("--timeout", "-t", type=float, default=DEFAULT_TIMEOUT, help=f"socket timeout seconds (default {DEFAULT_TIMEOUT})")
    p.add_argument("--workers", "-w", type=int, default=DEFAULT_WORKERS, help=f"concurrent threads (default {DEFAULT_WORKERS})")
    p.add_argument("--outfile", "-o", help="Write pretty output to file (optional). If omitted prints to stdout.")
    return p.parse_args()


def pretty_format_open(results: Dict[str, bool], port: int) -> str:
    """Return a formatted report showing only IPs with the port open."""
    open_hosts = [ip for ip, ok in results.items() if ok]

    report_lines = []
    report_lines.append(f"🔌 Port {port} Scan Report")
    report_lines.append("=" * 33)
    report_lines.append(f"Scanning for hosts with TCP port {port} open\n")

    if not open_hosts:
        report_lines.append("❌ No hosts with port open found.")
        return "\n".join(report_lines)

    header = "IP Address".ljust(18) + "Status\n" + "-" * 30
    report_lines.append(header)

    for ip in sorted(open_hosts, key=lambda s: tuple(int(x) for x in s.split('.'))):
        report_lines.append(f"{ip.ljust(18)} ✅ Port {port} Open")

    return "\n".join(report_lines)


def main():
    args = parse_args()

    if args.network:
        targets = list(ips_from_network(args.network))
    else:
        targets = args.ips

    if not targets:
        print("No target IPs found. Exiting.")
        return

    results = scan_ips(targets, args.port, args.timeout, args.workers)
    out_text = pretty_format_open(results, args.port)

    if args.outfile:
        with open(args.outfile, "w") as fh:
            fh.write(out_text)
        print(f"Wrote report to {args.outfile}")
    else:
        print(out_text)


if __name__ == "__main__":
    main()