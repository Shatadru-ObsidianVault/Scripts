#!/usr/bin/env python3
"""
check_ports_80_443_report.py

Scan multiple IPs or a network and show only hosts where both ports
80 and 443 are open — i.e., likely running a web server.

Usage examples:
  # Scan a single IP
  python check_ports_80_443_report.py --ips 192.168.0.165

  # Scan a network
  python check_ports_80_443_report.py --network 192.168.0.0/24

  # Save to a text file
  python check_ports_80_443_report.py --network 192.168.0.0/24 --outfile report.txt
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

DEFAULT_PORTS = [80, 443]
DEFAULT_TIMEOUT = 1.0
DEFAULT_WORKERS = 100


def check_ports(ip: str, ports: list = DEFAULT_PORTS, timeout: float = DEFAULT_TIMEOUT) -> bool:
    """Return True if all ports in list are open on the IP, else False."""
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                continue
        except Exception:
            return False
    return True


def ips_from_network(network: str) -> Iterable[str]:
    net = ipaddress.ip_network(network, strict=False)
    return (str(addr) for addr in net.hosts())


def scan_ips(ips: Iterable[str], ports: list, timeout: float, workers: int) -> Dict[str, bool]:
    results = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        future_to_ip = {ex.submit(check_ports, ip, ports, timeout): ip for ip in ips}
        for fut in as_completed(future_to_ip):
            ip = future_to_ip[fut]
            try:
                results[ip] = fut.result()
            except Exception:
                results[ip] = False
    return results


def parse_args():
    p = argparse.ArgumentParser(description="Scan IPs to find web servers (ports 80 & 443 open).")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--network", "-n", help="CIDR network to scan (e.g. 192.168.0.0/24)")
    group.add_argument("--ips", "-i", nargs="+", help="One or more IPs to scan")
    p.add_argument("--timeout", "-t", type=float, default=DEFAULT_TIMEOUT, help="Socket timeout seconds")
    p.add_argument("--workers", "-w", type=int, default=DEFAULT_WORKERS, help="Concurrent threads")
    p.add_argument("--outfile", "-o", help="Write pretty output to file (optional). If omitted prints to stdout")
    return p.parse_args()


def pretty_format_open(results: Dict[str, bool]) -> str:
    """
    Return a formatted text report showing only IPs with both ports open.
    """
    open_hosts = [ip for ip, ok in results.items() if ok]

    report_lines = []
    report_lines.append("🌐 Web Server Lookup Report")
    report_lines.append("=" * 33)
    report_lines.append("Scanning for hosts with ports 80 & 443 open\n")

    if not open_hosts:
        report_lines.append("❌ No active web servers found.")
        return "\n".join(report_lines)

    header = "IP Address".ljust(18) + "Status\n" + "-" * 30
    report_lines.append(header)

    for ip in sorted(open_hosts, key=lambda s: tuple(int(x) for x in s.split('.'))):
        report_lines.append(f"{ip.ljust(18)} ✅ Web Server Detected")

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

    results = scan_ips(targets, DEFAULT_PORTS, args.timeout, args.workers)
    out_text = pretty_format_open(results)

    if args.outfile:
        with open(args.outfile, "w") as fh:
            fh.write(out_text)
        print(f"Wrote report to {args.outfile}")
    else:
        print(out_text)


if __name__ == "__main__":
    main()