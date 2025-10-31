#!/usr/bin/env python3
"""
check_adb_port_pretty.py

Scan IPs or networks for adb (TCP port 5555) and display a readable report
showing only hosts with adb open.

Usage examples:
  # Scan one IP
  python check_adb_port_pretty.py --ips 192.168.0.165

  # Scan a network
  python check_adb_port_pretty.py --network 192.168.0.0/24

  # Save report to a file
  python check_adb_port_pretty.py --network 192.168.0.0/24 --outfile adb_report.txt
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

DEFAULT_PORT = 5555
DEFAULT_TIMEOUT = 1.0
DEFAULT_WORKERS = 100


def check_adb(ip: str, port: int = DEFAULT_PORT, timeout: float = DEFAULT_TIMEOUT) -> bool:
    """Return True if TCP port 5555 is open on ip, else False."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def ips_from_network(network: str) -> Iterable[str]:
    """Generate all host IPs in a CIDR network."""
    net = ipaddress.ip_network(network, strict=False)
    return (str(addr) for addr in net.hosts())


def scan_ips(ips: Iterable[str], port: int, timeout: float, workers: int) -> Dict[str, bool]:
    """Concurrent adb scan of given IP list."""
    results = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        future_to_ip = {ex.submit(check_adb, ip, port, timeout): ip for ip in ips}
        for fut in as_completed(future_to_ip):
            ip = future_to_ip[fut]
            try:
                results[ip] = fut.result()
            except Exception:
                results[ip] = False
    return results


def parse_args():
    p = argparse.ArgumentParser(description="Scan IPs to find active adb devices (port 5555 open).")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--network", "-n", help="CIDR network to scan (e.g. 192.168.0.0/24)")
    group.add_argument("--ips", "-i", nargs="+", help="One or more IPs to scan")
    p.add_argument("--timeout", "-t", type=float, default=DEFAULT_TIMEOUT, help="Socket timeout seconds")
    p.add_argument("--workers", "-w", type=int, default=DEFAULT_WORKERS, help="Concurrent threads")
    p.add_argument("--outfile", "-o", help="Write report to file (optional). If omitted prints to stdout")
    return p.parse_args()


def pretty_format_open(results: Dict[str, bool]) -> str:
    """Generate a formatted report showing only IPs with adb open."""
    open_hosts = [ip for ip, ok in results.items() if ok]

    report_lines = []
    report_lines.append("🔐 adb Server Lookup Report")
    report_lines.append("=" * 33)
    report_lines.append("Scanning for hosts with adb (port 5555) open\n")

    if not open_hosts:
        report_lines.append("❌ No active adb devices found.")
        return "\n".join(report_lines)

    header = "IP Address".ljust(18) + "Status\n" + "-" * 30
    report_lines.append(header)

    for ip in sorted(open_hosts, key=lambda s: tuple(int(x) for x in s.split('.'))):
        report_lines.append(f"{ip.ljust(18)} ✅ adb Service Detected")

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

    results = scan_ips(targets, DEFAULT_PORT, args.timeout, args.workers)
    out_text = pretty_format_open(results)

    if args.outfile:
        with open(args.outfile, "w") as fh:
            fh.write(out_text)
        print(f"Wrote report to {args.outfile}")
    else:
        print(out_text)


if __name__ == "__main__":
    main()