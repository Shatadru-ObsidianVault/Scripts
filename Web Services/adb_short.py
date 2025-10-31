#!/usr/bin/env python3
"""
check_adb_ips_only.py

Scan IPs or networks for ADB (TCP port 5555) and print only IPs
with the port open, one per line.

Usage:
  python check_adb_ips_only.py --network 192.168.0.0/24
  python check_adb_ips_only.py --ips 192.168.0.101 192.168.0.105
"""

import argparse
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_PORT = 5555
DEFAULT_TIMEOUT = 1.0
DEFAULT_WORKERS = 100

def check_adb(ip: str, port: int = DEFAULT_PORT, timeout: float = DEFAULT_TIMEOUT) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

def ips_from_network(network: str):
    net = ipaddress.ip_network(network, strict=False)
    return (str(addr) for addr in net.hosts())

def scan_ips(ips, port, timeout, workers):
    open_ips = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(check_adb, ip, port, timeout): ip for ip in ips}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                if fut.result():
                    open_ips.append(ip)
            except Exception:
                pass
    return sorted(open_ips, key=lambda s: tuple(map(int, s.split('.'))))

def parse_args():
    p = argparse.ArgumentParser(description="Print only IPs with ADB open (port 5555).")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--network", "-n", help="CIDR network to scan (e.g. 192.168.0.0/24)")
    group.add_argument("--ips", "-i", nargs="+", help="Specific IPs to scan")
    p.add_argument("--timeout", "-t", type=float, default=DEFAULT_TIMEOUT, help="Socket timeout seconds")
    p.add_argument("--workers", "-w", type=int, default=DEFAULT_WORKERS, help="Concurrent threads")
    return p.parse_args()

def main():
    args = parse_args()
    targets = list(ips_from_network(args.network)) if args.network else args.ips
    if not targets:
        return
    open_ips = scan_ips(targets, DEFAULT_PORT, args.timeout, args.workers)
    for ip in open_ips:
        print(ip)

if __name__ == "__main__":
    main()