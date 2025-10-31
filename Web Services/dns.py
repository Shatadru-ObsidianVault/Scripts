# dns.py

# -*- coding: utf-8 -*-

import sys
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

import socket
import subprocess
import platform
import sys
import json

def ping(host):
    """Ping a host to check if it's reachable."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", host]
    return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def check_dns(domain, dns_server, output_json=False):
    net_status = ping(dns_server)
    
    try:
        ip = socket.gethostbyname(domain)
        dns_status = True
    except socket.gaierror:
        dns_status = False
        ip = None

    # Determine overall status
    if net_status and dns_status:
        overall = "DNS is working"
    elif net_status and not dns_status:
        overall = "Network works but DNS failed"
    else:
        overall = "No network connectivity"

    # JSON output
    if output_json:
        result = {
            "dns_server_reachable": net_status,
            "domain_resolved": dns_status,
            "domain_ip": ip,
            "status": overall
        }
        print(json.dumps(result, indent=4))
    else:
        # Normal text output
        print(f"Checking connectivity to DNS server {dns_server}...")
        print(f"{'✅' if net_status else '❌'} DNS server {dns_server} is {'reachable' if net_status else 'unreachable'}.\n")
        print(f"Resolving domain {domain}...")
        if dns_status:
            print(f"✅ Domain {domain} resolved to {ip}. {overall}.")
        else:
            print(f"❌ Failed to resolve {domain}. {overall}.")

if __name__ == "__main__":
    args = sys.argv[1:]

    if not (2 <= len(args) <= 3):
        print("Usage: python dns.py [domain] [dns_server] [-json]")
        sys.exit(1)

    domain = args[0]
    dns_server = args[1]
    output_json = "-json" in args

    check_dns(domain, dns_server, output_json)