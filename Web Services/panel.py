import subprocess
import psutil
import re
import socket

def check_wifi():
    try:
        output = subprocess.check_output("netsh wlan show interfaces", shell=True, text=True)
        return "State" in output and "connected" in output.lower()
    except:
        return False

def check_ethernet():
    try:
        for interface, addrs in psutil.net_if_addrs().items():
            if "Ethernet" in interface and any(addr.address for addr in addrs if addr.family == socket.AF_INET):
                return True
        return False
    except:
        return False

def check_bluetooth():
    try:
        output = subprocess.check_output("powershell Get-Service bthserv", shell=True, text=True)
        return "Running" in output
    except:
        return False

def check_cellular():
    try:
        output = subprocess.check_output("netsh mbn show interfaces", shell=True, text=True)
        return "State" in output and "connected" in output.lower()
    except:
        return False

def check_hotspot():
    try:
        output = subprocess.check_output("netsh wlan show hostednetwork", shell=True, text=True)
        return "Status" in output and "started" in output.lower()
    except:
        return False

def check_airplane_mode():
    try:
        output = subprocess.check_output(
            'reg query "HKLM\\System\\CurrentControlSet\\Control\\RadioManagement\\SystemRadioState"', 
            shell=True, text=True)
        return "0x0" in output  # 0x0 = Off, 0x1 = On
    except:
        return False

def check_firewall():
    try:
        output = subprocess.check_output("netsh advfirewall show allprofiles", shell=True, text=True)
        return "State ON" in output.upper()
    except:
        return False

def check_vpn():
    try:
        output = subprocess.check_output("ipconfig", shell=True, text=True)
        return any(word in output.lower() for word in ["vpn", "tunnel", "ppp adapter"])
    except:
        return False

def check_proxy():
    try:
        output = subprocess.check_output("netsh winhttp show proxy", shell=True, text=True)
        return "Direct access" not in output
    except:
        return False

def check_relay():
    # No standard Windows relay; assume False
    return False

def check_vnc():
    for proc in psutil.process_iter(['name']):
        if 'vnc' in proc.info['name'].lower():
            return True
    return False

def check_ssh():
    for proc in psutil.process_iter(['name']):
        if 'sshd' in proc.info['name'].lower():
            return True
    return False

def check_ftp():
    for proc in psutil.process_iter(['name']):
        if 'ftp' in proc.info['name'].lower():
            return True
    return False


# Mapping all checks
checks = {
    "Ethernet": check_ethernet,
    "Wi-Fi": check_wifi,
    "Bluetooth": check_bluetooth,
    "Cellular": check_cellular,
    "Hotspot": check_hotspot,
    "Airplane Mode": check_airplane_mode,
    "Firewall": check_firewall,
    "VPN": check_vpn,
    "Proxy": check_proxy,
    "Relay": check_relay,
    "VNC Server": check_vnc,
    "SSH Server": check_ssh,
    "FTP Server": check_ftp
}

if __name__ == "__main__":
    for name, func in checks.items():
        try:
            print(f"{name}: {func()}")
        except Exception as e:
            print(f"{name}: False  # error: {e}")