import subprocess
import re

def scan_wifi_networks():
    try:
        # Run the Windows command to list all Wi-Fi networks
        output = subprocess.check_output(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'], shell=True, text=True, encoding='utf-8', errors='ignore')

        # Split into lines
        lines = output.splitlines()
        networks = []
        current_network = {}

        for line in lines:
            line = line.strip()

            if line.startswith("SSID "):
                if current_network:
                    networks.append(current_network)
                    current_network = {}
                ssid = line.split(" : ", 1)[1] if " : " in line else ""
                current_network["SSID"] = ssid

            elif line.startswith("BSSID "):
                bssid = line.split(" : ", 1)[1] if " : " in line else ""
                current_network["BSSID"] = bssid

            elif "Signal" in line:
                signal = line.split(" : ", 1)[1] if " : " in line else ""
                current_network["Signal"] = signal

            elif "Radio type" in line:
                radio = line.split(" : ", 1)[1] if " : " in line else ""
                current_network["RadioType"] = radio

            elif "Channel" in line:
                channel = line.split(" : ", 1)[1] if " : " in line else ""
                current_network["Channel"] = channel

        if current_network:
            networks.append(current_network)

        # Print results
        print("Nearby Wi-Fi and Hotspot Devices:\n" + "="*40)
        for i, net in enumerate(networks, 1):
            print(f"{i}. SSID     : {net.get('SSID', 'Unknown')}")
            print(f"   BSSID    : {net.get('BSSID', 'Unknown')}")
            print(f"   Signal   : {net.get('Signal', 'Unknown')}")
            print(f"   Channel  : {net.get('Channel', 'Unknown')}")
            print(f"   Radio    : {net.get('RadioType', 'Unknown')}")
            print("-"*40)

    except subprocess.CalledProcessError as e:
        print("❌ Error running netsh command:", e)
    except Exception as e:
        print("⚠️ Unexpected error:", e)

if __name__ == "__main__":
    scan_wifi_networks()