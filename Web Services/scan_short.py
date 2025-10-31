import subprocess
import re

def get_wifi_names():
    try:
        output = subprocess.check_output(
            ['netsh', 'wlan', 'show', 'networks'],
            shell=True, text=True, encoding='utf-8', errors='ignore'
        )

        # Extract SSIDs using regex
        ssids = re.findall(r"SSID\s+\d+\s*:\s*(.*)", output)

        # Clean out empty, duplicate, or non-SSID lines
        clean_list = []
        for ssid in ssids:
            name = ssid.strip()
            if name and not name.lower().startswith("network type"):
                clean_list.append(name)

        # Remove duplicates while preserving order
        seen = set()
        final_ssids = []
        for s in clean_list:
            if s not in seen:
                seen.add(s)
                final_ssids.append(s)

        # Print only SSIDs, one per line
        for ssid in final_ssids:
            print(ssid)

    except Exception as e:
        print("⚠️ Error:", e)

if __name__ == "__main__":
    get_wifi_names()