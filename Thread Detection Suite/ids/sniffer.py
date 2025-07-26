# ids/sniffer.py

from scapy.all import sniff, IP, TCP, get_if_list, get_if_addr
from datetime import datetime
import pandas as pd
import os

LOG_FILE = "logs/alerts.csv"
THRESHOLD = 5
syn_count = {}
alerts = []

def alert(ip):
    print(f"🛑 [ALERT] SYN Flood from {ip}")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alerts.append({
        "Timestamp": timestamp,
        "Source IP": ip,
        "Alert": "SYN Flood Detected"
    })

def save_alerts():
    os.makedirs("logs", exist_ok=True)
    
    # Always ensure the file exists even if no alerts
    if not alerts and not os.path.exists(LOG_FILE):
        pd.DataFrame(columns=["Timestamp", "Source IP", "Alert"]).to_csv(LOG_FILE, index=False)
        print("✅ No alerts to save.")
        return

    if alerts:
        df = pd.DataFrame(alerts)
        header = not os.path.exists(LOG_FILE)
        df.to_csv(LOG_FILE, mode="a", header=header, index=False)
        print(f"📁 Alerts saved to: {LOG_FILE}")
    else:
        print("✅ No alerts to save.")

def detect(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip = packet[IP].src
        flags = packet[TCP].flags
        if flags == "S":  # SYN flag
            syn_count[ip] = syn_count.get(ip, 0) + 1
            if syn_count[ip] > THRESHOLD:
                alert(ip)

def get_active_interface():
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip != "127.0.0.1":
                return iface
        except:
            continue
    return None

def run():
    print("\n🛡️ IDS: Monitoring for SYN Floods")
    iface = get_active_interface()
    if not iface:
        print("❌ No active network interface found.")
        return

    print(f"🔎 Monitoring on interface: {iface} (connected Wi-Fi or Ethernet)\n")
    try:
        sniff(prn=detect, store=False, count=50, iface=iface, timeout=30)
        save_alerts()
        print("✅ IDS scan completed.")
    except PermissionError:
        print("❌ Permission denied. Run with admin/root.")
    except Exception as e:
        print(f"❌ Error during sniffing: {e}")
