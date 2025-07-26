# scanner/port_scanner.py

import socket
import pandas as pd
import os
from datetime import datetime

LOG_FILE = "logs/port_scan_results.csv"

def scan_ports(target):
    print(f"\n🔍 Scanning {target} for open TCP ports (1–1024)...\n")
    open_ports = []

    for port in range(1, 1025):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.3)
                result = sock.connect_ex((target, port))
                if result == 0:
                    print(f"✅ Port {port} is OPEN")
                    open_ports.append(port)
        except Exception as e:
            print(f"❌ Error scanning port {port}: {e}")
    return open_ports

def save_results(target, open_ports):
    os.makedirs("logs", exist_ok=True)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if not open_ports:
        print("\n⚠️ No open ports found.")
        # Ensure the CSV exists with headers so dashboard works
        if not os.path.exists(LOG_FILE):
            pd.DataFrame(columns=["Timestamp", "Target", "Open Port"]).to_csv(LOG_FILE, index=False)
        return

    data = {
        "Timestamp": [timestamp] * len(open_ports),
        "Target": [target] * len(open_ports),
        "Open Port": open_ports
    }

    df = pd.DataFrame(data)
    header = not os.path.exists(LOG_FILE)
    df.to_csv(LOG_FILE, mode='a', header=header, index=False)
    print(f"\n📁 Results saved to: {LOG_FILE}")

def validate_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def run():
    print("\n🌐 TCP Port Scanner")
    target = input("🔧 Enter target IP address: ").strip()

    if not validate_ip(target):
        print("❌ Invalid IP address format.")
        return

    open_ports = scan_ports(target)
    save_results(target, open_ports)
