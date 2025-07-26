# Threat-Detection-Suite-

readme_styled = """
# 🛡️ Threat Detection Suite – Multi-Layered Cyber Defense Toolkit 🔐  
**Author**: Aman Singh  
**GitHub**: [Amans66](https://github.com/Amans66)  
**LinkedIn**: Aman Singh  

---

## 📄 Description

**Threat Detection Suite** is an all-in-one Python-powered cybersecurity toolkit tailored for **penetration testing**, **vulnerability scanning**, and **network intrusion monitoring**. It integrates three powerful modules: a TCP port scanner, a web vulnerability detector, and an intrusion detection system (IDS), all topped off with a visual dashboard using **Streamlit**.

---

## 🔍 How is Threat Detection Suite Helpful?

🔹 **Port Security Audits**: Scan for open ports across a target IP to detect exposed services.  
🔹 **Web App Pen Testing**: Check for XSS, SQL Injection, and Broken Authentication vulnerabilities.  
🔹 **Network Monitoring**: Detect potential SYN flood attacks through packet sniffing.  
🔹 **Log Analysis & Visualization**: Built-in dashboard for visual summaries of all logs.  
🔹 **Modular CLI Interface**: Each module runs independently through an intuitive terminal menu.  
🔹 **Educational Tool**: Perfect for ethical hackers and cybersecurity learners.

---

## 🛠️ Where Can You Use It?

✔ **University/College Cyber Labs** – Practice ethical hacking and IDS techniques.  
✔ **CTF Challenges** – Analyze attack patterns and scan challenge servers.  
✔ **Personal Pen-Testing Projects** – Secure your own website or systems.  
✔ **Red Team Simulations** – Conduct basic recon and vulnerability testing.  
✔ **Network Admin Use** – Monitor internal infrastructure for unintentional exposures.  
✔ **Offline Demonstration** – Works completely offline post setup.

---

## ⚙️ Installation & Setup

### Step 1: Install Python Dependencies

python3 -m venv venv
source venv/bin/activate

# Update system & install Python dependencies
sudo apt update && sudo apt install python3-pip -y
pip install -r Requirement.txt

# Step 2: Clone This Repository
git clone https://github.com/Amans66/Threat-Detection-Suite.git
cd Threat-Detection-Suite

# Step 3: Run the Tool
python3 main.py

# 🚦 How It Works
1️⃣ Port Scanner: Scans TCP ports 1–1024 and logs open ones to logs/port_scan_results.csv
2️⃣ Web Scanner: Injects test payloads into URLs and logs vulnerable endpoints
3️⃣ IDS Sniffer: Captures packets to detect SYN flood signs (logs to logs/alerts.csv)
4️⃣ Dashboard: Summarizes scan and IDS logs via an interactive interface

# 💻 Example Output
Port Scanner

🔧 Enter target IP: 192.168.0.1  
✅ Port 22 is OPEN  
✅ Port 80 is OPEN  
📁 Results saved to: logs/port_scan_results.csv
Web Scanner


🔧 Enter URL: https://example.com  
✅ SQLi Vulnerable: Yes  
✅ XSS Vulnerable: No  
📁 Results saved to: logs/web_scan_results.csv
IDS Sniffer


🛑 ALERT: SYN Flood detected from 192.168.0.105  
📁 Alerts saved to: logs/alerts.csv

# 🧪 Tested On
Platform	Support Level
Linux	✅ Excellent
Android (Termux)	✅ Excellent
Windows	⚠️ WSL Recommended
MacOS	✅ Good
BSD	❓ Untested

# ⚠️ Disclaimer
🚨 This tool is developed strictly for educational and legal security research purposes. Unauthorized usage is illegal. The author holds no responsibility for misuse.

# 🙌 Support
If you found this project useful:
# ⭐ Star the repo on GitHub → github.com/Amans66
# 💬 Share it with fellow ethical hackers and security learners.
