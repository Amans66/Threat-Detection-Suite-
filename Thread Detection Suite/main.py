# main.py

from scanner import port_scanner, web_scanner
from ids import sniffer
from banner import print_banner
import subprocess
import sys

def show_menu():
    print("""
[1] 🔍 Run Port Scanner
[2] 🌐 Run Web Scanner
[3] 🛡️  Run IDS Sniffer
[4] 📊 Launch Dashboard
[5] ❌ Exit
""")

def run_module(choice):
    try:
        if choice == '1':
            port_scanner.run()
        elif choice == '2':
            web_scanner.run()
        elif choice == '3':
            sniffer.run()
        elif choice == '4':
            subprocess.run(["streamlit", "run", "dashboard/app.py"])
        elif choice == '5':
            print("\n👋 Exiting Threat Detection Suite. Stay Safe!")
            sys.exit(0)
        else:
            print("⚠️ Invalid choice. Please select 1–5.")
    except Exception as e:
        print(f"❌ Error occurred: {e}")

def main():
    print_banner()
    while True:
        try:
            show_menu()
            choice = input("🔧 Enter your choice: ").strip()
            run_module(choice)
        except KeyboardInterrupt:
            print("\n🛑 Interrupted by user. Exiting...")
            sys.exit(0)

if __name__ == "__main__":
    main()
