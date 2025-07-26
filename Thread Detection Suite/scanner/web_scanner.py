# scanner/web_scanner.py

import requests
from bs4 import BeautifulSoup
import pandas as pd
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse, urljoin
from datetime import datetime
import os

LOG_FILE = "logs/web_scan_results.csv"

def test_broken_authentication(url):
    try:
        protected_path = "/admin"
        test_url = urljoin(url, protected_path)
        response = requests.get(test_url, timeout=5, allow_redirects=False)

        if response.status_code in [200, 302]:
            if "login" not in response.text.lower() and "password" not in response.text.lower():
                return True
    except Exception as e:
        print(f"❌ Broken Auth check failed: {e}")
    return False

def test_xss(url):
    import requests
    payload = "<script>alert('XSS')</script>"
    try:
        test_url = url + "?q=" + payload
        response = requests.get(test_url, timeout=5)
        return payload in response.text
    except Exception as e:
        print(f"❌ XSS test failed: {e}")
        return False


def test_sqli(url):
    payload = "' OR 1=1--"
    test_url = f"{url}?id={payload}"
    try:
        response = requests.get(test_url, timeout=5)
        return any(k in response.text.lower() for k in ["error", "sql", "syntax", "warning"])
    except Exception as e:
        print(f"❌ SQLi check failed: {e}")
        return False

def run_tests(url):
    print(f"\n🔍 Running Web Vulnerability Tests on: {url}")
    return {
        "Timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "URL": url,
        "XSS": test_xss(url),
        "SQLi": test_sqli(url),
        "Broken Authentication": test_broken_authentication(url)
    }

def save_result(result):
    os.makedirs("logs", exist_ok=True)
    df = pd.DataFrame([result])
    header = not os.path.exists(LOG_FILE)
    df.to_csv(LOG_FILE, mode='a', header=header, index=False)
    print(f"\n📁 Results saved to: {LOG_FILE}")

def validate_url(url):
    parsed = urlparse(url)
    return all([parsed.scheme, parsed.netloc])

def run():
    print("\n🌐 Web Vulnerability Scanner")
    url = input("🔧 Enter full target URL (e.g., https://example.com/page): ").strip()

    if not validate_url(url):
        print("❌ Invalid URL format.")
        return

    result = run_tests(url)
    save_result(result)

    print("\n🧪 Scan Summary:")
    print(f" - Target: {result['URL']}")
    print(f" - XSS Vulnerable: {'✅ Yes' if result['XSS'] else '❌ No'}")
    print(f" - SQLi Vulnerable: {'✅ Yes' if result['SQLi'] else '❌ No'}")
    print(f" - Broken Authentication: {'✅ Yes' if result['Broken Authentication'] else '❌ No'}")
