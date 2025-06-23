
import argparse
import csv
import os
from datetime import datetime
from termcolor import cprint
from scanner_core import (
    check_url_status,
    check_security_headers,
    check_mixed_content,
    check_xss,
    check_sql_injection,
    get_input_fields,
    check_cookie_flags
)

LOG_FILE = "logs/scan_log.csv"

def log_issue(url, scan_type, issue_type, details):
    """Log any issue found into CSV log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, url, scan_type, issue_type, details])

def scan_website(url):
    cprint(f"\n🔍 Starting Scan on {url}\n", "cyan", attrs=["bold"])

    risk_summary = {"High": 0, "Medium": 0, "Low": 0}

    # 1. URL Status
    cprint("➡️  Checking URL Status", "blue")
    result = check_url_status(url)
    if "error" in result:
        cprint(f"[ERROR] {result['error']}", "red")
        log_issue(url, "URL Status", "Error", result["error"])
        risk_summary["High"] += 1
    else:
        cprint(f"[URL Status] {result['status_code']} - {result['reason']}", "green")
        log_issue(url, "URL Status", "Status Code", f"{result['status_code']} - {result['reason']}")

    # 2. Security Headers
    cprint("➡️  Checking Security Headers", "blue")
    result = check_security_headers(url)
    if "missing_headers" in result and result["missing_headers"]:
        cprint(f"[Security Headers] Missing: {', '.join(result['missing_headers'])}", "yellow")
        log_issue(url, "Security Headers", "Missing Headers", ', '.join(result["missing_headers"]))
        risk_summary["Medium"] += 1
    else:
        cprint("[Security Headers] All important headers present", "green")

    # 3. Mixed Content
    cprint("➡️  Checking Mixed Content", "blue")
    result = check_mixed_content(url)
    if "insecure_links_found" in result and result["insecure_links_found"] > 0:
        cprint(f"[Mixed Content] Found {result['insecure_links_found']} insecure HTTP links.", "yellow")
        log_issue(url, "Mixed Content", "Insecure Links", f"{result['insecure_links_found']} found")
        risk_summary["Medium"] += 1
    elif "error" in result:
        cprint(f"[Mixed Content] {result['error']}", "red")
        risk_summary["High"] += 1
    else:
        cprint("[Mixed Content] No insecure content found", "green")

    # 4. XSS
    cprint("➡️  Testing for XSS", "blue")
    result = check_xss(url)
    if result.get("vulnerable"):
        cprint("[XSS] Vulnerable to reflected XSS!", "red")
        log_issue(url, "XSS", "Vulnerable", result.get("test_url", ""))
        risk_summary["High"] += 1
    else:
        cprint("[XSS] No reflected XSS detected", "green")

    # 5. SQL Injection
    cprint("➡️  Testing for SQL Injection", "blue")
    result = check_sql_injection(url)
    if result.get("vulnerable"):
        cprint("[SQL Injection] Vulnerable to SQLi!", "red")
        log_issue(url, "SQL Injection", "Vulnerable", result.get("test_url", ""))
        risk_summary["High"] += 1
    else:
        cprint("[SQL Injection] No SQLi detected", "green")

    # 6. Forms
    cprint("➡️  Checking for Forms", "blue")
    result = get_input_fields(url)
    if "forms_found" in result:
        cprint(f"[Forms] Found {result['forms_found']} forms.", "cyan")
        log_issue(url, "Form Scanner", "Forms Found", str(result["forms_found"]))
    elif "error" in result:
        cprint(f"[Forms] {result['error']}", "red")

    # 7. Cookie Flags
    cprint("➡️  Checking Cookie Flags", "blue")
    result = check_cookie_flags(url)
    if result.get("Secure") is False or result.get("HttpOnly") is False:
        cprint(f"[Cookies] Missing flags: {result}", "yellow")
        log_issue(url, "Cookies", "Missing Flags", str(result))
        risk_summary["Low"] += 1
    else:
        cprint("[Cookies] Secure & HttpOnly flags are set properly", "green")

    # Summary
    cprint("\n✅ Scan Complete", "cyan", attrs=["bold"])
    cprint("📊 Risk Summary:", "magenta")
    cprint(f"🔴 High: {risk_summary['High']} | 🟠 Medium: {risk_summary['Medium']} | 🔵 Low: {risk_summary['Low']}", "white", attrs=["bold"])
    cprint("📁 Logs saved to logs/scan_log.csv\n", "cyan")

def main():
    parser = argparse.ArgumentParser(description="Advanced Web Security Scanner (CLI)")
    parser.add_argument("--url", required=True, help="Website URL to scan")
    args = parser.parse_args()

    # Ensure logs folder exists
    if not os.path.exists("logs"):
        os.makedirs("logs")

    # Ensure log file exists
    if not os.path.isfile(LOG_FILE):
        with open(LOG_FILE, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Timestamp", "URL", "ScanType", "IssueType", "Details"])

    scan_website(args.url)

if __name__ == "__main__":
    main()

