
from flask import Flask, render_template, request, redirect, url_for, send_file
from scanner_core import (
    check_url_status,
    check_security_headers,
    check_mixed_content,
    check_xss,
    check_sql_injection,
    get_input_fields,
    check_cookie_flags
)
import csv
import os
from datetime import datetime
import pandas as pd

app = Flask(__name__)

LOG_FILE = "logs/scan_log.csv"

def log_issue(url, scan_type, issue_type, details):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, url, scan_type, issue_type, details])

def classify_risk(scan_type, issue_type):
    scan_type = scan_type.lower()
    issue_type = issue_type.lower()

    if any(x in scan_type for x in ["xss", "sql injection", "url status"]) and "vulnerable" in issue_type:
        return "High"
    elif "security headers" in scan_type or "mixed content" in scan_type:
        return "Medium"
    elif "cookies" in scan_type:
        return "Low"
    return "Low"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    results = {}
    chart_data = {"High": 0, "Medium": 0, "Low": 0}

    res = check_url_status(url)
    if "error" in res:
        results['URL Status'] = res
        log_issue(url, "URL Status", "Error", res["error"])
        chart_data["High"] += 1
    else:
        results['URL Status'] = res
        log_issue(url, "URL Status", "Status", f"{res['status_code']} - {res['reason']}")

    res = check_security_headers(url)
    if "missing_headers" in res and res["missing_headers"]:
        results['Security Headers'] = res
        log_issue(url, "Security Headers", "Missing", ", ".join(res["missing_headers"]))
        chart_data["Medium"] += 1
    else:
        results['Security Headers'] = {"message": "All headers present"}

    res = check_mixed_content(url)
    if "insecure_links_found" in res and res["insecure_links_found"] > 0:
        results['Mixed Content'] = res
        log_issue(url, "Mixed Content", "Insecure Links", str(res["insecure_links_found"]))
        chart_data["Medium"] += 1
    else:
        results['Mixed Content'] = {"message": "No mixed content found"}

    res = check_xss(url)
    if res.get("vulnerable"):
        results['XSS'] = res
        log_issue(url, "XSS", "Vulnerable", res.get("test_url", ""))
        chart_data["High"] += 1
    else:
        results['XSS'] = {"message": "No XSS detected"}

    res = check_sql_injection(url)
    if res.get("vulnerable"):
        results['SQL Injection'] = res
        log_issue(url, "SQL Injection", "Vulnerable", res.get("test_url", ""))
        chart_data["High"] += 1
    else:
        results['SQL Injection'] = {"message": "No SQLi detected"}

    res = get_input_fields(url)
    if "forms_found" in res:
        results['Forms'] = res
        log_issue(url, "Form Scanner", "Forms Found", str(res["forms_found"]))
    else:
        results['Forms'] = res

    res = check_cookie_flags(url)
    if res.get("Secure") is False or res.get("HttpOnly") is False:
        results['Cookies'] = res
        log_issue(url, "Cookies", "Missing Flags", str(res))
        chart_data["Low"] += 1
    else:
        results['Cookies'] = {"message": "Secure and HttpOnly set"}

    return render_template("index.html", url=url, results=results, chart_data=chart_data)

@app.route('/logs')
def logs():
    if not os.path.exists(LOG_FILE):
        return render_template("logs.html", logs=[], chart_data={"High": 0, "Medium": 0, "Low": 0})

    with open(LOG_FILE, newline='') as file:
        reader = csv.DictReader(file)
        logs = list(reader)

    chart_data = {"High": 0, "Medium": 0, "Low": 0}
    for row in logs:
        risk = classify_risk(row["ScanType"], row["IssueType"])
        row["RiskLevel"] = risk
        chart_data[risk] += 1

    return render_template("logs.html", logs=logs, chart_data=chart_data)

@app.route('/export')
def export():
    if not os.path.exists(LOG_FILE):
        return "No log file to export"
    
    df = pd.read_csv(LOG_FILE)
    export_file = "logs/exported_logs.xlsx"
    df.to_excel(export_file, index=False)
    
    return send_file(export_file, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)

