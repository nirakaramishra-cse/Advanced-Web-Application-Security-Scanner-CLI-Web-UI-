

<h1 align="center">🔐 Advanced Web Application Security Scanner</h1>

<p align="center">
  <b>A Python-based web vulnerability scanner with both CLI & Flask Web UI support.</b><br>
  Detects common web security issues like <i>XSS</i>, <i>SQL Injection</i>, and <i>insecure headers</i>. Ideal for students, ethical hackers, and developers.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-blue?logo=python">
  <img src="https://img.shields.io/badge/Flask-Web_Framework-lightgrey?logo=flask">
  <img src="https://img.shields.io/badge/Project--Type-Cybersecurity-green">
  <img src="https://img.shields.io/badge/UI-Dual_Option-blueviolet">
</p>

---

## 🧠 Project Overview

This project is a lightweight yet powerful scanner that helps developers and security testers identify basic vulnerabilities in web applications. It offers:

- 🖥️ Command-Line Interface (CLI) for fast usage
- 🌐 Web-based UI with charts, logging, and export options
- 📊 Real-time results and severity visualization
- 🧾 CSV + Excel export functionality

---

## ✨ Key Features

- ✅ **XSS Detection** – Scans form inputs for reflected scripts  
- ✅ **SQL Injection Detection** – Detects vulnerable parameters  
- ✅ **Security Header Check** – Looks for missing CSP, X-Frame-Options, etc.  
- ✅ **Cookie Flag Analysis** – Checks for Secure and HttpOnly attributes  
- ✅ **Dual Mode** – CLI and Flask Web Dashboard  
- ✅ **CSV Logging & Excel Export**  
- ✅ **Pie Chart Visualization** with Chart.js  
- ✅ **Searchable Log Viewer**

---

## 📸 Screenshots

<p align="center">
    <img src="screenshots/scan_ui .png" alt="Scan UI" width="800"><br>
  <em>Figure 1: Web UI to scan dashboard</em><br><br>
  <img src="screenshots/scan_ui 1.png" alt="Scan UI" width="800"><br>
  <em>Figure 2: Web UI to scan target URL</em><br><br>
  <img src="screenshots/chart_pie .png" alt="Chart" width="800"><br>
  <em>Figure 3: Vulnerability severity visualization</em><br><br>
  <img src="screenshots/log_export .png" alt="Export" width="800"><br>
  <em>Figure 4: Log export feature in Excel</em>
  <img src="screenshots/filter logs 1.png" alt="Export" width="800"><br>
  <em>Figure 5: Log serch feature in Filter</em>
  <img src="screenshots/Sample CLI Output.png" alt="Export" width="800"><br>
  <em>Figure 6: CLI Scan Testing Output</em>
  <img src="screenshots/logs page.png" alt="Export" width="800"><br>
  <em>Figure 7: Previous Scan History visualization</em>
</p>

---

## 🛠 Technologies Used

| Area          | Tool/Library           |
|---------------|------------------------|
| Backend       | Python 3.x, Flask      |
| Frontend      | HTML, Bootstrap 5      |
| Visualization | Chart.js               |
| HTTP Requests | requests, BeautifulSoup|
| Data Handling | pandas, openpyxl       |

---

## 📂 Project Structure

Advanced-web-Scanner/
- ├── app.py # Flask Web App
- ├── scanner.py # CLI Interface
- ├── scanner_core.py # Core Scanning Logic
- ├── scan_log.csv # CSV log storage
- ├── exported_logs.xlsx # Excel Exported File
- ├── requirements.txt # Dependencies
- ├── templates/
- │ ├── index.html # Web scan UI
- │ └── logs.html # Log history UI
- ├── screenshots/ # UI & Result Images
- ├── static/ # Optional JS/CSS

---

## ▶️ How to Run

### 🔹 1. Clone the Repository

```bash
git clone https://github.com/nirakaramishra-cse/Advanced-Web-Application-Security-Scanner-CLI-Web-UI-.git
cd Advanced-Web-Application-Security-Scanner-CLI-Web-UI-
```

### 🔹 2. (Optional) Create Virtual Environment

```bash
python -m venv venv  
source venv/bin/activate
# On Windows: venv\Scripts\activate
```

### 🔹 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 🔹 4. Run the Web UI

```bash
python app.py
```
Then open http://localhost:5000 in your browser.

### 🔹 5. Run from CLI

```bash
python scanner.py --url https://example.com
```
---

## 🧪 Scan Capabilities

| Scan Type        | What It Does                                 |
| ---------------- | -------------------------------------------- |
| **XSS**              | Checks form fields for reflected payloads    |
| **SQL Injection**    | Tests GET parameters for injection points    |
| **Security Headers** | Verifies CSP, X-Frame-Options, etc.          |
| **Cookie Flags**     | Checks for HttpOnly and Secure attributes    |
| **Mixed Content**    | Detects insecure (HTTP) links on HTTPS sites |

---

## 📁 Sample Log Output (CSV)

```besh
Timestamp, URL, Scan Type, Issue Type, Details
2025-06-18 16:00:01, https://abc.com, XSS, Vulnerability, XSS found in form input
```
---

## 📤 Export Logs

* Visit /logs → Click “Export to Excel” to download .xlsx version of the scan log.
* All entries are formatted and timestamped for auditing.

---

## 🚀 Future Enhancements

- 🌍 Add site-wide spidering module

- 🔐 Support login-protected scans (sessions)

- 📅 Schedule automated scans

- 🔗 REST API for remote usage

- ☁ Deploy to Render/Heroku for public access

---

## ⚠️ Disclaimer

- This tool is strictly for **educational** and **authorized testing** purposes.
- Do **NOT** use it against websites without proper permission.
- The author holds no responsibility for misuse.

---

# 🤝 Contributing to this 

We welcome contributions!
This project is built to help students and beginners learn web application security through hands-on scanning tools.

- Fork the repo
- Create a new branch
- Make your changes
- Submit a pull request

---

## 🙋 About the Author

Created by **Nirakara Mishra**
- 🎓 B.Tech in Computer Science & Engineering
- 🎓 Specialization: Cybersecurity
- **🌐 Portfolio:**  [https://nirakaramishra-cse.github.io/Portfolio] 
- **🔗 LinkedIn:**  [https://www.linkedin.com/in/nirakaramishra-cse] 
- **🔗 GitHub:**  [https://github.com/nirakaramishra-cse] 

