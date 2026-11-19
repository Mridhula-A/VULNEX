# VULNEX – Security Intelligence Center

**VULNEX** is a Python-based web vulnerability assessment tool designed to help users identify exposed network ports, detect running services, analyze potential security risks, and retrieve related vulnerability intelligence.

The application combines network scanning technologies, NVD CVE intelligence, risk analysis, SQLite database storage, and downloadable security reports through an interactive web dashboard.

**Purpose:** Educational and authorized security assessment.

## Features

### Network Scanning
- TCP port scanning using Python socket connections.
- Optional Nmap service and version detection.
- Optional Scapy-based TCP SYN scanning.
- Single-host scanning.
- CIDR network discovery using Nmap.

### Vulnerability Intelligence
- NVD CVE API integration.
- Service and product-based CVE lookup.
- CVE severity analysis using available CVSS information.
- Risk assessment of detected services.
- Security findings and severity summaries.

### Security Dashboard
- Interactive Flask-based web interface.
- Scan progress monitoring.
- Dashboard statistics and risk charts.
- Recent scan activity.
- Scan history and individual scan details.
- Report preview.

### Reporting and Storage
- SQLite database for persistent scan history.
- PDF report generation.
- CSV report generation.
- JSON report generation.

## Technology Stack

| Component | Technology |
|---|---|
| Programming Language | Python |
| Backend | Flask |
| Frontend | HTML5, CSS3, JavaScript |
| UI Framework | Bootstrap 5 |
| Database | SQLite |
| Network Scanning | Python Sockets |
| Additional Scanning | Nmap, Scapy |
| Vulnerability Intelligence | NVD CVE API 2.0 |
| Report Generation | ReportLab, CSV, JSON |
| Visualization | Chart.js |

## Project Structure

```text
Vulnerability-Scanner/
│
├── app.py
├── main.py
├── config.py
├── requirements.txt
├── README.md
│
├── database/
│   └── db_manager.py
│
├── scanner/
│   ├── socket_scanner.py
│   ├── nmap_scanner.py
│   ├── scapy_scanner.py
│   └── service_detector.py
│
├── vulnerability/
│   ├── cve_matcher.py
│   ├── nvd_api.py
│   └── risk_analyzer.py
│
├── reports/
│   └── report_generator.py
│
├── utils/
│   └── validators.py
│
├── templates/
│   └── index.html
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── script.js
│
├── data/
├── database/
└── exports/
```

## Requirements

- Python 3.10 or later.
- Nmap installed and available in PATH (required for CIDR network discovery).
- Npcap on Windows for Scapy packet operations.
- Appropriate privileges for packet-based SYN scanning.
- Internet access for NVD vulnerability lookups.

Socket-based TCP scanning does not require administrator privileges.

## Installation – Windows

Clone or download the project and open PowerShell in the project directory.

```powershell
cd Vulnerability-Scanner

py -m venv .venv

.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip

pip install -r requirements.txt
```

If PowerShell blocks virtual environment activation:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

.venv\Scripts\Activate.ps1
```

## Running VULNEX

Start the Flask application:

```powershell
python app.py
```

Open your browser and visit:

**http://127.0.0.1:5000**

To stop the application, press `Ctrl + C` in the terminal.

## Nmap Configuration

Nmap is used for service detection and CIDR network discovery.

Download Nmap:

https://nmap.org/download.html

Ensure the Nmap executable is available through the system PATH.

The socket scanner can still be used independently when Nmap is unavailable, although network discovery requires Nmap.

## NVD API Configuration

VULNEX integrates with the National Vulnerability Database (NVD) CVE API 2.0.

An optional NVD API key can be configured to improve request limits.

Request an API key:

https://nvd.nist.gov/developers/request-an-api-key

The key is stored locally through the application's configuration. Do not publish or share configuration files containing API credentials.

## Application Workflow

1. Enter an authorized target IP address, hostname, or supported network range.
2. Configure the ports to assess.
3. Select the required scanning engines.
4. Confirm authorization to scan the target.
5. Initiate the security assessment.
6. Monitor scan progress.
7. Review detected services and potential CVE matches.
8. Examine risk summaries and scan history.
9. Preview and export assessment reports.

## Report Formats

VULNEX supports three report formats:

- **PDF:** Readable security assessment report.
- **CSV:** Structured data for spreadsheet analysis.
- **JSON:** Machine-readable assessment results.

## Security and Responsible Use

VULNEX is intended exclusively for systems owned by the user or systems for which explicit authorization has been granted.

- Never scan systems without permission.
- Use conservative scanning configurations.
- Protect API keys and locally stored assessment data.
- Follow applicable laws and organizational security policies.

## Limitations

- An open port does not automatically indicate a vulnerability.
- CVE matches are potential candidates and may contain false positives.
- Exact product versions, configurations, and affected-version ranges must be independently verified.
- NVD lookup results depend on API availability and network connectivity.
- Scapy packet operations depend on suitable privileges and packet-capture support.
- Scan results are assessment indicators, not proof that a system is secure or vulnerable.

## Disclaimer

VULNEX is an educational security assessment project. It is not a replacement for professional penetration testing, comprehensive vulnerability management, or independent security audits.

**Use responsibly. Scan only with proper authorization.**