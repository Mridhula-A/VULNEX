# 🛡️ VULNEX – Security Intelligence Center

### Scan. Analyze. Assess. Secure.

**VULNEX** is a Python-based vulnerability assessment platform designed to identify exposed network services, analyze potential security risks, retrieve vulnerability intelligence and generate structured security reports through a modern web dashboard.

Built with Python and Flask, VULNEX combines network scanning capabilities, service detection, CVE intelligence and risk assessment into one centralized security interface.

---

## 🚀 Key Features

| Feature               | Description                                                 |
| --------------------- | ----------------------------------------------------------- |
| 🔍 TCP Port Scanning  | Identifies open ports using Python socket-based scanning    |
| 🌐 Network Discovery  | Supports CIDR-based host discovery through Nmap             |
| 🧩 Service Detection  | Identifies services and versions using Nmap                 |
| 📡 Packet Analysis    | Optional Scapy-based SYN packet checks                      |
| 🛡️ CVE Intelligence  | Retrieves vulnerability information through the NVD API     |
| ⚠️ Risk Assessment    | Analyzes discovered findings and their security severity    |
| 📊 Security Dashboard | Displays scan statistics, results and security insights     |
| 📜 Scan History       | Stores previous scan records using SQLite                   |
| 📄 Report Generation  | Exports assessment reports in PDF, CSV and JSON formats     |
| 👁️ Report Preview    | Allows users to preview scan reports through the dashboard  |
| ⚡ Background Scanning | Executes scan jobs in the background with progress tracking |

---

## 🖥️ Technology Stack

| Category                   | Technologies            |
| -------------------------- | ----------------------- |
| Programming Language       | Python                  |
| Backend Framework          | Flask                   |
| Frontend                   | HTML5, CSS3, JavaScript |
| UI Framework               | Bootstrap 5             |
| Network Scanning           | Python Socket, Nmap     |
| Packet Analysis            | Scapy                   |
| Vulnerability Intelligence | NVD CVE API 2.0         |
| Database                   | SQLite                  |
| Report Generation          | ReportLab, CSV, JSON    |
| Development Environment    | Visual Studio Code      |
| Browser Support            | Chrome, Firefox, Edge   |

---

## ⚙️ How VULNEX Works

VULNEX follows a structured vulnerability assessment workflow:

1. **Target Input** – The user enters an IP address, hostname or supported CIDR network range.
2. **Authorization** – The user confirms that they are authorized to assess the target.
3. **Network Scanning** – TCP socket checks and supported scanning tools identify accessible services.
4. **Service Detection** – Nmap helps identify running services and their versions.
5. **CVE Lookup** – Discovered service information can be used to retrieve relevant vulnerability intelligence from the NVD API.
6. **Risk Assessment** – Findings are analyzed and categorized by severity.
7. **Result Storage** – Scan information is stored in the SQLite database.
8. **Report Generation** – Results can be previewed and exported into PDF, CSV and JSON formats.

---

## 🏗️ Project Architecture

```text
VULNEX/
│
├── app.py
├── main.py
├── config.py
├── requirements.txt
├── README.md
├── .gitignore
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
├── templates/
│   └── index.html
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── script.js
│
├── utils/
│   └── validators.py
│
├── gui/
│   └── dashboard.py
│
├── data/
└── exports/
```

---

## 💻 Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR-USERNAME/VULNEX.git
```

### 2. Navigate to the Project Directory

```bash
cd VULNEX
```

### 3. Create a Virtual Environment

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Install Nmap

Install Nmap separately if you want to use its network discovery and service detection features.

Official website: [https://nmap.org/download.html](https://nmap.org/download.html)

### 6. Run the Application

```bash
python app.py
```

### 7. Open the Dashboard

Visit the following address in your browser:

```text
http://127.0.0.1:5000
```

---

## 📊 Report Formats

VULNEX supports multiple report formats to make assessment results easier to review and share.

- **PDF:** Structured vulnerability assessment reports.
- **CSV:** Tabular scan findings for spreadsheet analysis.
- **JSON:** Structured results for further processing and integration.

---

## 🔐 Security & Responsible Usage

VULNEX is developed for educational purposes and authorized security assessments.

- Scan only systems and networks for which you have explicit permission.
- Do not use the tool to access or disrupt unauthorized systems.
- Keep API credentials and sensitive configuration outside public repositories.
- Handle scan results and discovered network information responsibly.
- Ensure that third-party tools are installed and configured correctly.

**Disclaimer:** The developer is not responsible for misuse, unauthorized scanning or damage caused by improper use of this software.

---

## 🔮 Future Enhancements

Potential areas for future development include:

- Advanced vulnerability correlation.
- Enhanced network visualization.
- Additional scanning modules.
- Improved vulnerability prioritization.
- Advanced reporting and assessment analytics.
- User authentication and access management.

---

## 👩‍💻 Project Information

**Project Name:** VULNEX – Security Intelligence Center
**Project Category:** Cybersecurity / Vulnerability Assessment
**Project Type:** Python-Based Web Application
**Primary Language:** Python

---

## ⭐ Support

If you find VULNEX interesting, consider giving this repository a ⭐ on GitHub.

Contributions, suggestions and constructive feedback are welcome!

---

\<p align="center">   \<b>VULNEX – Security Intelligence Center\</b>\<br>   \<i>Detect Vulnerabilities. Strengthen Security.\</i> \</p>

\<p align="center">   Built with Python and a passion for Cybersecurity. 💜 \</p>
