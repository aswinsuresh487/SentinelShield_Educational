# 🛡️ SentinelShield Educational WAF

> A Python-based Web Application Firewall for learning threat detection and prevention

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-Educational-yellow.svg)](LICENSE)

**SentinelShield** is an educational Web Application Firewall built with Flask that demonstrates real-world threat detection against OWASP Top 10 vulnerabilities. Developed as part of a cybersecurity internship at Unified Mentor.

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Usage](#-usage)
- [Testing](#-testing)
- [Project Structure](#-project-structure)
- [Results](#-results)
- [Limitations](#-limitations)
- [Future Enhancements](#-future-enhancements)
- [Contributing](#-contributing)
- [License](#-license)
- [Acknowledgments](#-acknowledgments)

---

## ✨ Features

- **Reverse Proxy Architecture** - Intercepts HTTP requests before they reach backend applications
- **Pattern-Based Detection** - Regex rules for SQL Injection, XSS, LFI, and Command Injection
- **Comprehensive Logging** - JSON-formatted logs for forensic analysis and incident response
- **Real-Time Dashboard** - HTML dashboard with attack metrics and visualization
- **Automated Testing** - Full test suite for regression testing and validation
- **Zero False Positives** - Tuned detection rules with 100% accuracy in testing

### Attack Detection Coverage

✅ **SQL Injection** - UNION SELECT, DROP TABLE, Boolean-based, Comment-based  
✅ **Cross-Site Scripting (XSS)** - Script tags, Event handlers, JavaScript protocols  
✅ **Local File Inclusion (LFI)** - Directory traversal, Absolute paths, Protocol wrappers  
✅ **Command Injection** - Command separators, Backticks, Shell metacharacters

---


**Key Components:**
- **simple_waf.py** - Core WAF reverse proxy with Flask
- **automated_tests.py** - Regression test suite
- **generate_report.py** - Dashboard and log analysis
- **logs/** - Request and attack logs (JSON format)

---

## 🔧 Prerequisites

Before you begin, ensure you have:

- **Operating System**: Kali Linux 2024 (or any Linux distribution)
- **Python**: Version 3.8 or higher
- **Docker**: For running DVWA backend
- **Git**: For cloning the repository

---

## 📥 Installation

Follow these steps to set up SentinelShield on your local machine.

### Step 1: Clone the Repository

bash
git clone https://github.com/aswinsuresh487/SentinelShield_Educational.git
cd SentinelShield_Educational


Step 2: Create Python Virtual Environment

python3 -m venv venv
source venv/bin/activate  # On Linux/Mac

Step 3: Install Python Dependencies

pip install flask requests

Step 4: Set Up DVWA Backend (Docker)
Pull and run the Damn Vulnerable Web Application

docker pull vulnerables/web-dvwa
docker run -d -p 8080:80 vulnerables/web-dvwa

Verify DVWA is running:
docker ps
curl http://localhost:8080

Step 5: Create Required Directories

mkdir -p logs tests reports

🚀 Usage

Starting the WAF
Activate virtual environment (if not already active):
source venv/bin/activate

Run the WAF:

python3 simple_waf.py

You should see:
 * Running on http://127.0.0.1:5000

The WAF is now intercepting all requests on port 5000 and proxying clean traffic to DVWA on port 8080.

Accessing the WAF
Application Access: http://localhost:5000 (routes through WAF to DVWA)

WAF Status Endpoint: http://localhost:5000/waf/status


Viewing Logs
All requests log:

cat logs/waf_log.txt

Blocked attacks only:

cat logs/blocked_attacks.txt

Generating Dashboard

python3 generate_report.py

Open the generated reports/dashboard.html in your browser to view:

Total requests and detection rate

Attack type distribution

Top attacker IPs



📁 Project Structure

SentinelShield_Educational/

├── simple_waf.py           # Core WAF implementation

├── automated_tests.py      # Automated test suite

├── generate_report.py      # Dashboard generator

├── kali_setup.sh          # Environment setup script

├── logs/

│   ├── waf_log.txt        # All requests (JSON)

│   └── blocked_attacks.txt # Malicious requests only

├── reports/
│   └── dashboard.html     # Generated security dashboard

├── tests/

│   └── manual_tests.md    # Manual testing documentation

├── venv/                  # Python virtual environment

└── README.md              # This file



