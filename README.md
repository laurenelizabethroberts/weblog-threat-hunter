# Web Log Threat Hunter
[![CI](https://github.com/laurenelizabethroberts/weblog-threat-hunter/actions/workflows/ci.yml/badge.svg)](https://github.com/laurenelizabethroberts/weblog-threat-hunter/actions/workflows/ci.yml)
![Python 3.11](https://img.shields.io/badge/python-3.11-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)


# Overview

The Web Log Threat Hunter project is a security analysis tool designed to help security analysts and researchers quickly detect potential threats within web server logs. It focuses on identifying suspicious patterns such as brute-force attempts, SQL injection probes, directory traversal, and other common attack techniques.

This tool provides actionable insights by highlighting top talkers, anomalous requests, error patterns, and suspicious IP addresses to accelerate incident response and threat hunting.

Features

* Parse and analyze Apache/Nginx web logs

* Detect suspicious activity such as:

  * SQL injection attempts

  * XSS payloads

  * Directory traversal patterns

  * Authentication brute-force

* Generate summary reports with top talkers (IP, user agents, endpoints)

* CLI-based for fast triage

* Export results to structured reports

# How to Run:

## Installation

Clone the repository and set up your environment:
git clone https://github.com/laurenelizabethroberts/weblog-threat-hunter.git

## Create a Virtual Environment
python -m venv .venv
source .venv/bin/activate   # Linux/Mac
.venv\Scripts\activate      # Windows

## Install Dependencies
pip install -r requirements.txt

## Run the Tool
python webloghunter.py -i samples/access.log -o reports -c config.yaml --top-talkers 5
Options (arguments explained):

-i → Input log file

-o → Output directory for reports

-c → Config file for detection rules

--top-talkers → Number of top IPs/endpoints to display
You can edit config.yaml to add or remove detection rules. Each rule uses regex patterns to catch suspicious requests (SQLi, XSS, brute force, etc.).

## View the Results
The tool generates a markdown or CSV report in the reports/ folder.
reports/example.md

# Detection Coverage

| Pattern Type | Detection Method | Output Field | MITRE ATT&CK |
|---------------|-----------------|---------------|---------------|
| Brute-force login | Regex on `/login` + 401 codes > X | `failed_auth` | T1110 |
| SQL injection | Regex for `(\%27)|(')|(--)|(\%23)` | `sql_injection` | T1190 |
| Path Traversal | Detect `../` or `\..\` | `traversal` | T1006 |
| Reconnaissance scans | Count unique IPs per endpoint | `scanner` | T1595 |
| Data exfil volume | Bytes > threshold per IP | `exfil` | T1567 |

# Example Output:
[INFO] Processing logs...
[INFO] Top 5 IP addresses:
   192.168.1.20 (230 requests)
   203.0.113.45 (195 requests, flagged: brute force)
[INFO] Suspicious patterns detected: 4
   - SQL injection attempt from 203.0.113.45
   - Directory traversal from 198.51.100.12

# Project Structure
web-log-threat-hunter/

├── samples/              # Example log files

├── reports/              # Generated reports

├── config.sample.yaml    # Example configuration

├── webloghunter.py       # Main script

├── requirements.txt      # Dependencies

└── README.md             # Project documentation


# Use Cases
* Security Operations Centers (SOC) for rapid log triage

* Incident response teams analyzing suspicious traffic

* Blue-teamers building detection playbooks

* Cybersecurity students practicing log analysis


# License

Distributed under the MIT License. See LICENSE for more information.




