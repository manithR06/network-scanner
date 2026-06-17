# NetScanner — Intelligent Network Security Assessment Platform

A professional web-based network security scanner built with Python and Flask.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Flask](https://img.shields.io/badge/Flask-3.x-green)
![Nmap](https://img.shields.io/badge/Nmap-7.x-red)

## Features

- Automated Nmap network scanning
- Risk scoring system (Low / Medium / High / Critical)
- CVE vulnerability lookup via NVD API
- Professional PDF report generation
- Scheduled automatic scanning
- Email alerts for high risk findings
- Scan history and management
- Dashboard with charts

## Tech Stack

- Backend — Python, Flask, SQLAlchemy, SQLite
- Scanner — Nmap, python-nmap
- Frontend — Bootstrap 5, Chart.js
- Reports — ReportLab
- Scheduler — APScheduler

## Setup

### 1. Clone the repo

git clone https://github.com/YOUR_USERNAME/network-scanner.git
cd network-scanner

### 2. Install dependencies

pip install flask flask-sqlalchemy python-nmap reportlab apscheduler requests python-dotenv

### 3. Configure environment

cp .env.example .env

### 4. Run the app

sudo python3 app.py

### 5. Open in browser

http://127.0.0.1:5000

## Legal Notice

This tool is for authorized network security testing only.
Never scan networks you do not own or have explicit written permission to test.
Unauthorized network scanning is illegal in most countries.

## Author

github.com/manithR06
EOF
