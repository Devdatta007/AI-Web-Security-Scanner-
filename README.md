# AI Web Security Scanner
Live URL :https://ai-web-security-scanner.onrender.com

AI Web Security Scanner is a next-generation AI-powered cybersecurity platform designed to automate web vulnerability detection, network reconnaissance, and intelligent security auditing.

The project combines:

- Nmap-based port scanning
- HTTP security header analysis
- Subdomain reconnaissance
- AI-generated cybersecurity reports
- PDF report generation
- Real-time scan logging
- SQLite-based report storage
- Authentication system for users

The platform is capable of identifying security weaknesses such as:

- Missing security headers
- Exposed services and ports
- Potential CVE-linked vulnerabilities
- SSL/TLS misconfigurations
- Honeypot/deception risks
- Publicly exposed sensitive services



## Features

### Intelligent Port Scanning
- Fast Nmap-powered service detection
- Service/version fingerprinting
- Vulnerability intelligence mapping
- Open port analysis

### AI Security Reporting
- NVIDIA NIM + Mistral AI integration
- Automated executive summaries
- Vulnerability analysis tables
- Strategic remediation planning
- Technical deep-dive reporting

### Security Header Analysis
- Detects missing:
  - CSP
  - HSTS
  - X-Frame-Options
  - Referrer-Policy
  - X-XSS-Protection

### Subdomain Reconnaissance
- Automatic subdomain discovery
- DNS resolution analysis
- Attack surface expansion detection

### Honeypot Detection
- AI deception analysis engine
- Port density heuristics
- Service banner analysis
- Honeypot signature detection

### PDF Security Reports
- Professional audit report generation
- Markdown table rendering
- Structured vulnerability summaries

### Authentication & History
- User login/register system
- Persistent scan history
- SQLite database integration


## Tech Stack

### Backend
- Python
- Flask
- SQLite

### Security Tools
- Nmap
- Requests
- Socket Programming

### AI Integration
- NVIDIA NIM API
- OpenAI SDK
- Mistral Large Model
- Llama 3.1

### Reporting
- ReportLab PDF Engine

                                
## Project Structure

```bash
├── app.py
├── scanner.py
├── ai_reporter.py
├── report_generator.py
├── database.py
├── app.db
├── README.md
├── .env

© 2026 Nexvora. All rights reserved.


