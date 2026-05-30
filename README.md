AI Web Security Scanner 🛡️

AI Web Security Scanner is an advanced cybersecurity auditing platform built with Python, Flask, Nmap, SQLite, and NVIDIA AI models. The system performs automated web security assessments by analyzing open ports, service versions, HTTP security headers, exposed services, and subdomain infrastructure. It combines traditional security scanning with AI-powered vulnerability intelligence to generate comprehensive security reports and actionable remediation recommendations.

Key Features
🔍 Automated Nmap-based network and service scanning
🌐 Security header analysis and HTTPS verification
🛰️ Subdomain reconnaissance and discovery
🧠 AI-powered vulnerability assessment using NVIDIA NIM models
🚨 Vulnerability intelligence mapping with CVE references
🕵️ Honeypot and deception-risk detection
📄 Professional PDF security report generation
👤 User authentication and scan history management
💾 SQLite-based report storage and retrieval
⚡ Real-time scan progress streaming using Server-Sent Events (SSE)
How It Works
Users authenticate and submit a target website.
The scanner resolves the target domain and performs a fast Nmap service scan.
HTTP security headers are inspected for missing or insecure configurations.
Common subdomains are enumerated and analyzed.
Open services are matched against a built-in vulnerability intelligence database.
Deception and honeypot detection algorithms evaluate scan results.
Scan findings are summarized and sent to NVIDIA AI models for advanced analysis.
The AI generates a detailed cybersecurity assessment with severity ratings, CVE mappings, impact analysis, and remediation steps.
Results are stored in SQLite and can be exported as professional PDF reports.
Technology Stack
Python
Flask
SQLite
Nmap
NVIDIA NIM API
OpenAI SDK
ReportLab
Gunicorn
Requests

Project Goal
The platform helps security professionals, penetration testers, students, and website administrators quickly identify potential security weaknesses, understand associated risks, and receive AI-generated remediation guidance through a centralized web interface.

Designed And Developed By Nexvora 


The platform helps security professionals, penetration testers, students, and website administrators quickly identify potential security weaknesses, understand associated risks, and receive AI-generated remediation guidance through a centralized web interface.
