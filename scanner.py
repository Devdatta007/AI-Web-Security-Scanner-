import nmap
import requests
import urllib.parse
import socket
import json

# Lightweight mapping of common services to known vulnerability patterns
# In a production app, this would query an actual CVE API like Vulners or NVD.
VULNERABILITY_DB = {
    "ssh": [
        {"version_pattern": "7.2", "risk": "High", "cve": "CVE-2016-6210", "info": "Enumeration vulnerability found in OpenSSH 7.2."},
        {"version_pattern": "any", "risk": "Medium", "info": "SSH exposed to public internet may be subject to brute-force attacks."}
    ],
    "http": [
        {"version_pattern": "Apache/2.4.49", "risk": "Critical", "cve": "CVE-2021-41773", "info": "Path traversal and file disclosure vulnerability."},
        {"version_pattern": "any", "risk": "Low", "info": "HTTP service detected. Ensure security headers are properly configured."}
    ],
    "mysql": [
        {"version_pattern": "any", "risk": "High", "info": "MySQL exposed publicly. Risk of database credential brute-forcing and unauthorized access."}
    ],
    "rdp": [
        {"version_pattern": "any", "risk": "High", "info": "Remote Desktop exposed. High risk of BlueKeep (CVE-2019-0708) or brute-force if not patched."}
    ],
    "ftp": [
        {"version_pattern": "any", "risk": "Medium", "info": "FTP often transmits credentials in plaintext. Use SFTP or FTPS instead."}
    ]
}

def lookup_vulnerabilities(service_name, version_str):
    """Matches service/version against local intelligence database."""
    matches = []
    service_key = service_name.lower()
    
    if service_key in VULNERABILITY_DB:
        for entry in VULNERABILITY_DB[service_key]:
            pattern = entry.get("version_pattern", "any")
            if pattern == "any" or (version_str and pattern in version_str):
                matches.append(entry)
    
    return matches

def analyze_deception_risk(open_ports, nm_host_info, target_ip):
    """
    Analyzes port patterns and service banners to identify potential honeypots.
    Returns: {probability: int, reasons: list}
    """
    reasons = []
    score = 0
    
    # 1. Port Density Heuristic
    if len(open_ports) > 30:
        score += 40
        reasons.append(f"High Port Density detected ({len(open_ports)} ports). Typical of honeypots like Cowrie or HoneyD.")
    elif len(open_ports) > 15:
        score += 15
        reasons.append("Moderate Port Density detected.")

    # 2. Service Banner Uniformity
    banners = [p['service'].lower() for p in open_ports if p.get('service')]
    if len(banners) > 3:
        unique_banners = set(banners)
        # If very few unique banners for many ports
        ratio = len(unique_banners) / len(banners)
        if ratio < 0.3:
            score += 30
            reasons.append("High Banner Uniformity detected. Services appear to use identical or emulated response signatures.")

    # 3. Known Honeypot Banners
    honeypot_keywords = ['cowrie', 'kippo', 'honeypot', 'dionaea', 'glastopf']
    for b in banners:
        if any(key in b for key in honeypot_keywords):
            score += 50
            reasons.append(f"Explicit Honeypot Signature found in service banner: {b}")
            break

    # 4. OS / Service Logical Discrepancy
    # (Simplified for now - can be expanded)
    os_info = nm_host_info.get('osmatch', [])
    os_guess = os_info[0]['name'].lower() if os_info else "unknown"
    
    if "windows" in os_guess and any("linux" in b for b in banners):
        score += 20
        reasons.append("OS Personality Discrepancy: Windows fingerprint but Linux service banners detected.")

    return {
        "probability": min(100, score),
        "reasons": reasons
    }

def extract_hostname(url):
    try:
        # Normalizing URL to handle missing schemes
        if not url.startswith('http://') and not url.startswith('https://'):
            url_to_parse = 'http://' + url
        else:
            url_to_parse = url
        parsed = urllib.parse.urlparse(url_to_parse)
        return parsed.hostname
    except Exception:
        return None

def scan_target(url, log_callback=None):
    if log_callback: log_callback("🔍 Starting target scan...")
    hostname = extract_hostname(url)
    if not hostname:
        return {"status": "error", "message": "Invalid URL format provided."}
    
    try:
        if log_callback: log_callback(f"🌐 Resolving hostname: {hostname}...")
        target_ip = socket.gethostbyname(hostname)
        if log_callback: log_callback(f"📍 Resolved IP: {target_ip}")
    except socket.gaierror:
        return {"status": "error", "message": "Could not resolve hostname to IP."}
        
    try:
        # Search specifically in Windows installation folders if it's missing from the PATH
        nmap_paths = (
            'nmap', 
            r'C:\Program Files (x86)\Nmap\nmap.exe', 
            r'C:\Program Files\Nmap\nmap.exe'
        )
        if log_callback: log_callback("⚡ Initializing Nmap engine...")
        nm = nmap.PortScanner(nmap_search_path=nmap_paths)
        # STRICT RULE: NO aggressive scanning, only defensive: -F (fast) -sV (service version)
        if log_callback: log_callback("🛡️ Performing fast service scan (-F -sV)...")
        nm.scan(hosts=target_ip, arguments='-F -sV')
    except nmap.PortScannerError as e:
        if "nmap program was not found" in str(e).lower():
            return {"status": "error", "message": "Nmap executable is not installed on the system. Please install Nmap (https://nmap.org/download) and add it to the system PATH."}
        return {"status": "error", "message": f"Nmap execution failed: {str(e)}"}
    except Exception as e:
        return {"status": "error", "message": f"Unexpected scan error: {str(e)}"}
        
    if target_ip not in nm.all_hosts():
        return {"status": "error", "message": "Target host seems to be down or blocking ping requests."}
        
    open_ports = []
    host_info = nm[target_ip]
    for proto in host_info.all_protocols():
        ports = host_info[proto].keys()
        for port in ports:
            state = host_info[proto][port]['state']
            if state == 'open':
                service = host_info[proto][port].get('name', 'unknown')
                version = host_info[proto][port].get('version', '')
                if log_callback: log_callback(f"✅ Found open port: {port} ({service})")
                open_ports.append({
                    "port": port,
                    "service": f"{service} {version}".strip(),
                    "protocol": proto
                })
                
    if log_callback: log_callback(f"📊 Identified {len(open_ports)} open ports.")
    
    # Analyze Deception Risk
    if log_callback: log_callback("🕵️ AI Deception Filter: Analyzing for Honeypot signatures...")
    deception_results = analyze_deception_risk(open_ports, nm[target_ip], target_ip)
    if deception_results['probability'] > 40:
        if log_callback: log_callback(f"🚩 WARNING: High Deception Risk detected ({deception_results['probability']}%). Host might be a Trap.")

    # Enrich with vulnerability data
    if log_callback: log_callback("🧠 Cross-referencing findings with vulnerability intelligence...")
    for port in open_ports:
        vulns = lookup_vulnerabilities(port['service'].split()[0], port['service'])
        port['vulnerabilities'] = vulns
        if vulns:
            if log_callback: log_callback(f"🚩 Intelligence found for {port['service']} on port {port['port']}.")

    return {
        "status": "success", 
        "open_ports": open_ports,
        "deception_risk": deception_results
    }

def analyze_headers(url, log_callback=None):
    if log_callback: log_callback("🕵️ Analyzing HTTP security headers...")
    # Ensure URL is properly formatted for HTTP requests
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url
        
    issues = []
    headers_found = {}
    is_https = url.startswith('https')
    
    try:
        if log_callback: log_callback(f"📡 Requesting {url}...")
        response = requests.get(url, timeout=10, verify=True)
        headers = response.headers
        
        # Analyze critical security headers
        security_headers = {
            'Content-Security-Policy': 'Missing Content-Security-Policy header',
            'X-Frame-Options': 'Missing X-Frame-Options header (Clickjacking risk)',
            'X-XSS-Protection': 'Missing X-XSS-Protection header',
            'Strict-Transport-Security': 'Missing HSTS header (SSL/TLS force)',
            'Referrer-Policy': 'Missing Referrer-Policy header'
        }

        for header, risk in security_headers.items():
            if header not in headers:
                if log_callback: log_callback(f"⚠️ Warning: {header} is missing.")
                issues.append(risk)
            else:
                if log_callback: log_callback(f"✔️ Found: {header}")
                headers_found[header] = headers[header]
            
        if 'Server' in headers:
            if log_callback: log_callback(f"🚩 Info: Server header exposed: {headers['Server']}")
            issues.append(f"Server header exposed: {headers['Server']}")
            headers_found['Server'] = headers['Server']
            
        if is_https:
            if log_callback: log_callback("🔒 SSL/TLS is active.")
            issues.append("SSL/TLS is active (HTTPS Verified)")
            
        return {
            "status": "success", 
            "issues": issues, 
            "headers": headers_found
        }
    except requests.exceptions.SSLError:
        return {"status": "error", "message": "SSL Certificate verification failed."}
    except requests.exceptions.RequestException as e:
        return {"status": "error", "message": f"HTTP Request failed: {str(e)}"}

def find_subdomains(url, log_callback=None):
    if log_callback: log_callback("🌐 Starting subdomain reconnaissance...")
    hostname = extract_hostname(url)
    if not hostname: return []
    
    # Extract base domain if possible (very simple logic for hackathon)
    parts = hostname.split('.')
    if len(parts) > 2:
        base_domain = '.'.join(parts[-2:])
    else:
        base_domain = hostname

    common_subs = ['www', 'mail', 'dev', 'api', 'blog', 'test', 'stage', 'admin', 'vpn', 'shop']
    found = []
    
    for sub in common_subs:
        target = f"{sub}.{base_domain}"
        if log_callback: log_callback(f"🔎 Probing: {target}...")
        try:
            ip = socket.gethostbyname(target)
            if log_callback: log_callback(f"✨ Found subdomain: {target} ({ip})")
            found.append({"subdomain": target, "ip": ip})
        except socket.gaierror:
            continue
            
    if log_callback: log_callback(f"✅ Recon complete. Found {len(found)} subdomains.")
    return found

def compile_scan_summary(scan_data, header_data, subdomain_data=None):
    summary_parts = []
    
    # Transform Open Ports
    if scan_data.get('status') == 'success':
        summary_parts.append("Open Ports:")
        ports = scan_data.get('open_ports', [])
        if ports:
            for p in ports:
                # Defensive check for empty vulnerability lists
                vuln_risk = p['vulnerabilities'][0]['risk'] if p.get('vulnerabilities') and len(p['vulnerabilities']) > 0 else None
                vuln_info = f" [RISK: {vuln_risk}]" if vuln_risk else ""
                summary_parts.append(f"- {p['port']}/{p['protocol']} ({p['service']}){vuln_info}")
        else:
            summary_parts.append("- No open ports found in fast scan.")
    else:
        summary_parts.append(f"Port Scan Error: {scan_data.get('message')}")
        
    # Transform Subdomains
    if subdomain_data:
        summary_parts.append("\nIdentified Subdomains:")
        for s in subdomain_data:
            summary_parts.append(f"- {s['subdomain']} ({s['ip']})")

    # Transform Issues
    summary_parts.append("\nIssues:")
    if header_data.get('status') == 'success':
        issues = header_data.get('issues', [])
        if issues:
            for issue in issues:
                summary_parts.append(f"- {issue}")
        else:
            summary_parts.append("- No critical missing security headers detected.")
    else:
        summary_parts.append(f"- Header Analysis Error: {header_data.get('message')}")

    # Transform Deception Risk
    deception_risk = scan_data.get('deception_risk')
    if deception_risk:
        summary_parts.append(f"\nAI Deception Filter: {deception_risk['probability']}% Probability")
        if deception_risk['reasons']:
            for reason in deception_risk['reasons']:
                summary_parts.append(f"- {reason}")

    return "\n".join(summary_parts)


