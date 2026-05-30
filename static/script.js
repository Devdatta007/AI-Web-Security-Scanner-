document.addEventListener('DOMContentLoaded', () => {
    // DOM Selectors
    const scanForm = document.getElementById('scanForm');
    const scanBtn = document.getElementById('scanBtn');
    const loading = document.getElementById('loading');
    const errContainer = document.getElementById('error-container');
    const errText = document.getElementById('error-text');
    const resultsContainer = document.getElementById('results-container');
    const portsList = document.getElementById('ports-list');
    const issuesList = document.getElementById('issues-list');
    const aiReportContent = document.getElementById('ai-report-content');
    const aiThoughtContent = document.getElementById('ai-thought-content');
    const aiThoughtContainer = document.getElementById('ai-thought-container');
    const downloadBtn = document.getElementById('downloadBtn');
    const printBtn = document.getElementById('printBtn');
    const statusIndicator = document.getElementById('status-indicator');
    
    // Sidebar Toggle Selectors
    const sidebar = document.getElementById('sidebar');
    const sidebarOverlay = document.getElementById('sidebar-overlay');
    const sidebarToggle = document.getElementById('sidebar-toggle');

    const consoleContainer = document.getElementById('console-container');
    const consoleOutput = document.getElementById('console-output');

    // Sidebar Logic
    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', () => {
            sidebar.classList.toggle('-translate-x-full');
            sidebarOverlay.classList.toggle('hidden');
        });
    }

    if (sidebarOverlay) {
        sidebarOverlay.addEventListener('click', () => {
            sidebar.classList.add('-translate-x-full');
            sidebarOverlay.classList.add('hidden');
        });
    }

    if (printBtn) {
        printBtn.addEventListener('click', () => window.print());
    }

    // Form Submission
    if (scanForm) {
        scanForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const urlInput = document.getElementById('url').value.trim();
            const authorized = document.getElementById('authorized').checked;

            if (!urlInput || !authorized) return;

            // Reset UI Context
            if (errContainer) errContainer.classList.add('hidden');
            if (resultsContainer) resultsContainer.classList.add('hidden');
            if (consoleContainer) consoleContainer.classList.add('hidden');
            if (aiThoughtContainer) aiThoughtContainer.classList.add('hidden');
            if (consoleOutput) consoleOutput.innerHTML = '';
            if (portsList) portsList.innerHTML = '';
            if (issuesList) issuesList.innerHTML = '';
            if (aiReportContent) aiReportContent.innerHTML = '';
            if (downloadBtn) downloadBtn.classList.add('hidden');
            
            // Disable UI
            scanBtn.disabled = true;
            scanBtn.querySelector('span').textContent = 'Initializing Analysis...';
            if (statusIndicator) statusIndicator.classList.remove('hidden');

            try {
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: urlInput, authorized: authorized })
                });

                const data = await response.json();
                
                if (data.status === 'error') {
                    showError(data.message);
                    resetScanButton();
                    return;
                } 
                
                if (data.status === 'started') {
                    const scanId = data.scan_id;
                    startConsoleStream(scanId);
                }
            } catch (error) {
                showError("L1 Protocol Error: Infrastructure unreachable.");
                console.error(error);
                resetScanButton();
            }
        });
    }

    // Populate Activity Feed
    const activityFeed = document.getElementById('activity-feed');
    if (activityFeed) {
        const events = [
            { icon: 'shield', text: 'System firewall baseline synchronized', time: '2m' },
            { icon: 'eye', text: 'New asset discovery protocol initialized', time: '14m' },
            { icon: 'crosshair', text: 'Target vector #842 cleared for audit', time: '1h' },
            { icon: 'zap', text: 'AI reasoning engine version 3.4.1 deployed', time: '3h' },
            { icon: 'cpu', text: 'Neural weights optimized for CVE-2025 detection', time: '5h' }
        ];

        events.forEach(ev => {
            const div = document.createElement('div');
            div.className = 'flex gap-4 items-start group reveal';
            div.innerHTML = `
                <div class="p-2 border border-border bg-zinc-950/50 group-hover:border-white transition-colors">
                    <i data-lucide="${ev.icon}" class="w-3 h-3 text-zinc-500 group-hover:text-white transition-colors"></i>
                </div>
                <div class="flex-1 space-y-1">
                    <p class="text-[10px] text-zinc-400 group-hover:text-white leading-tight transition-colors line-clamp-2">${ev.text}</p>
                    <span class="text-[8px] font-bold text-zinc-700 uppercase tracking-widest">${ev.time} AGO</span>
                </div>
            `;
            activityFeed.appendChild(div);
        });
        if (typeof lucide !== 'undefined') lucide.createIcons();
    }

    function resetScanButton() {
        if (!scanBtn) return;
        scanBtn.disabled = false;
        scanBtn.querySelector('span').textContent = 'Initialize Recon Session';
        if (statusIndicator) statusIndicator.classList.add('hidden');
    }

    function startConsoleStream(scan_id) {
        consoleContainer.classList.remove('hidden');
        const eventSource = new EventSource(`/stream/${scan_id}`);

        eventSource.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                
                if (data.message === 'EOF') {
                    eventSource.close();
                    fetchFinalResults(scan_id);
                    return;
                }

                const line = document.createElement('div');
                line.className = 'flex items-start gap-3 mb-1.5 opacity-80 reveal';
                
                const prompt = document.createElement('span');
                prompt.textContent = '→';
                prompt.className = 'text-white font-bold shrink-0';
                line.appendChild(prompt);

                const msgSpan = document.createElement('span');
                msgSpan.textContent = data.message;
                msgSpan.className = 'break-all';
                
                // Content detection for minimal color highlights
                if (data.message.includes('🤖') || data.message.includes('🧠') || data.message.includes('Intelligence')) {
                    msgSpan.className += ' text-white font-bold';
                } else if (data.message.includes('Error') || data.message.includes('❌') || data.message.includes('expired')) {
                    msgSpan.className += ' text-zinc-500 line-through';
                }
                
                line.appendChild(msgSpan);
                consoleOutput.appendChild(line);
                consoleOutput.scrollTop = consoleOutput.scrollHeight;
            } catch (e) {
                console.error("Stream parse error:", e);
            }
        };

        eventSource.onerror = (err) => {
            eventSource.close();
            // Silent recovery attempt if we are still scanning
            if (scanBtn.disabled && scanBtn.querySelector('span').textContent !== 'Finalizing...') {
                const recoveryMsg = document.createElement('div');
                recoveryMsg.textContent = "📡 Re-establishing secure intelligence uplink...";
                recoveryMsg.className = "text-zinc-500 font-mono text-[9px] mt-1 opacity-50";
                consoleOutput.appendChild(recoveryMsg);
                consoleOutput.scrollTop = consoleOutput.scrollHeight;
                
                // Trigger the smart polling recovery with much longer patience
                fetchFinalResults(scan_id); 
            }
        };
    }

    async function fetchFinalResults(scanId, retries = 0) {
        // "running" = scan is actively in progress (poll indefinitely every 3s)
        // "pending" = scan_id not found at all (time out after ~30s)
        const MAX_NOT_FOUND_RETRIES = 10;
        if (loading) loading.classList.remove('hidden');
        if (scanBtn && scanBtn.querySelector('span')) {
            scanBtn.querySelector('span').textContent = 'Synchronizing...';
        }
        
        try {
            const response = await fetch(`/results/${scanId}`);
            if (!response.ok) throw new Error(`Network Error: ${response.status}`);
            
            const data = await response.json();
            
            if (data.status === 'success') {
                if (downloadBtn) {
                    downloadBtn.href = `/download/${scanId}`;
                    downloadBtn.classList.remove('hidden');
                }
                const standaloneLink = document.getElementById('standaloneLink');
                if (standaloneLink) {
                    standaloneLink.href = `/report/${scanId}`;
                    standaloneLink.classList.remove('hidden');
                }
                renderResults(data, scanId);
                resetScanButton();
                if (loading) loading.classList.add('hidden');
            } else if (data.status === 'running' || data.status === 'started') {
                // Scan is actively running — keep polling with no retry limit
                setTimeout(() => fetchFinalResults(scanId, 0), 3000);
            } else if (data.status === 'pending') {
                // Scan ID not found yet — retry a few times in case of race condition
                if (retries < MAX_NOT_FOUND_RETRIES) {
                    setTimeout(() => fetchFinalResults(scanId, retries + 1), 3000);
                } else {
                    showError("Sync Timeout: The intelligence synthesis is taking longer than expected. Please check 'Historical Reports' in a few moments.");
                    resetScanButton();
                    if (loading) loading.classList.add('hidden');
                }
            } else {
                showError(data.message || "Intelligence retrieval failed.");
                resetScanButton();
                if (loading) loading.classList.add('hidden');
            }
        } catch (error) {
            console.error("Retrieval Error:", error);
            if (retries < 3) {
                 setTimeout(() => fetchFinalResults(scanId, retries + 1), 2000);
            } else {
                 showError(`Operational Error: ${error.message}`);
                 resetScanButton();
                 if (loading) loading.classList.add('hidden');
            }
        }
    }

    function showError(msg) {
        if (errText) errText.textContent = msg;
        errContainer.classList.remove('hidden');
        const errLine = document.createElement('div');
        errLine.textContent = `[FAIL] ${msg}`;
        errLine.className = "text-white opacity-50 font-mono mt-2";
        if (consoleOutput) {
            consoleOutput.appendChild(errLine);
            consoleOutput.scrollTop = consoleOutput.scrollHeight;
        }
    }

    let riskChart = null;

    function renderResults(data, scanId) {
        try {
            const metaUrl = document.getElementById('meta-url');
            if (metaUrl) metaUrl.textContent = (data.target_url || '-').toUpperCase();
            
            const metaId = document.getElementById('meta-id');
            if (metaId) metaId.textContent = scanId || '-';
            
            const metaTime = document.getElementById('meta-time');
            if (metaTime) metaTime.textContent = data.timestamp || '-';
            
            // Ports Table
            if (portsList) {
                portsList.innerHTML = '';
                const ports = data.scan_data || [];
                if (!ports.length) {
                    portsList.innerHTML = '<tr><td colspan="6" class="p-6 text-center text-[10px] uppercase tracking-widest text-zinc-700 italic">No open ports detected</td></tr>';
                } else {
                    ports.forEach(portObj => {
                        const info = getPortIntelligence(portObj);
                        const riskClass = {
                            'CRITICAL': 'text-red-500 border-red-500/40 bg-red-500/5',
                            'HIGH':     'text-orange-400 border-orange-400/40 bg-orange-400/5',
                            'MEDIUM':   'text-yellow-400 border-yellow-400/40 bg-yellow-400/5',
                            'LOW':      'text-zinc-400 border-zinc-700 bg-zinc-900/30',
                            'INFO':     'text-zinc-500 border-zinc-800 bg-transparent',
                        }[info.risk] || 'text-zinc-500 border-zinc-800 bg-transparent';

                        const tr = document.createElement('tr');
                        tr.className = 'border-b border-border hover:bg-zinc-900/30 transition-colors reveal';
                        tr.innerHTML = `
                            <td class="px-4 py-4 font-mono text-xs font-bold text-white whitespace-nowrap">${portObj.port}</td>
                            <td class="px-4 py-4 text-[10px] font-bold uppercase tracking-widest text-zinc-400 whitespace-nowrap">${(portObj.protocol || 'tcp').toUpperCase()}</td>
                            <td class="px-4 py-4 text-[10px] text-zinc-300 font-mono whitespace-nowrap">${portObj.service || 'Unknown'}</td>
                            <td class="px-4 py-4 whitespace-nowrap">
                                <span class="px-2 py-1 border text-[9px] font-black uppercase tracking-widest ${riskClass}">${info.risk}</span>
                            </td>
                            <td class="px-4 py-4 text-[10px] text-zinc-400 leading-relaxed max-w-xs">${info.impact}</td>
                            <td class="px-4 py-4 text-[10px] text-zinc-300 leading-relaxed max-w-xs">${info.resolution}</td>
                        `;
                        portsList.appendChild(tr);
                    });
                }
            }

            // Headers / Issues
            if (issuesList) {
                issuesList.innerHTML = '';
                (data.issues || []).forEach(issue => {
                    const li = document.createElement('li');
                    li.className = "p-4 border border-border bg-black flex gap-4 items-start reveal transition-all hover:border-white/50";
                    
                    const isRisk = issue.toLowerCase().includes('missing') || issue.toLowerCase().includes('exposed');
                    const indicator = document.createElement('div');
                    indicator.className = `w-1.5 h-1.5 mt-1.5 ${isRisk ? 'bg-white shadow-[0_0_8px_white]' : 'bg-zinc-800'}`;
                    li.appendChild(indicator);
                    
                    const text = document.createElement('span');
                    text.textContent = issue;
                    text.className = isRisk ? 'text-white text-xs font-bold uppercase tracking-tight' : 'text-zinc-600 text-[11px] font-medium';
                    li.appendChild(text);
                    issuesList.appendChild(li);
                });
            }

            // Subdomains
            const subSection = document.getElementById('subdomains-section');
            const subList = document.getElementById('subdomains-list');
            if (subSection && subList) {
                subList.innerHTML = '';
                if (data.subdomains && data.subdomains.length) {
                    subSection.classList.remove('hidden');
                    data.subdomains.forEach(sub => {
                        const li = document.createElement('li');
                        li.className = "p-3 border border-border bg-black flex flex-col gap-1 hover:border-white transition-colors reveal";
                        li.innerHTML = `
                            <span class="text-white font-mono text-[10px] font-bold truncate">${sub.subdomain}</span>
                            <span class="text-[8px] text-zinc-700 font-bold uppercase tracking-widest">${sub.ip}</span>
                        `;
                        subList.appendChild(li);
                    });
                } else {
                    subSection.classList.add('hidden');
                }
            }

            // AI Report
            if (aiReportContent && data.ai_report) {
                let reportText = data.ai_report;
                let thinking = "";
                
                if (reportText.includes("### 💡 AI Reasoning Process")) {
                    const parts = reportText.split("---");
                    if (parts.length > 1) {
                        thinking = parts[0].replace("### 💡 AI Reasoning Process", "").trim();
                        reportText = parts.slice(1).join("---").trim();
                    }
                }

                if (thinking && aiThoughtContainer && aiThoughtContent) {
                    aiThoughtContent.textContent = thinking.replace(/^>\s*/gm, '');
                    aiThoughtContainer.classList.remove('hidden');
                }

                if (typeof marked !== 'undefined') {
                    reportText = reportText.replace(/REMEDIATION/g, 'RESOLUTION').replace(/Remediation/g, 'Resolution').replace(/remediation/g, 'resolution');
                    aiReportContent.innerHTML = marked.parse(reportText);
                } else {
                    aiReportContent.innerHTML = `<pre class="text-white text-xs whitespace-pre-wrap">${reportText}</pre>`;
                }
                
                if (typeof lucide !== 'undefined') lucide.createIcons();
            }

            // Surface Map Visualization
            if (typeof initAttackSurfaceMap === 'function') {
                initAttackSurfaceMap(data);
            }

            updateIntegrityArray(data);
            if (resultsContainer) {
                resultsContainer.classList.remove('hidden');
                resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }

        } catch (err) {
            console.error(err);
            showError("Parity Failure: Render interrupted.");
        }
    }

    function updateIntegrityArray(data) {
        const ports = data.scan_data || [];
        const issues = data.issues || [];
        
        let scores = {
            net: Math.max(0, 100 - ports.length * 20),
            head: Math.max(0, 100 - issues.filter(i => i.toLowerCase().includes('missing')).length * 25),
            ssl: issues.some(i => i.toLowerCase().includes('https') || i.toLowerCase().includes('ssl')) ? 100 : 30,
            priv: issues.some(i => i.toLowerCase().includes('exposed')) ? 40 : 100
        };

        const avg = (scores.net + scores.head + scores.ssl + scores.priv) / 4;
        const badge = document.getElementById('meta-score-badge');
        const hBar = document.getElementById('health-bar');
        
        if (badge) {
            badge.textContent = `${Math.round(avg)}%`;
            badge.className = `text-9xl font-black tracking-tighter transition-colors ${avg < 50 ? 'text-red-500' : 'text-white'}`;
        }
        if (hBar) {
            hBar.style.width = `${Math.round(avg)}%`;
            hBar.className = `h-full transition-all duration-1000 ${avg < 50 ? 'bg-red-500' : 'bg-white'}`;
        }

        // Update linear gauges
        const categories = {
            'net': scores.net,
            'head': scores.head,
            'ssl': scores.ssl,
            'priv': scores.priv
        };

        Object.keys(categories).forEach(cat => {
            const gauge = document.getElementById(`gauge-${cat}`);
            const label = document.getElementById(`label-${cat}`);
            const score = categories[cat];
            
            if (gauge) {
                gauge.style.width = `${score}%`;
                gauge.className = `h-full transition-all duration-1000 ${score < 50 ? 'bg-red-500' : 'bg-white'}`;
            }
            if (label) {
                label.textContent = `${Math.round(score)}%`;
                label.className = `text-[9px] font-mono min-w-[30px] text-right transition-colors ${score < 50 ? 'text-red-500' : 'text-white'}`;
            }
        });

        // 3. Update Deception Risk
        const deception = data.deception_risk;
        if (deception) {
            const dGauge = document.getElementById('gauge-deception');
            const dLabel = document.getElementById('label-deception');
            const dText = document.getElementById('deception-text');
            const dWarning = document.getElementById('deception-warning');
            
            const prob = deception.probability;
            if (dGauge) dGauge.style.width = `${prob}%`;
            if (dLabel) dLabel.textContent = `${prob}%`;
            
            if (prob > 70) {
                if (dGauge) dGauge.className = "bg-red-500 h-full transition-all duration-1000";
                if (dLabel) dLabel.className = "text-[9px] font-mono text-red-500 min-w-[30px] text-right";
                if (dText) {
                    dText.textContent = "High Probability Trap";
                    dText.className = "text-[7px] text-red-500 uppercase italic font-bold";
                }
                if (dWarning) dWarning.classList.remove('hidden');
            } else if (prob > 30) {
                if (dText) dText.textContent = "Suspicious Environment";
            } else {
                if (dText) dText.textContent = "Low Deception Risk";
            }
        }
    }

    function initAttackSurfaceMap(data) {
        const container = document.getElementById('attack-surface-map');
        const loader = document.getElementById('graph-loader');
        if (!container) return;

        // Clear previous graph
        container.innerHTML = '';
        if (loader) loader.classList.remove('opacity-0');

        const nodes = [];
        const links = [];

        // 1. Central Target Node
        const targetNode = { id: 'target', name: data.target_url, val: 20, color: '#FFFFFF', type: 'root' };
        nodes.push(targetNode);

        // Hub configuration
        const hubMap = {
            'ports': { id: 'hub_ports', name: 'Services', val: 12, color: '#22D3EE', type: 'hub' },
            'issues': { id: 'hub_issues', name: 'Risk Vectors', val: 12, color: '#EF4444', type: 'hub' },
            'subs': { id: 'hub_subs', name: 'Sub-Assets', val: 12, color: '#52525B', type: 'hub' }
        };

        // Populate Ports
        if (data.scan_data && data.scan_data.length > 0) {
            nodes.push(hubMap.ports);
            links.push({ source: 'target', target: 'hub_ports' });
            data.scan_data.forEach((p, idx) => {
                const id = `port_${idx}`;
                nodes.push({ id, name: `Port ${p.port}: ${p.service}`, val: 6, color: '#22D3EE' });
                links.push({ source: 'hub_ports', target: id });
            });
        }

        // Populate Issues
        if (data.issues && data.issues.length > 0) {
            nodes.push(hubMap.issues);
            links.push({ source: 'target', target: 'hub_issues' });
            data.issues.forEach((issue, idx) => {
                const id = `issue_${idx}`;
                const color = (issue.includes('Critical') || issue.includes('High')) ? '#EF4444' : '#F59E0B';
                nodes.push({ id, name: issue, val: 8, color });
                links.push({ source: 'hub_issues', target: id });
            });
        }

        // Populate Subdomains
        if (data.subdomains && data.subdomains.length > 0) {
            nodes.push(hubMap.subs);
            links.push({ source: 'target', target: 'hub_subs' });
            data.subdomains.forEach((sub, idx) => {
                const id = `sub_${idx}`;
                nodes.push({ id, name: sub.subdomain, val: 6, color: '#52525B' });
                links.push({ source: 'hub_subs', target: id });
            });
        }

        // Initialize 3D Graph
        const Graph = ForceGraph3D()(container)
            .width(container.offsetWidth)
            .height(container.offsetHeight)
            .graphData({ nodes, links })
            .backgroundColor('#000000')
            .nodeLabel('name')
            .nodeColor(node => node.color)
            .nodeVal(node => node.val)
            .linkWidth(1)
            .linkColor(() => 'rgba(255,255,255,0.05)')
            .linkDirectionalParticles(2)
            .linkDirectionalParticleWidth(1.5)
            .linkDirectionalParticleSpeed(0.005);

        // Auto-center on load
        Graph.onEngineStop(() => Graph.zoomToFit(400));

        // Handle window resize
        window.addEventListener('resize', () => {
            if (container && container.offsetWidth) {
                Graph.width(container.offsetWidth).height(container.offsetHeight);
            }
        });

        // Update Loader UI
        setTimeout(() => {
            if (loader) {
                loader.classList.add('opacity-0');
                setTimeout(() => loader.classList.add('hidden'), 500);
            }
        }, 1500);
    }

    // Expose to window for result.html
    window.renderResults = renderResults;
    window.updateRiskChart = updateRiskChart;
    window.fetchFinalResults = fetchFinalResults;

    // ─── Port Intelligence Database ───────────────────────────────────────────
    function getPortIntelligence(portObj) {
        const port = parseInt(portObj.port);
        const service = (portObj.service || '').toLowerCase();

        // Check vulnerability data from backend first
        const vulns = portObj.vulnerabilities || [];
        const topVuln = vulns.find(v => v.risk && v.risk !== 'any') || vulns[0];

        const db = {
            21:  { risk: 'HIGH',     impact: 'FTP transmits credentials and data in plaintext. Susceptible to credential sniffing, brute-force, and anonymous login abuse.',                                    resolution: 'Disable FTP. Migrate to SFTP (port 22) or FTPS. Enforce strong authentication and restrict anonymous access.' },
            22:  { risk: 'MEDIUM',   impact: 'SSH exposed to the internet is a common brute-force target. Weak keys or outdated versions (e.g. OpenSSH 7.2) allow user enumeration.',                         resolution: 'Disable password auth — use SSH key pairs only. Restrict access via firewall to trusted IPs. Keep OpenSSH updated.' },
            23:  { risk: 'CRITICAL', impact: 'Telnet sends all data including passwords in cleartext. Trivially intercepted on any network segment.',                                                           resolution: 'Disable Telnet immediately. Replace with SSH. Block port 23 at the firewall.' },
            25:  { risk: 'HIGH',     impact: 'Open SMTP relay can be exploited for spam campaigns and phishing. Exposes internal mail infrastructure.',                                                         resolution: 'Restrict SMTP relay to authenticated users only. Enable SPF, DKIM, DMARC. Use TLS for all mail transport.' },
            53:  { risk: 'MEDIUM',   impact: 'Open DNS resolver can be abused for DNS amplification DDoS attacks and zone transfer leaks.',                                                                    resolution: 'Restrict recursive queries to internal IPs only. Disable zone transfers to unauthorized hosts. Use DNSSEC.' },
            80:  { risk: 'LOW',      impact: 'Unencrypted HTTP exposes all traffic to interception (MITM). Sensitive data submitted over HTTP is readable in transit.',                                        resolution: 'Redirect all HTTP traffic to HTTPS (301). Enforce HSTS. Disable HTTP entirely if possible.' },
            110: { risk: 'HIGH',     impact: 'POP3 without TLS transmits email credentials and content in plaintext.',                                                                                         resolution: 'Disable plain POP3. Use POP3S (port 995) with TLS enforced. Prefer IMAP over TLS (993).' },
            135: { risk: 'HIGH',     impact: 'Windows RPC endpoint mapper. Commonly exploited for remote code execution (e.g. MS03-026). Should never be internet-facing.',                                   resolution: 'Block port 135 at the perimeter firewall. Apply all Windows security patches. Disable unnecessary RPC services.' },
            139: { risk: 'HIGH',     impact: 'NetBIOS session service. Exposes Windows file sharing and is associated with EternalBlue (MS17-010) and other SMB exploits.',                                   resolution: 'Block ports 139 and 445 at the firewall. Disable NetBIOS over TCP/IP. Apply MS17-010 patch immediately.' },
            143: { risk: 'MEDIUM',   impact: 'IMAP without TLS exposes email credentials and message content in transit.',                                                                                     resolution: 'Disable plain IMAP. Enforce IMAPS (port 993). Require TLS for all mail client connections.' },
            443: { risk: 'INFO',     impact: 'HTTPS is expected and required. Risk depends on TLS version, cipher suites, and certificate validity.',                                                          resolution: 'Ensure TLS 1.2+ only. Disable SSLv3, TLS 1.0/1.1. Use strong cipher suites. Renew certificates before expiry.' },
            445: { risk: 'CRITICAL', impact: 'SMB directly exposed to the internet. Primary attack vector for EternalBlue (CVE-2017-0144), WannaCry, and NotPetya ransomware.',                               resolution: 'Block port 445 at the perimeter firewall immediately. Apply MS17-010 patch. Disable SMBv1. Use VPN for internal file sharing.' },
            1433: { risk: 'CRITICAL', impact: 'MSSQL database port exposed publicly. Allows direct brute-force of database credentials and potential data exfiltration.',                                     resolution: 'Block port 1433 from public internet. Restrict to application server IPs only. Use strong SA passwords. Enable SQL Server auditing.' },
            1521: { risk: 'CRITICAL', impact: 'Oracle DB listener exposed. Allows direct connection attempts, SID enumeration, and credential brute-force.',                                                   resolution: 'Block port 1521 from public internet. Restrict listener to internal IPs. Enforce strong authentication and audit all connections.' },
            3306: { risk: 'HIGH',    impact: 'MySQL exposed publicly allows direct brute-force of database credentials, potential data dump, and SQL injection escalation.',                                   resolution: 'Bind MySQL to 127.0.0.1 only. Block port 3306 at the firewall. Use SSH tunneling for remote DB access. Enforce strong passwords.' },
            3389: { risk: 'CRITICAL', impact: 'RDP exposed to the internet is a top ransomware entry point. Vulnerable to BlueKeep (CVE-2019-0708), brute-force, and credential stuffing.',                  resolution: 'Block RDP from public internet. Use VPN + RDP or RD Gateway. Enable NLA. Apply all Windows patches. Use MFA.' },
            5432: { risk: 'HIGH',    impact: 'PostgreSQL exposed publicly allows direct credential attacks and potential data exfiltration.',                                                                   resolution: 'Bind PostgreSQL to localhost. Block port 5432 at the firewall. Use SSL connections. Restrict pg_hba.conf to trusted IPs.' },
            5900: { risk: 'HIGH',    impact: 'VNC exposed without encryption allows screen capture and full remote control. Often has weak or no authentication.',                                             resolution: 'Block VNC from public internet. Tunnel VNC over SSH. Enforce strong VNC passwords. Use a VPN for remote access.' },
            6379: { risk: 'CRITICAL', impact: 'Redis with no authentication exposed publicly. Allows full data read/write, config manipulation, and potential RCE via cron/SSH key injection.',               resolution: 'Bind Redis to 127.0.0.1. Set a strong requirepass. Block port 6379 at the firewall. Never expose Redis to the internet.' },
            8080: { risk: 'MEDIUM',  impact: 'Alternate HTTP port often used for dev servers, proxies, or admin panels. May expose unprotected management interfaces.',                                        resolution: 'Restrict access to trusted IPs. Ensure TLS is configured. Remove or password-protect any admin interfaces.' },
            8443: { risk: 'LOW',     impact: 'Alternate HTTPS port. Risk profile similar to 443 — depends on TLS configuration and what service is running.',                                                 resolution: 'Ensure TLS 1.2+. Validate certificate. Restrict access if this is an admin or management interface.' },
            27017: { risk: 'CRITICAL', impact: 'MongoDB with no authentication exposed publicly. Allows full database read/write/delete without credentials.',                                                 resolution: 'Enable MongoDB authentication immediately. Bind to localhost. Block port 27017 at the firewall. Enable TLS for connections.' },
        };

        if (db[port]) {
            // Override risk level if backend vulnerability data has a higher severity
            let risk = db[port].risk;
            if (topVuln && topVuln.risk) {
                const order = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
                if (order.indexOf(topVuln.risk.toUpperCase()) > order.indexOf(risk)) {
                    risk = topVuln.risk.toUpperCase();
                }
            }
            return { risk, impact: db[port].impact, resolution: db[port].resolution };
        }

        // Generic fallback based on service name
        if (service.includes('http'))  return { risk: 'LOW',    impact: 'HTTP service detected. Traffic may be unencrypted.',                                    resolution: 'Enforce HTTPS. Review what is exposed on this port.' };
        if (service.includes('ssh'))   return { risk: 'MEDIUM', impact: 'SSH service detected. Ensure only key-based auth is enabled.',                          resolution: 'Disable password auth. Restrict to trusted IPs. Keep SSH updated.' };
        if (service.includes('ftp'))   return { risk: 'HIGH',   impact: 'FTP transmits data in plaintext.',                                                      resolution: 'Replace with SFTP or FTPS.' };
        if (service.includes('smtp'))  return { risk: 'MEDIUM', impact: 'Mail service exposed. Verify relay restrictions.',                                      resolution: 'Restrict relay. Enable TLS. Configure SPF/DKIM/DMARC.' };
        if (service.includes('mysql') || service.includes('postgres') || service.includes('mongo') || service.includes('db'))
            return { risk: 'HIGH', impact: 'Database service exposed publicly. Risk of credential brute-force and data exfiltration.', resolution: 'Restrict to internal IPs only. Never expose databases to the public internet.' };

        return {
            risk: 'MEDIUM',
            impact: topVuln ? topVuln.info || 'Service exposed on non-standard port.' : 'Unknown service exposed. Attack surface is increased.',
            resolution: 'Identify the service running on this port. If not required externally, block it at the firewall.'
        };
    }
});
