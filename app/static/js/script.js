console.log("script.js loaded");
document.addEventListener("DOMContentLoaded", function () {
    const mainContent = document.getElementById("main-content");

    const routes = {
        "dashboard-btn": null,  // Full reload for dashboard
        "attack-surface-btn": "/attack_surface",
        "findings-btn": "/findings",
        "assets-btn": "/assets",
        "reports-btn": "/reports",
        "new-scan-btn": "/new_scan",
        "chatbot-btn": "/chatbot_component",
        "website_scanner-btn": "/website_scanner",  // ✅ Added
        "port-scanner-btn": "/port-scanner",  // ✅ Added port scanner
        "domain-finder-btn": "/domain-finder",  // ✅ Added domain finder
        "subdomain-finder-btn": "/subdomain-finder",  // ✅ Added subdomain finder
        "sqli-exploiter-btn": "/sqli-exploiter",  // ✅ Added sqli exploiter
        "whois-lookup-btn": "/whois-lookup",  // ✅ Added whois lookup
        "dns-lookup-btn": "/dns-lookup"  // ✅ Added dns lookup
    };

    Object.entries(routes).forEach(([btnId, route]) => {
        const btn = document.getElementById(btnId);
        if (btn) {
            btn.addEventListener("click", () => {
                if (route === null) {
                    window.location.href = "/";
                    return;
                }

                fetch(route)
                    .then((res) => res.text())
                    .then((html) => {
                        mainContent.innerHTML = html;
                        history.pushState({ route }, '', route); // Update the URL

                        // Dynamically load attack_surface.js if loading the Attack Surface page
                        if (route === "/attack_surface") {
                            const existingScript = document.querySelector('script[src="/static/js/attack_surface.js"]');
                            if (existingScript) existingScript.remove();
                            const script = document.createElement('script');
                            script.src = '/static/js/attack_surface.js';
                            script.defer = true;
                            document.body.appendChild(script);
                        }

                        // ✅ Load zap scanner for both /new_scan and /website_scanner
                        if (route === "/new_scan" || route === "/website_scanner") {
                            const zapScriptSrc = "/static/js/zap_scanner.js";

                            // Remove existing zap script
                            const existingZAP = Array.from(document.scripts).find(s => s.src.includes(zapScriptSrc));
                            if (existingZAP) existingZAP.remove();

                            const zapScript = document.createElement("script");
                            zapScript.src = zapScriptSrc;
                            zapScript.type = "module";
                            zapScript.defer = true;
                            document.body.appendChild(zapScript);

                            // Only /new_scan has new_scan.js
                            if (route === "/new_scan") {
                                const scanScriptId = "new-scan-script";
                                const oldScript = document.getElementById(scanScriptId);
                                if (oldScript) oldScript.remove();

                                const script = document.createElement("script");
                                script.id = scanScriptId;
                                script.src = "/static/js/new_scan.js";
                                script.defer = true;
                                document.body.appendChild(script);
                            }
                        }

                        // ✅ Load port scanner for /port-scanner
                        if (route === "/port-scanner") {
                            const portScannerScriptSrc = "/static/js/port_scanner.js";
                            
                            // Remove existing port scanner script
                            const existingPortScanner = Array.from(document.scripts).find(s => s.src.includes(portScannerScriptSrc));
                            if (existingPortScanner) existingPortScanner.remove();

                            const portScannerScript = document.createElement("script");
                            portScannerScript.src = portScannerScriptSrc;
                            portScannerScript.type = "module";
                            portScannerScript.defer = true;
                            document.body.appendChild(portScannerScript);
                        }

                        // ✅ Load domain finder for /domain-finder
                        if (route === "/domain-finder") {
                            const domainFinderScriptSrc = "/static/js/domain_finder.js";
                            
                            // Remove existing domain finder script
                            const existingDomainFinder = Array.from(document.scripts).find(s => s.src.includes(domainFinderScriptSrc));
                            if (existingDomainFinder) existingDomainFinder.remove();

                            const domainFinderScript = document.createElement("script");
                            domainFinderScript.src = domainFinderScriptSrc;
                            domainFinderScript.type = "module";
                            domainFinderScript.defer = true;
                            document.body.appendChild(domainFinderScript);
                        }

                        // ✅ Load subdomain finder for /subdomain-finder
                        if (route === "/subdomain-finder") {
                            const subdomainFinderScriptSrc = "/static/js/subdomain_finder.js";
                            
                            // Remove existing subdomain finder script
                            const existingSubdomainFinder = Array.from(document.scripts).find(s => s.src.includes(subdomainFinderScriptSrc));
                            if (existingSubdomainFinder) existingSubdomainFinder.remove();

                            const subdomainFinderScript = document.createElement("script");
                            subdomainFinderScript.src = subdomainFinderScriptSrc;
                            subdomainFinderScript.type = "module";
                            subdomainFinderScript.defer = true;
                            document.body.appendChild(subdomainFinderScript);
                        }

                        // 🤖 Handle chatbot logic
                        if (route === "/chatbot_component") {
                            const form = document.getElementById("chat-form");
                            const input = document.getElementById("chat-input");
                            const log = document.getElementById("chat-log");

                            form.addEventListener("submit", async (e) => {
                                e.preventDefault();
                                const msg = input.value.trim();
                                if (!msg) return;

                                log.innerHTML += `<p><strong>👨 You:</strong> ${msg}</p>`;
                                input.value = "";

                                const spinnerId = `spinner-${Date.now()}`;
                                log.innerHTML += `<p id="${spinnerId}"><em>🤖 Thinking... <span class="spinner">⏳</span></em></p>`;
                                log.scrollTop = log.scrollHeight;

                                try {
                                    const response = await fetch("/api/chat", {
                                        method: "POST",
                                        headers: { "Content-Type": "application/json" },
                                        body: JSON.stringify({ message: msg }),
                                    });

                                    const data = await response.json();
                                    const rawReply = data?.reply || "❌ No reply from server.";

                                    document.getElementById(spinnerId)?.remove();

                                    const escapedReply = rawReply.replace(/</g, "&lt;").replace(/>/g, "&gt;");
                                    const pre = document.createElement("pre");
                                    pre.classList.add("bot-reply");
                                    log.appendChild(pre);

                                    let i = 0;
                                    function typeChar() {
                                        if (i < escapedReply.length) {
                                            pre.innerHTML += escapedReply[i] === "\n" ? "<br>" : escapedReply[i];
                                            i++;
                                            setTimeout(typeChar, 5);
                                            log.scrollTop = log.scrollHeight;
                                        }
                                    }
                                    typeChar();
                                } catch (err) {
                                    document.getElementById(spinnerId)?.remove();
                                    log.innerHTML += `<p><strong>❌ Error:</strong> ${err.message}</p>`;
                                    log.scrollTop = log.scrollHeight;
                                }
                            });
                        }
                    })
                    .catch((err) => {
                        mainContent.innerHTML = "<p>❌ Failed to load page.</p>";
                        console.error("Page load error:", err);
                    });
            });
        } else {
            console.log("Button not found:", btnId);
        }
    });

    // Handle browser back/forward navigation
    window.addEventListener('popstate', function(event) {
        const route = window.location.pathname;
        fetch(route)
            .then(res => res.text())
            .then(html => {
                mainContent.innerHTML = html;
                // Dynamically load attack_surface.js if loading the Attack Surface page
                if (route === "/attack_surface") {
                    const existingScript = document.querySelector('script[src="/static/js/attack_surface.js"]');
                    if (existingScript) existingScript.remove();
                    const script = document.createElement('script');
                    script.src = '/static/js/attack_surface.js';
                    script.defer = true;
                    document.body.appendChild(script);
                }
            });
    });

    // === Real-time Dashboard Updates ===
    // Add Chart.js CDN
    if (!document.getElementById('chartjs-cdn')) {
        const chartScript = document.createElement('script');
        chartScript.id = 'chartjs-cdn';
        chartScript.src = 'https://cdn.jsdelivr.net/npm/chart.js';
        document.head.appendChild(chartScript);
    }
    let activeScansPie = null;
    function updateActiveScansLegend(data) {
        const counts = [data.queued_scans.length, data.running_scans.length, data.finished_scans.length];
        const labels = ['Queued', 'Running', 'Finished'];
        const colors = ['#ff9800', '#2196f3', '#4caf50'];
        let legendHtml = '';
        labels.forEach((label, i) => {
            legendHtml += `<span style=\"display:inline-block;width:18px;height:18px;background:${colors[i]};border-radius:4px;margin-right:8px;vertical-align:middle;\"></span> <span style=\"font-weight:bold;\">${label}:</span> <b>${counts[i]}</b> &nbsp;&nbsp;`;
        });
        document.getElementById('active-scans-legend').innerHTML = legendHtml;
    }
    function updateRecentActivityTimeline(data) {
        const timeline = document.getElementById('recent-activity-timeline');
        if (!timeline) return;
        let html = '';
        if (!data.recent_activities.length) {
            html = '<li style="color:#888;text-align:center;">No recent activity available.</li>';
        } else {
            data.recent_activities.forEach(activity => {
                // Choose icon and badge color by scan type (if available)
                let icon = '📝';
                let badge = '<span style="background:#222;color:#0f0;padding:2px 8px;border-radius:8px;font-size:0.9em;margin-right:8px;">Scan</span>';
                if (activity.description.toLowerCase().includes('port scan')) { icon = '🌐'; badge = '<span style="background:#2196f3;color:#fff;padding:2px 8px;border-radius:8px;font-size:0.9em;margin-right:8px;">Port</span>'; }
                if (activity.description.toLowerCase().includes('domain')) { icon = '🌍'; badge = '<span style="background:#4caf50;color:#fff;padding:2px 8px;border-radius:8px;font-size:0.9em;margin-right:8px;">Domain</span>'; }
                if (activity.description.toLowerCase().includes('subdomain')) { icon = '🧩'; badge = '<span style="background:#ff9800;color:#fff;padding:2px 8px;border-radius:8px;font-size:0.9em;margin-right:8px;">Subdomain</span>'; }
                if (activity.description.toLowerCase().includes('waf')) { icon = '🛡️'; badge = '<span style="background:#9c27b0;color:#fff;padding:2px 8px;border-radius:8px;font-size:0.9em;margin-right:8px;">WAF</span>'; }
                if (activity.description.toLowerCase().includes('website')) { icon = '🖥️'; badge = '<span style="background:#00bcd4;color:#fff;padding:2px 8px;border-radius:8px;font-size:0.9em;margin-right:8px;">Web</span>'; }
                if (activity.description.toLowerCase().includes('wordpress')) { icon = '⚙️'; badge = '<span style="background:#607d8b;color:#fff;padding:2px 8px;border-radius:8px;font-size:0.9em;margin-right:8px;">WP</span>'; }
                if (activity.description.toLowerCase().includes('sqli')) { icon = '💉'; badge = '<span style="background:#e91e63;color:#fff;padding:2px 8px;border-radius:8px;font-size:0.9em;margin-right:8px;">SQLi</span>'; }
                if (activity.description.toLowerCase().includes('xss')) { icon = '⚡'; badge = '<span style="background:#ffc107;color:#222;padding:2px 8px;border-radius:8px;font-size:0.9em;margin-right:8px;">XSS</span>'; }
                if (activity.description.toLowerCase().includes('whois')) { icon = '🔎'; badge = '<span style="background:#607d8b;color:#fff;padding:2px 8px;border-radius:8px;font-size:0.9em;margin-right:8px;">Whois</span>'; }
                if (activity.description.toLowerCase().includes('dns')) { icon = '📡'; badge = '<span style="background:#00bcd4;color:#fff;padding:2px 8px;border-radius:8px;font-size:0.9em;margin-right:8px;">DNS</span>'; }
                html += `<li style=\"margin-bottom:1em;display:flex;align-items:center;\"><span style=\"font-size:1.3em;margin-right:10px;\">${icon}</span>${badge}<span style=\"color:#0f0;font-family:monospace;font-size:1em;margin-right:10px;\">${activity.timestamp.replace('T',' ').slice(0,19)}</span> <span style=\"color:#fff;\">${activity.description}</span></li>`;
            });
        }
        timeline.innerHTML = html;
    }
    function updateActiveScansAndRecentActivity() {
        fetch('/api/active-scans')
            .then(res => res.json())
            .then(data => {
                updateActiveScansLegend(data);
                updateRecentActivityTimeline(data);
            });
    }
    function updateAttackSurfaceSummary() {
        fetch('/api/attack_surface_stats')
            .then(res => res.json())
            .then(stats => {
                if (document.getElementById('ip-address-count')) document.getElementById('ip-address-count').textContent = stats.ips || 0;
                if (document.getElementById('hostnames-count')) document.getElementById('hostnames-count').textContent = stats.domains || 0;
                if (document.getElementById('port-count')) document.getElementById('port-count').textContent = stats.open_ports || 0;
                if (document.getElementById('protocol-count')) document.getElementById('protocol-count').textContent = stats.subdomains || 0;
                if (document.getElementById('services-count')) document.getElementById('services-count').textContent = stats.endpoints || 0;
                if (document.getElementById('technologies-count')) document.getElementById('technologies-count').textContent = stats.technologies || 0;
            });
    }
    function updateRiskScore() {
        fetch('/api/risk_score')
            .then(res => res.json())
            .then(data => {
                const val = document.getElementById('risk-score-value');
                const desc = document.getElementById('risk-score-desc');
                if (val) {
                    val.textContent = data.score;
                    val.style.color = data.color;
                }
                if (desc) desc.textContent = data.desc;
            });
    }
    // Only run on dashboard
    if (window.location.pathname === '/' || window.location.pathname === '/dashboard') {
        updateActiveScansAndRecentActivity();
        updateAttackSurfaceSummary();
        updateRiskScore();
        setInterval(updateActiveScansAndRecentActivity, 5000);
        setInterval(updateAttackSurfaceSummary, 5000);
        setInterval(updateRiskScore, 10000);
    }
});

document.addEventListener("click", function(e) {
    const websiteScannerCard = e.target.closest("#website_scanner-btn");
    const portScannerCard = e.target.closest("#port-scanner-btn");
    const domainFinderCard = e.target.closest("#domain-finder-btn");
    const subdomainFinderCard = e.target.closest("#subdomain-finder-btn");
    const sqliExploiterCard = e.target.closest("#sqli-exploiter-btn");
    const whoisLookupCard = e.target.closest("#whois-lookup-btn");
    const dnsLookupCard = e.target.closest("#dns-lookup-btn");
    
    if (websiteScannerCard) {
        console.log("Website Scanner card clicked");
        e.preventDefault();
        fetch("/website_scanner")
            .then(res => res.text())
            .then(html => {
                document.getElementById("main-content").innerHTML = html;
                // Dynamically import zap_scanner.js as a module after DOM update and call initZapScanner
                import("/static/js/zap_scanner.js").then(mod => {
                    mod.initZapScanner();
                    console.log("zap_scanner.js initialized after DOM update");
                });
            });
    }
    
    if (portScannerCard) {
        console.log("Port Scanner card clicked");
        e.preventDefault();
        fetch("/port-scanner")
            .then(res => res.text())
            .then(html => {
                document.getElementById("main-content").innerHTML = html;
                // Dynamically import port_scanner.js as a module after DOM update
                import("/static/js/port_scanner.js").then(mod => {
                    mod.initPortScanner();
                    console.log("port_scanner.js initialized after DOM update");
                });
            });
    }

    if (domainFinderCard) {
        console.log("Domain Finder card clicked");
        e.preventDefault();
        fetch("/domain-finder")
            .then(res => res.text())
            .then(html => {
                document.getElementById("main-content").innerHTML = html;
                // Dynamically import domain_finder.js as a module after DOM update
                import("/static/js/domain_finder.js").then(mod => {
                    mod.initDomainFinder();
                    console.log("domain_finder.js initialized after DOM update");
                });
            });
    }

    if (subdomainFinderCard) {
        console.log("Subdomain Finder card clicked");
        e.preventDefault();
        fetch("/subdomain-finder")
            .then(res => res.text())
            .then(html => {
                document.getElementById("main-content").innerHTML = html;
                // Dynamically import subdomain_finder.js as a module after DOM update
                import("/static/js/subdomain_finder.js").then(mod => {
                    mod.initSubdomainFinder();
                    console.log("subdomain_finder.js initialized after DOM update");
                });
            });
    }

    if (sqliExploiterCard) {
        console.log("SQLi Exploiter card clicked");
        e.preventDefault();
        fetch("/sqli-exploiter")
            .then(res => res.text())
            .then(html => {
                document.getElementById("main-content").innerHTML = html;
                // Dynamically import sqli_exploiter.js as a module after DOM update
                import("/static/js/sqli_exploiter.js").then(mod => {
                    mod.initSqliExploiter();
                    console.log("sqli_exploiter.js initialized after DOM update");
                });
            });
    }

    if (whoisLookupCard) {
        console.log("Whois Lookup card clicked");
        e.preventDefault();
        fetch("/whois-lookup")
            .then(res => res.text())
            .then(html => {
                document.getElementById("main-content").innerHTML = html;
                import("/static/js/whois_lookup.js").then(mod => {
                    mod.initWhoisLookup();
                    console.log("whois_lookup.js initialized after DOM update");
                });
            });
    }

    if (dnsLookupCard) {
        console.log("DNS Lookup card clicked");
        e.preventDefault();
        fetch("/dns-lookup")
            .then(res => res.text())
            .then(html => {
                document.getElementById("main-content").innerHTML = html;
                import("/static/js/dns_lookup.js").then(mod => {
                    mod.initDnsLookup();
                    console.log("dns_lookup.js initialized after DOM update");
                });
            });
    }
});
