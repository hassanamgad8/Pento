export function initSniper() {
    console.log('[sniper.js] initSniper called');
    const chatMessages = document.getElementById('chat-messages');
    const targetInput = document.getElementById('target-input');
    const startScanBtn = document.getElementById('start-scan');
    const downloadReportBtn = document.getElementById('download-report');
    const resultsContainer = document.getElementById('results-container');
    const loadingModal = new window.bootstrap.Modal(document.getElementById('loadingModal'));
    const loadingMessage = document.getElementById('loading-message');
    const progressBar = document.querySelector('.progress-bar');
    const sniperForm = document.getElementById('sniper-form');
    const tagsInput = document.getElementById('tags-input');
    const cookiesInput = document.getElementById('cookies-input');
    const headersInput = document.getElementById('headers-input');

    // Form validation
    function validateForm() {
        const target = targetInput.value.trim();
        if (!target) {
            showError('Please enter a valid target IP or URL.');
            return false;
        }
        return true;
    }

    function showError(message) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'alert alert-danger alert-dismissible fade show';
        errorDiv.innerHTML = `
            <i class="fas fa-exclamation-circle me-2"></i>${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        sniperForm.insertBefore(errorDiv, sniperForm.firstChild);
        setTimeout(() => errorDiv.remove(), 5000);
    }

    function addMessage(message, type = 'system') {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${type}`;
        
        // Add icon based on message type
        let icon = 'fa-info-circle';
        if (type === 'user') icon = 'fa-user';
        if (type === 'error') icon = 'fa-exclamation-triangle';
        
        messageDiv.innerHTML = `
            <div class="d-flex align-items-start">
                <i class="fas ${icon} me-2 mt-1"></i>
                <div class="flex-grow-1">${message}</div>
            </div>
        `;
        
        chatMessages.appendChild(messageDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    function updateProgress(percent, message) {
        progressBar.style.width = `${percent}%`;
        loadingMessage.innerHTML = `
            <i class="fas fa-spinner fa-spin me-2"></i>${message}
        `;
    }

    function parseIfJson(str) {
        if (typeof str === 'string') {
            try {
                const obj = JSON.parse(str);
                if (typeof obj === 'object') return obj;
            } catch (e) {}
        }
        return str;
    }

    function formatTimestamp() {
        const now = new Date();
        return now.toLocaleTimeString();
    }

    function updateResults(data) {
        resultsContainer.style.display = '';
        
        // Parse possible JSON strings to objects
        data.vulnerabilities = parseIfJson(data.vulnerabilities);
        data.system_info = parseIfJson(data.system_info);
        data.network_topology = parseIfJson(data.network_topology);
        data.exploitation_results = parseIfJson(data.exploitation_results);
        data.spring4shell_result = parseIfJson(data.spring4shell_result);
        data.exploit_results = parseIfJson(data.exploit_results);
        // Handle nuclei_output as string or array
        if (Array.isArray(data.nuclei_output)) {
            data.nuclei_output = data.nuclei_output.map(line => {
                if (typeof line === 'string') return line;
                return JSON.stringify(line, null, 2);
            }).join('\n');
        }

        // Update each tab with formatted content
        updateSummaryTab(data);
        updateSystemTab(data);
        updateUsersTab(data);
        updateProcessesTab(data);
        updateFilesystemTab(data);
        updateNetworkTab(data);
        updateConsoleTab(data);
        updateReportTab(data);

        downloadReportBtn.disabled = false;
    }

    function updateSummaryTab(data) {
        const summaryTab = document.getElementById('summary');
        let summaryHtml = '<div class="summary-content">';

        // Add scan overview
        summaryHtml += `
            <div class="card bg-dark border-success mb-4">
                <div class="card-header">
                    <h6 class="mb-0"><i class="fas fa-chart-pie me-2"></i>Scan Overview</h6>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-6">
                            <p><strong>Target:</strong> ${data.target || 'N/A'}</p>
                            <p><strong>Scan Time:</strong> ${data.scan_time || 'N/A'}</p>
                        </div>
                        <div class="col-md-6">
                            <p><strong>Vulnerabilities Found:</strong> ${data.vulnerabilities?.length || 0}</p>
                            <p><strong>Successful Exploits:</strong> ${data.exploitation_results?.length || 0}</p>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Add vulnerabilities section
        if (data.vulnerabilities && data.vulnerabilities.length > 0) {
            summaryHtml += `
                <div class="card bg-dark border-success mb-4">
                    <div class="card-header">
                        <h6 class="mb-0"><i class="fas fa-bug me-2"></i>Vulnerabilities</h6>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-dark table-hover">
                                <thead>
                                    <tr>
                                        <th>Severity</th>
                                        <th>Name</th>
                                        <th>Description</th>
                                    </tr>
                                </thead>
                                <tbody>
            `;
            data.vulnerabilities.forEach(vuln => {
                const severityClass = {
                    'critical': 'danger',
                    'high': 'danger',
                    'medium': 'warning',
                    'low': 'info'
                }[vuln.severity] || 'secondary';
                
                summaryHtml += `
                    <tr>
                        <td><span class="badge bg-${severityClass}">${vuln.severity}</span></td>
                        <td>${vuln.name || vuln.template}</td>
                        <td>${vuln.description || 'N/A'}</td>
                    </tr>
                `;
            });
            summaryHtml += `
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            `;
        }

        // Add exploitation results
        if (data.exploitation_results && data.exploitation_results.length > 0) {
            summaryHtml += `
                <div class="card bg-dark border-success">
                    <div class="card-header">
                        <h6 class="mb-0"><i class="fas fa-terminal me-2"></i>Exploitation Results</h6>
                    </div>
                    <div class="card-body">
            `;
            data.exploitation_results.forEach(res => {
                summaryHtml += `
                    <div class="exploit-result mb-3">
                        <h6 class="text-success">
                            <i class="fas fa-check-circle me-2"></i>${res.service} on port ${res.port}
                        </h6>
                        <div class="ms-4">
                            <p><strong>Module:</strong> ${res.module}</p>
                            <p><strong>Payload:</strong> ${res.payload}</p>
                            ${res.session_id ? `<p><strong>Session ID:</strong> ${res.session_id}</p>` : ''}
                            <pre class="mt-2">${escapeHtml(res.output)}</pre>
                        </div>
                    </div>
                `;
            });
            summaryHtml += `
                    </div>
                </div>
            `;
        }

        summaryHtml += '</div>';
        summaryTab.innerHTML = summaryHtml || '<div class="alert alert-info">No results available.</div>';
    }

    function updateSystemTab(data) {
        const systemTab = document.getElementById('system');
        if (data.exploitation_results && data.exploitation_results[0]?.post_exploitation?.system) {
            systemTab.innerHTML = `
                <div class="card bg-dark border-success">
                    <div class="card-body">
                        <pre>${escapeHtml(data.exploitation_results[0].post_exploitation.system)}</pre>
                    </div>
                </div>
            `;
        } else {
            systemTab.innerHTML = '<div class="alert alert-info">No system information available.</div>';
        }
    }

    function updateUsersTab(data) {
        const usersTab = document.getElementById('users');
        if (data.exploitation_results && data.exploitation_results[0]?.post_exploitation?.credentials) {
            usersTab.innerHTML = `
                <div class="card bg-dark border-success">
                    <div class="card-body">
                        <pre>${escapeHtml(data.exploitation_results[0].post_exploitation.credentials)}</pre>
                    </div>
                </div>
            `;
        } else {
            usersTab.innerHTML = '<div class="alert alert-info">No user information available.</div>';
        }
    }

    function updateProcessesTab(data) {
        const processesTab = document.getElementById('processes');
        if (data.exploitation_results && data.exploitation_results[0]?.post_exploitation?.processes) {
            processesTab.innerHTML = `
                <div class="card bg-dark border-success">
                    <div class="card-body">
                        <pre>${escapeHtml(data.exploitation_results[0].post_exploitation.processes)}</pre>
                    </div>
                </div>
            `;
        } else {
            processesTab.innerHTML = '<div class="alert alert-info">No process information available.</div>';
        }
    }

    function updateFilesystemTab(data) {
        const filesystemTab = document.getElementById('filesystem');
        if (data.exploitation_results && data.exploitation_results[0]?.post_exploitation?.filesystem) {
            filesystemTab.innerHTML = `
                <div class="card bg-dark border-success">
                    <div class="card-body">
                        <pre>${escapeHtml(data.exploitation_results[0].post_exploitation.filesystem)}</pre>
                    </div>
                </div>
            `;
        } else {
            filesystemTab.innerHTML = '<div class="alert alert-info">No filesystem information available.</div>';
        }
    }

    function updateNetworkTab(data) {
        const networkTab = document.getElementById('network');
        if (data.exploitation_results && data.exploitation_results[0]?.post_exploitation?.network) {
            networkTab.innerHTML = `
                <div class="card bg-dark border-success">
                    <div class="card-body">
                        <pre>${escapeHtml(data.exploitation_results[0].post_exploitation.network)}</pre>
                    </div>
                </div>
            `;
        } else {
            networkTab.innerHTML = '<div class="alert alert-info">No network information available.</div>';
        }
    }

    function updateConsoleTab(data) {
        const consoleTab = document.getElementById('console');
        let consoleHtml = '<div class="console-content">';

        if (data.nmap_output) {
            consoleHtml += `
                <div class="card bg-dark border-success mb-4">
                    <div class="card-header">
                        <h6 class="mb-0"><i class="fas fa-search me-2"></i>Nmap Output</h6>
                    </div>
                    <div class="card-body">
                        <pre>${escapeHtml(data.nmap_output)}</pre>
                    </div>
                </div>
            `;
        }

        if (data.nuclei_output) {
            consoleHtml += `
                <div class="card bg-dark border-success mb-4">
                    <div class="card-header">
                        <h6 class="mb-0"><i class="fas fa-bug me-2"></i>Nuclei Output</h6>
                    </div>
                    <div class="card-body">
                        <pre>${escapeHtml(data.nuclei_output)}</pre>
                    </div>
                </div>
            `;
        }

        if (data.exploitation_results && data.exploitation_results.length > 0) {
            data.exploitation_results.forEach((res, i) => {
                consoleHtml += `
                    <div class="card bg-dark border-success mb-4">
                        <div class="card-header">
                            <h6 class="mb-0"><i class="fas fa-terminal me-2"></i>Metasploit Output [${i+1}]</h6>
                        </div>
                        <div class="card-body">
                            <pre>${escapeHtml(res.output)}</pre>
                            ${res.post_exploitation?.output ? `
                                <h6 class="mt-4">Post-Exploitation Output</h6>
                                <pre>${escapeHtml(res.post_exploitation.output)}</pre>
                            ` : ''}
                        </div>
                    </div>
                `;
            });
        }

        consoleHtml += '</div>';
        consoleTab.innerHTML = consoleHtml || '<div class="alert alert-info">No console output available.</div>';
    }

    function updateReportTab(data) {
        const reportTab = document.getElementById('report');
        if (data.llm_report) {
            const converter = new showdown.Converter({
                tables: true,
                tasklists: true,
                strikethrough: true,
                emoji: true,
                ghCodeBlocks: true,
                ghCompatibleHeaderId: true,
                parseImgDimensions: true,
                simplifiedAutoLink: true,
                openLinksInNewWindow: true
            });
            
            // Configure showdown options
            converter.setOption('headerAttributes', 'class="markdown-header"');
            converter.setOption('codeBlockStyle', 'fenced');
            
            const html = converter.makeHtml(data.llm_report);
            reportTab.innerHTML = `
                <div class="markdown-output p-3 text-light" style="background: #111; font-family: monospace;">
                    ${html}
                </div>
            `;
            
            // Add click handlers for CVEs and external links
            const links = reportTab.querySelectorAll('a');
            links.forEach(link => {
                link.target = '_blank';
                link.className = 'text-warning';
                
                // Special handling for CVE links
                if (link.href.includes('CVE-') || link.textContent.match(/CVE-\d{4}-\d+/)) {
                    link.addEventListener('click', (e) => {
                        e.preventDefault();
                        const cveId = link.textContent.match(/CVE-\d{4}-\d+/)?.[0] || link.textContent;
                        window.open(`https://nvd.nist.gov/vuln/detail/${cveId}`, '_blank');
                    });
                }
            });

            // Add syntax highlighting to code blocks
            const codeBlocks = reportTab.querySelectorAll('pre code');
            codeBlocks.forEach(block => {
                block.className = 'language-bash';
                hljs.highlightElement(block);
            });
        } else {
            reportTab.innerHTML = '<div class="alert alert-info">No LLM report available.</div>';
        }
    }

    function escapeHtml(text) {
        if (!text) return '';
        if (typeof text !== 'string') text = String(text);
        return text.replace(/[&<>"']/g, function (c) {
            return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'}[c];
        });
    }

    if (sniperForm) {
        console.log('[sniper.js] Attaching submit handler to sniperForm');
        sniperForm.addEventListener('submit', async function(e) {
            console.log('[sniper.js] sniperForm submit handler triggered');
            e.preventDefault();
            
            if (!validateForm()) return;

            const target = targetInput.value.trim();
            const tags = tagsInput ? tagsInput.value.trim() : '';
            const cookies = cookiesInput ? cookiesInput.value.trim() : '';
            const headers = headersInput ? headersInput.value.trim() : '';

            // Clear previous results and messages
            resultsContainer.style.display = 'none';
            chatMessages.innerHTML = '';
            
            // Show loading state
            loadingModal.show();
            addMessage(`[${formatTimestamp()}] Starting scan for target: ${target}`, 'user');

            try {
                const response = await fetch('/api/sniper/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ target, tags, cookies, headers })
                });

                const reader = response.body.getReader();
                const decoder = new TextDecoder();

                while (true) {
                    const {value, done} = await reader.read();
                    if (done) break;

                    const chunk = decoder.decode(value);
                    const events = chunk.split('\n').filter(Boolean);

                    for (const event of events) {
                        const data = JSON.parse(event);
                        if (data.type === 'progress') {
                            updateProgress(data.percent, data.message);
                        } else if (data.type === 'message') {
                            addMessage(`[${formatTimestamp()}] ${data.message}`, data.messageType || 'system');
                        } else if (data.type === 'results') {
                            updateProgress(100, "Scan complete. Rendering results...");
                            updateResults(data.data);
                        }
                    }
                }
            } catch (error) {
                addMessage(`[${formatTimestamp()}] Error: ${error.message}`, 'error');
                showError('An error occurred during the scan. Please try again.');
            } finally {
                loadingMessage.innerHTML = '';
                loadingModal.hide();
            }
        });
    } else {
        console.warn('[sniper.js] sniperForm not found!');
    }

    downloadReportBtn.addEventListener('click', async function() {
        try {
            addMessage(`[${formatTimestamp()}] Generating report...`, 'system');
            const response = await fetch('/api/sniper/report', {
                method: 'GET'
            });
            
            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'sniper-report.pdf';
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                a.remove();
                addMessage(`[${formatTimestamp()}] Report downloaded successfully.`, 'system');
            } else {
                throw new Error('Failed to generate report');
            }
        } catch (error) {
            addMessage(`[${formatTimestamp()}] Error downloading report: ${error.message}`, 'error');
            showError('Failed to generate report. Please try again.');
        }
    });

    // Add this to your existing styles
    const style = document.createElement('style');
    style.textContent = `
        .markdown-output {
            line-height: 1.6;
            font-size: 0.95rem;
        }

        .markdown-output h1, 
        .markdown-output h2, 
        .markdown-output h3, 
        .markdown-output h4, 
        .markdown-output h5, 
        .markdown-output h6 {
            color: #00ff00;
            margin-top: 1.5rem;
            margin-bottom: 1rem;
            border-bottom: 1px solid #333;
            padding-bottom: 0.5rem;
            font-weight: 600;
        }

        .markdown-output h1 { font-size: 1.8rem; }
        .markdown-output h2 { font-size: 1.5rem; }
        .markdown-output h3 { font-size: 1.2rem; }
        .markdown-output h4 { font-size: 1.1rem; }
        .markdown-output h5, 
        .markdown-output h6 { font-size: 1rem; }

        .markdown-output p {
            margin-bottom: 1rem;
        }

        .markdown-output pre {
            background: #000;
            color: #0f0;
            padding: 1rem;
            border-left: 3px solid #0f0;
            overflow-x: auto;
            border-radius: 4px;
            margin: 1rem 0;
        }

        .markdown-output code {
            background: #000;
            color: #0f0;
            padding: 0.2rem 0.4rem;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }

        .markdown-output pre code {
            padding: 0;
            background: transparent;
        }

        .markdown-output blockquote {
            border-left: 4px solid #00ff00;
            margin: 1rem 0;
            padding: 0.5rem 1rem;
            background: rgba(0, 255, 0, 0.05);
        }

        .markdown-output ul, 
        .markdown-output ol {
            margin: 1rem 0;
            padding-left: 2rem;
        }

        .markdown-output li {
            margin: 0.5rem 0;
        }

        .markdown-output table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
            background: rgba(0, 0, 0, 0.3);
        }

        .markdown-output th, 
        .markdown-output td {
            padding: 0.75rem;
            border: 1px solid #333;
        }

        .markdown-output th {
            background: rgba(0, 255, 0, 0.1);
            color: #00ff00;
        }

        .markdown-output tr:nth-child(even) {
            background: rgba(0, 0, 0, 0.2);
        }

        .markdown-output a {
            color: #00ff00;
            text-decoration: none;
            border-bottom: 1px dotted #00ff00;
            transition: all 0.2s ease;
        }

        .markdown-output a:hover {
            color: #00cc00;
            border-bottom: 1px solid #00cc00;
        }

        .markdown-output img {
            max-width: 100%;
            height: auto;
            border-radius: 4px;
            margin: 1rem 0;
        }

        .markdown-output hr {
            border: none;
            border-top: 1px solid #333;
            margin: 2rem 0;
        }

        .markdown-output .task-list-item {
            list-style-type: none;
            margin-left: -1.5rem;
        }

        .markdown-output .task-list-item-checkbox {
            margin-right: 0.5rem;
        }

        .markdown-output .emoji {
            height: 1.2em;
            width: 1.2em;
            margin: 0 0.1em;
            vertical-align: -0.1em;
        }
    `;
    document.head.appendChild(style);
} 