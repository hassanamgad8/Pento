export async function initZapScanner() {
    const formContainer = document.getElementById("scan-form-container");
    const progressContainer = document.getElementById("scan-progress-container");
    const resultsContainer = document.getElementById("scan-results-container");

    if (!formContainer) {
        console.log("zap_scanner.js: #scan-form-container not found");
        return;
    }

    let currentScanId = null;
    let scanStatusInterval = null;

    async function loadProgressTemplate() {
        try {
            const response = await fetch("/scan_partials/progress");
            if (response.ok) {
                progressContainer.innerHTML = await response.text();
                progressContainer.classList.remove("hidden");
                setupProgressListeners();
            }
        } catch (err) {
            console.error("Error loading progress template:", err);
        }
    }

    async function loadResultsTemplate() {
        try {
            const response = await fetch("/scan_partials/results");
            if (response.ok) {
                resultsContainer.innerHTML = await response.text();
                resultsContainer.classList.remove("hidden");
                setupResultsListeners();
            }
        } catch (err) {
            console.error("Error loading results template:", err);
        }
    }

    function setupProgressListeners() {
        const cancelBtn = document.getElementById("cancel-scan-btn");
        if (cancelBtn) cancelBtn.addEventListener("click", cancelScan);
    }

    function setupResultsListeners() {
        // Placeholder for future logic
    }

    const zapForm = document.getElementById("zap-scan-form");
    if (zapForm) {
        console.log("zap_scanner.js: attaching submit handler to #zap-scan-form");
        zapForm.addEventListener("submit", async function (e) {
            e.preventDefault();
            console.log("zap_scanner.js: form submitted");
            const url = document.getElementById("zap-url").value;
            const spider = document.getElementById("use-spider").checked;
            const ajax = document.getElementById("use-ajax").checked;
            const active = document.getElementById("use-active").checked;

            try {
                const response = await fetch("/zap_scan", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ url, spider, ajax, active })
                });

                const result = await response.json();

                if (result.error) {
                    alert(`Error: ${result.error}`);
                    return;
                }

                currentScanId = result.scan_id;
                formContainer.classList.add("hidden");
                await loadProgressTemplate();

                document.getElementById("scan-target-url").textContent = url;

                startStatusPolling();
            } catch (err) {
                console.error("Error starting scan:", err);
                alert(`Error starting scan: ${err.message}`);
            }
        });
    } else {
        console.log("zap_scanner.js: #zap-scan-form not found");
    }

    function startStatusPolling() {
        if (scanStatusInterval) clearInterval(scanStatusInterval);
        checkScanStatus();
        scanStatusInterval = setInterval(checkScanStatus, 3000);
    }

    async function checkScanStatus() {
        if (!currentScanId) return;

        try {
            const response = await fetch(`/zap_scan_status?scan_id=${currentScanId}`);
            const scanInfo = await response.json();

            updateProgressUI(scanInfo);

            if (scanInfo.status === "completed") {
                clearInterval(scanStatusInterval);
                await showResults(scanInfo);
            }
        } catch (err) {
            console.error("Error checking scan status:", err);
            addLogEntry(`❌ Error: ${err.message}`);
        }
    }

    function updateProgressUI(scanInfo) {
        const progressBar = document.getElementById("scan-progress-bar");
        const progressLabel = document.getElementById("scan-progress-label");
        const currentStage = document.getElementById("scan-current-stage");
        const statusMessage = document.getElementById("scan-status-message");

        if (!progressBar || !progressLabel || !currentStage || !statusMessage) return;

        const progress = Math.round(scanInfo.progress);
        progressBar.style.width = `${progress}%`;
        progressLabel.textContent = `${progress}%`;
        currentStage.textContent = scanInfo.current_stage || "Processing";
        statusMessage.textContent = `Status: ${scanInfo.status.replace(/_/g, " ")}`;

        if (scanInfo.status !== window.lastStatus) {
            addLogEntry(`${getStatusEmoji(scanInfo.status)} ${scanInfo.current_stage || scanInfo.status}`);
            window.lastStatus = scanInfo.status;
        }
    }

    function addLogEntry(message) {
        const scanLog = document.getElementById("scan-log");
        if (!scanLog) return;

        const entry = document.createElement("div");
        entry.className = "log-entry";
        entry.textContent = message;
        scanLog.appendChild(entry);
        scanLog.scrollTop = scanLog.scrollHeight;
    }

    function getStatusEmoji(status) {
        const statusEmojis = {
            "initialized": "🚀",
            "spider_running": "🕷️",
            "spider_completed": "✅",
            "ajax_running": "⚙️",
            "ajax_completed": "✅",
            "active_running": "⚡",
            "active_completed": "✅",
            "generating_reports": "📄",
            "completed": "🎉",
            "cancelled": "❌"
        };
        return statusEmojis[status] || "➡️";
    }

    async function cancelScan() {
        if (!currentScanId) return;

        try {
            const response = await fetch("/zap_scan_cancel", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ scan_id: currentScanId })
            });

            await response.json();
            clearInterval(scanStatusInterval);
            addLogEntry("❌ Scan cancelled by user");

            setTimeout(() => {
                progressContainer.classList.add("hidden");
                formContainer.classList.remove("hidden");
            }, 2000);
        } catch (err) {
            console.error("Error cancelling scan:", err);
            addLogEntry(`❌ Error cancelling scan: ${err.message}`);
        }
    }

    async function showResults(scanInfo) {
        await loadResultsTemplate();
        progressContainer.innerHTML = ""; // ✅ Clear previous progress block to prevent duplication

        const targetEl = document.getElementById("scan-target-url");
        if (targetEl) targetEl.textContent = scanInfo.url;

        if (scanInfo.reports) {
            const htmlBtn = document.getElementById("html-report-link");
            const pdfBtn = document.getElementById("pdf-report-link");
            const jsonBtn = document.getElementById("json-report-link");

            if (htmlBtn) htmlBtn.href = scanInfo.reports.html;
            if (pdfBtn) pdfBtn.href = scanInfo.reports.pdf;
            if (jsonBtn) jsonBtn.href = scanInfo.reports.json;
        }

        const counts = { high: 0, medium: 0, low: 0, info: 0 };
        if (scanInfo.alerts && scanInfo.alerts.length) {
            scanInfo.alerts.forEach(alert => {
                const risk = alert.risk.toLowerCase();
                if (risk.includes("high")) counts.high++;
                else if (risk.includes("medium")) counts.medium++;
                else if (risk.includes("low")) counts.low++;
                else counts.info++;
            });
        }

        const total = counts.high + counts.medium + counts.low + counts.info;

        const assign = (id, val) => {
            const el = document.getElementById(id);
            if (el) el.textContent = val;
        };

        assign("high-count", counts.high);
        assign("medium-count", counts.medium);
        assign("low-count", counts.low);
        assign("info-count", counts.info);
        assign("total-count", total);
    }

    function createAlertElement(alert) {
        const alertItem = document.createElement("div");

        let severityClass = "bg-blue-50 border-blue-200";
        if (alert.risk.toLowerCase().includes("high")) {
            severityClass = "bg-red-50 border-red-200";
        } else if (alert.risk.toLowerCase().includes("medium")) {
            severityClass = "bg-orange-50 border-orange-200";
        } else if (alert.risk.toLowerCase().includes("low")) {
            severityClass = "bg-yellow-50 border-yellow-200";
        }

        alertItem.className = `p-4 ${severityClass} border rounded-md`;
        alertItem.innerHTML = `
            <div class="flex justify-between items-start">
                <h4 class="font-medium">${escapeHtml(alert.name || alert.alert)}</h4>
                <span class="px-2 py-1 text-xs font-medium rounded ${getRiskBadgeClass(alert.risk)}">${alert.risk}</span>
            </div>
            <div class="mt-2">
                <p class="text-sm"><strong>URL:</strong> ${escapeHtml(alert.url)}</p>
                ${alert.param ? `<p class="text-sm"><strong>Parameter:</strong> ${escapeHtml(alert.param)}</p>` : ''}
                ${alert.evidence ? `<p class="text-sm mt-2"><strong>Evidence:</strong> <code class="bg-gray-100 px-1 py-0.5 rounded">${escapeHtml(alert.evidence)}</code></p>` : ''}
            </div>
            ${alert.solution ? `
            <div class="mt-2 pt-2 border-t border-gray-200">
                <p class="text-sm"><strong>Solution:</strong> ${escapeHtml(alert.solution)}</p>
            </div>` : ''}
        `;
        return alertItem;
    }

    function getRiskBadgeClass(risk) {
        const riskLower = risk.toLowerCase();
        if (riskLower.includes("high")) {
            return "bg-red-100 text-red-800";
        } else if (riskLower.includes("medium")) {
            return "bg-orange-100 text-orange-800";
        } else if (riskLower.includes("low")) {
            return "bg-yellow-100 text-yellow-800";
        } else {
            return "bg-blue-100 text-blue-800";
        }
    }

    function escapeHtml(unsafe) {
        if (!unsafe) return '';
        return unsafe
            .toString()
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    console.log("✅ zap_scanner.js loaded.");
}
