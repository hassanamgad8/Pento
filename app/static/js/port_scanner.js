export function initPortScanner() {
    const form = document.getElementById('port-scan-form');
    const resultsDiv = document.getElementById('scan-results');
    const resultsContent = document.getElementById('results-content');
    const errorMessage = document.getElementById('error-message');
    const pdfBtn = document.getElementById('pdf-report-btn');

    if (!form) {
        console.error('Port scanner form not found');
        return;
    }

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        // Hide previous results and errors
        resultsDiv.classList.add('hidden');
        errorMessage.classList.add('hidden');
        if (pdfBtn) pdfBtn.style.display = 'none';
        
        // Get form data
        const target = document.getElementById('target').value;
        const scanType = document.querySelector('input[name="scan_type"]:checked').value;
        const verbose = document.getElementById('verbose').checked;
        const timing = document.getElementById('timing').checked;
        
        try {
            // Show loading state
            const submitButton = form.querySelector('button[type="submit"]');
            submitButton.textContent = 'Scanning...';
            submitButton.disabled = true;
            
            // Send scan request
            const response = await fetch('/api/port-scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    target,
                    scan_type: scanType,
                    verbose,
                    timing
                })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                // Show results
                resultsContent.textContent = data.output;
                resultsDiv.classList.remove('hidden');
                if (pdfBtn) pdfBtn.style.display = '';
            } else {
                // Show error
                errorMessage.textContent = data.error || 'An error occurred during the scan';
                errorMessage.classList.remove('hidden');
            }
        } catch (error) {
            // Show error
            errorMessage.textContent = 'Failed to connect to the server';
            errorMessage.classList.remove('hidden');
            console.error('Scan error:', error);
        } finally {
            // Reset button state
            const submitButton = form.querySelector('button[type="submit"]');
            submitButton.textContent = 'Start Scan';
            submitButton.disabled = false;
        }
    });

    // PDF Report button logic
    if (pdfBtn) {
        pdfBtn.addEventListener('click', async function () {
            const target = document.getElementById('target').value;
            const scanType = document.querySelector('input[name="scan_type"]:checked').value;
            const result = resultsContent.textContent;
            const findings = extractFindings(result);

            pdfBtn.textContent = "Generating PDF...";
            pdfBtn.disabled = true;

            const response = await fetch('/api/port-scan/pdf', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target, scan_type: scanType, findings, result })
            });

            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = "port_scan_report.pdf";
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(url);
            } else {
                alert("Failed to generate PDF report.");
            }

            pdfBtn.textContent = "PDF Report";
            pdfBtn.disabled = false;
        });
    }
}

// Extract open ports and summary from nmap output
function extractFindings(scanOutput) {
    if (!scanOutput) return '';
    const lines = scanOutput.split('\n');
    // Find the section with port info (nmap output)
    const portLines = lines.filter(line => line.match(/\bopen\b/));
    let summary = '';
    if (portLines.length > 0) {
        summary += 'Open Ports Found:\n';
        portLines.forEach(line => {
            summary += line + '\n';
        });
    } else {
        summary = 'No open ports found or scan output not parsed.';
    }
    return summary.trim();
} 