export function initSubdomainFinder() {
    const form = document.getElementById('subdomain-finder-form');
    const resultsDiv = document.getElementById('subdomain-results');
    const amassOutput = document.getElementById('amass-output');
    const errorMessage = document.getElementById('subdomain-error-message');
    const pdfBtn = document.getElementById('pdf-subdomain-btn');

    if (!form) {
        console.error('Subdomain finder form not found');
        return;
    }

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        resultsDiv.classList.add('hidden');
        errorMessage.classList.add('hidden');
        if (pdfBtn) pdfBtn.style.display = 'none';
        amassOutput.textContent = '';

        const domain = document.getElementById('domain').value;
        try {
            const submitButton = form.querySelector('button[type="submit"]');
            submitButton.textContent = 'Scanning...';
            submitButton.disabled = true;

            const response = await fetch('/api/subdomain-finder', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain })
            });
            const data = await response.json();
            if (response.ok) {
                amassOutput.textContent = data.amass;
                resultsDiv.classList.remove('hidden');
                if (pdfBtn) pdfBtn.style.display = '';
            } else {
                errorMessage.textContent = data.error || 'An error occurred during the scan';
                errorMessage.classList.remove('hidden');
            }
        } catch (error) {
            errorMessage.textContent = 'Failed to connect to the server';
            errorMessage.classList.remove('hidden');
            console.error('Scan error:', error);
        } finally {
            const submitButton = form.querySelector('button[type="submit"]');
            submitButton.textContent = 'Start Scan';
            submitButton.disabled = false;
        }
    });

    if (pdfBtn) {
        pdfBtn.addEventListener('click', async function () {
            const domain = document.getElementById('domain').value;
            const amass = amassOutput.textContent;

            pdfBtn.textContent = "Generating PDF...";
            pdfBtn.disabled = true;

            const response = await fetch('/api/subdomain-finder/pdf', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain, amass })
            });

            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = "subdomain_finder_report.pdf";
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