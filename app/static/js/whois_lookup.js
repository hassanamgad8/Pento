export function initWhoisLookup() {
    const form = document.getElementById('whois-lookup-form');
    const resultsDiv = document.getElementById('whois-results');
    const whoisOutput = document.getElementById('whois-output');
    const errorMessage = document.getElementById('whois-error-message');
    const pdfBtn = document.getElementById('pdf-whois-btn');

    if (!form) {
        console.error('Whois lookup form not found');
        return;
    }

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        resultsDiv.classList.add('hidden');
        errorMessage.classList.add('hidden');
        if (pdfBtn) pdfBtn.style.display = 'none';
        whoisOutput.textContent = '';

        const domain = document.getElementById('domain').value;
        const options = Array.from(document.querySelectorAll('.whois-option:checked')).map(cb => cb.value);
        try {
            const submitButton = form.querySelector('button[type="submit"]');
            submitButton.textContent = 'Looking up...';
            submitButton.disabled = true;

            const response = await fetch('/api/whois-lookup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain, options })
            });
            const data = await response.json();
            if (response.ok) {
                whoisOutput.textContent = data.whois;
                resultsDiv.classList.remove('hidden');
                if (pdfBtn) pdfBtn.style.display = '';
            } else {
                errorMessage.textContent = data.error || 'An error occurred during the lookup';
                errorMessage.classList.remove('hidden');
            }
        } catch (error) {
            errorMessage.textContent = 'Failed to connect to the server';
            errorMessage.classList.remove('hidden');
            console.error('Lookup error:', error);
        } finally {
            const submitButton = form.querySelector('button[type="submit"]');
            submitButton.textContent = 'Lookup';
            submitButton.disabled = false;
        }
    });

    if (pdfBtn) {
        pdfBtn.addEventListener('click', async function () {
            const domain = document.getElementById('domain').value;
            const options = Array.from(document.querySelectorAll('.whois-option:checked')).map(cb => cb.value);
            const whois = whoisOutput.textContent;

            pdfBtn.textContent = "Generating PDF...";
            pdfBtn.disabled = true;

            const response = await fetch('/api/whois-lookup/pdf', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain, options, whois })
            });

            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = "whois_lookup_report.pdf";
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