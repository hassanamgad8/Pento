export function initDnsLookup() {
    const form = document.getElementById('dns-lookup-form');
    const resultsDiv = document.getElementById('dns-results');
    const digOutput = document.getElementById('dig-output');
    const errorMessage = document.getElementById('dns-error-message');
    const pdfBtn = document.getElementById('pdf-dns-btn');

    if (!form) {
        console.error('DNS lookup form not found');
        return;
    }

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        resultsDiv.classList.add('hidden');
        errorMessage.classList.add('hidden');
        if (pdfBtn) pdfBtn.style.display = 'none';
        digOutput.textContent = '';

        const domain = document.getElementById('domain').value;
        const options = Array.from(document.querySelectorAll('.dns-option:checked')).map(cb => cb.value);
        try {
            const submitButton = form.querySelector('button[type="submit"]');
            submitButton.textContent = 'Looking up...';
            submitButton.disabled = true;

            const response = await fetch('/api/dns-lookup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain, options })
            });
            const data = await response.json();
            if (response.ok) {
                digOutput.textContent = data.dig;
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
            const options = Array.from(document.querySelectorAll('.dns-option:checked')).map(cb => cb.value);
            const dig = digOutput.textContent;

            pdfBtn.textContent = "Generating PDF...";
            pdfBtn.disabled = true;

            const response = await fetch('/api/dns-lookup/pdf', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain, options, dig })
            });

            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = "dns_lookup_report.pdf";
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