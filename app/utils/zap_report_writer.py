import os
from datetime import datetime
from weasyprint import HTML

def save_html_report(alerts, target_url, output_dir="app/static/reports"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"zap_report_{timestamp}.html"
    filepath = os.path.join(output_dir, filename)

    html = f"""
    <html>
    <head><style>
    body {{ background: #111; color: #eee; font-family: monospace; padding: 2rem; }}
    h1 {{ color: #0f0; }}
    .alert {{ border-bottom: 1px solid #444; margin-bottom: 1rem; padding-bottom: 1rem; }}
    </style></head>
    <body>
    <h1>OWASP ZAP Scan Report</h1>
    <p><strong>Target:</strong> {target_url}</p>
    <p><strong>Total Alerts:</strong> {len(alerts)}</p>
    <hr>
    """

    for a in alerts:
        html += f"""
        <div class='alert'>
            <h3>[{a['risk']}] {a['alert']}</h3>
            <p><strong>Confidence:</strong> {a['confidence']}</p>
            <p><strong>URL:</strong> {a['url']}</p>
            <p><strong>Parameter:</strong> {a.get('param', '-')}</p>
            <p><strong>Evidence:</strong> {a.get('evidence', '-')}</p>
        </div>
        """

    html += "</body></html>"
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    return filepath  # Return full path to HTML



def save_pdf_report_from_html(html_path):
    pdf_path = html_path.replace(".html", ".pdf")
    HTML(html_path).write_pdf(pdf_path)
    return pdf_path