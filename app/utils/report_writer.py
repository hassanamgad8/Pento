import pdfkit
from datetime import datetime
import os

def generate_html_report(results, url, output_path="reports/"):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"ai_report_{timestamp}.html"
    full_path = os.path.join(output_path, filename)

    os.makedirs(output_path, exist_ok=True)

    with open(full_path, "w", encoding="utf-8") as f:
        f.write(f"<h1>AI Vulnerability Scan Report</h1>")
        f.write(f"<p><strong>Target:</strong> {url}</p>")
        f.write(f"<p><strong>Generated:</strong> {timestamp}</p>")
        f.write("<hr>")

        for result in results:
            f.write(f"<h2>Form: {result['form_url']}</h2>")
            f.write(f"<p>Method: {result['method']}</p>")
            f.write(f"<p>Inputs: {', '.join(result['inputs'])}</p>")
            f.write(f"<details><summary><strong>AI Output</strong></summary>")
            f.write(f"<pre>{result['ai_output']}</pre></details>")

            for test in result["tests"]:
                f.write("<hr>")
                f.write(f"<h3>{test.get('type', 'Unknown')} Test</h3>")
                f.write("<pre>")
                f.write(f"Input Tested: {test.get('input', '-')}\n")
                f.write(f"Payload: {test.get('payload', '-')}\n")
                f.write(f"Result: {test.get('result', '-')}\n")
                f.write(f"Status Code: {test.get('status_code', '-')}")
                f.write("</pre>")

    return full_path





def generate_pdf(html_path, pdf_path):
    pdfkit.from_file(html_path, pdf_path)