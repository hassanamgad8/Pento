from flask import Blueprint, render_template, request, jsonify, send_file
from flask_login import login_required
import paramiko
from fpdf import FPDF
import tempfile
import os
import re
from datetime import datetime

domain_finder_bp = Blueprint('domain_finder', __name__)

# SSH Configuration
KALI_HOST = "192.168.1.54"
KALI_PORT = 22
KALI_USERNAME = "kali"
KALI_PASSWORD = "kali"

def run_domain_tools(domain):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(KALI_HOST, KALI_PORT, KALI_USERNAME, KALI_PASSWORD)

        # Run whois
        stdin, stdout, stderr = ssh.exec_command(f"whois {domain}")
        whois_output = stdout.read().decode(errors='ignore')
        whois_error = stderr.read().decode(errors='ignore')

        # Run dnsrecon
        stdin, stdout, stderr = ssh.exec_command(f"dnsrecon -d {domain}")
        dnsrecon_output = stdout.read().decode(errors='ignore')
        dnsrecon_error = stderr.read().decode(errors='ignore')

        ssh.close()

        return {
            "whois": whois_output if whois_output else whois_error,
            "dnsrecon": dnsrecon_output if dnsrecon_output else dnsrecon_error
        }
    except Exception as e:
        return {"error": str(e)}

@domain_finder_bp.route('/domain-finder')
@login_required
def domain_finder():
    return render_template('domain_finder.html')

@domain_finder_bp.route('/api/domain-finder', methods=['POST'])
@login_required
def api_domain_finder():
    from app import db
    from app.models import Asset
    data = request.get_json()
    domain = data.get('domain')
    if not domain:
        return jsonify({"error": "Domain is required"}), 400
    result = run_domain_tools(domain)
    if "error" in result:
        return jsonify(result), 500

    # --- Robust domain extraction ---
    dnsrecon_output = result.get("dnsrecon", "")
    discovered_domains = set()
    domain_regex = re.compile(r'([a-zA-Z0-9_.-]+\.[a-zA-Z]{2,})')
    ip_regex = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    for line in dnsrecon_output.splitlines():
        matches = domain_regex.findall(line)
        for match in matches:
            # Ignore IP addresses and short tokens
            if not ip_regex.match(match) and len(match) > 3:
                discovered_domains.add(match.lower())
    print('Discovered domains:', discovered_domains)
    # Avoid duplicates in DB
    existing = {a.hostname for a in Asset.query.filter(Asset.hostname.in_(discovered_domains)).all()}
    for d in discovered_domains:
        if d not in existing:
            try:
                asset = Asset(hostname=d, asset_type='Domain', source='Domain Finder', last_seen=datetime.utcnow())
                db.session.add(asset)
                print(f'Added asset: {d}')
            except Exception as e:
                print(f'Error adding asset {d}:', e)
    try:
        db.session.commit()
    except Exception as e:
        print('DB commit error:', e)
    # --- End robust extraction ---

    return jsonify(result)

@domain_finder_bp.route('/api/domain-finder/pdf', methods=['POST'])
@login_required
def domain_finder_pdf():
    data = request.get_json()
    domain = data.get('domain', 'Unknown')
    whois = data.get('whois', '')
    dnsrecon = data.get('dnsrecon', '')

    class BlackBGFPDF(FPDF):
        def header(self):
            # Set black background for every page
            self.set_fill_color(0, 0, 0)
            self.rect(0, 0, 210, 297, 'F')
            # Logo and App Name
            if hasattr(self, 'logo_path') and os.path.exists(self.logo_path):
                self.image(self.logo_path, x=10, y=8, w=18)
            self.set_xy(30, 10)
            self.set_font("Courier", 'B', 16)
            self.set_text_color(0, 255, 0)
            self.cell(0, 10, "Pento", ln=1, align='L')
            self.set_y(25)

    pdf = BlackBGFPDF()
    pdf.logo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'static', 'images', 'hacker_logo.png'))
    pdf.add_page()

    # Title
    pdf.set_font("Courier", 'B', 18)
    pdf.set_text_color(0, 255, 0)
    pdf.cell(0, 12, "Domain Finder Report", ln=True, align='C')
    pdf.ln(6)

    # Domain
    pdf.set_font("Courier", 'B', 12)
    pdf.set_text_color(0, 255, 0)
    pdf.cell(35, 10, "Domain:", ln=0)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Courier", '', 12)
    pdf.cell(0, 10, f"{domain}", ln=1)
    pdf.ln(4)

    # General Information (Whois)
    pdf.set_font("Courier", 'B', 13)
    pdf.set_text_color(0, 255, 0)
    pdf.cell(0, 10, "General Information:", ln=1)
    pdf.set_font("Courier", '', 9)
    pdf.set_text_color(255, 255, 255)
    for line in whois.splitlines():
        pdf.cell(0, 6, line, ln=1)
    pdf.ln(2)

    # Domains (DNSRecon)
    pdf.set_font("Courier", 'B', 13)
    pdf.set_text_color(0, 255, 0)
    pdf.cell(0, 10, "Domains:", ln=1)
    pdf.set_font("Courier", '', 9)
    pdf.set_text_color(255, 255, 255)
    for line in dnsrecon.splitlines():
        pdf.cell(0, 6, line, ln=1)

    with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp:
        pdf.output(tmp.name)
        tmp_path = tmp.name

    return send_file(tmp_path, as_attachment=True, download_name="domain_finder_report.pdf") 