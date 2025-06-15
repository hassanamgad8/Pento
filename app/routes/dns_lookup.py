from flask import Blueprint, render_template, request, jsonify, send_file
from flask_login import login_required, current_user
import paramiko
from fpdf import FPDF
import tempfile
import os
from datetime import datetime

dns_lookup_bp = Blueprint('dns_lookup', __name__)

# SSH Configuration
KALI_HOST = "192.168.1.72"
KALI_PORT = 22
KALI_USERNAME = "kali"
KALI_PASSWORD = "kali"

DNS_OPTIONS = [
    {"flag": "+short", "name": "Short Output", "desc": "Show only the answer section."},
    {"flag": "+trace", "name": "Trace", "desc": "Trace the delegation path from the root name servers."},
    {"flag": "+dnssec", "name": "DNSSEC", "desc": "Request DNSSEC records."},
    {"flag": "+multiline", "name": "Multiline", "desc": "Print records in an expanded format."},
    {"flag": "+stats", "name": "Stats", "desc": "Print statistics at the end of the query."}
]

def run_dns_lookup(domain, options):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(KALI_HOST, KALI_PORT, KALI_USERNAME, KALI_PASSWORD)
        cmd = ["dig"]
        cmd.append(domain)
        for opt in options:
            if opt in [o["flag"] for o in DNS_OPTIONS]:
                cmd.append(opt)
        command = " ".join(cmd)
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode(errors='ignore')
        error = stderr.read().decode(errors='ignore')
        ssh.close()
        return output if output else error
    except Exception as e:
        return f"Error: {str(e)}"

@dns_lookup_bp.route('/dns-lookup')
@login_required
def dns_lookup():
    return render_template('dns_lookup.html', dns_options=DNS_OPTIONS)

@dns_lookup_bp.route('/api/dns-lookup', methods=['POST'])
@login_required
def api_dns_lookup():
    from app import db
    from app.models import Asset, Scan, RecentActivity
    data = request.get_json()
    domain = data.get('domain')
    options = data.get('options', [])
    if not domain:
        return jsonify({"error": "Domain is required"}), 400
    # Create Scan entry (status: running)
    scan = Scan(type='DNS Lookup', status='running', started_at=datetime.utcnow(), user_id=current_user.id)
    db.session.add(scan)
    db.session.commit()
    result = run_dns_lookup(domain, options)
    # Update Scan entry to finished
    scan.status = 'finished'
    scan.finished_at = datetime.utcnow()
    db.session.commit()
    # Log RecentActivity
    activity = RecentActivity(description=f"DNS lookup for {domain} completed", user_id=current_user.id, scan_id=scan.id)
    db.session.add(activity)
    db.session.commit()
    # --- Parse DNS output and insert Asset ---
    asset = Asset(
        hostname=domain,
        asset_type='DNS Record',
        source='DNS Lookup',
        last_seen=datetime.utcnow(),
        tags=",".join(options),
        risk='Low'
    )
    db.session.add(asset)
    db.session.commit()
    # --- End parse/insert ---
    if result.startswith("Error:"):
        return jsonify({"error": result}), 500
    return jsonify({"dig": result})

@dns_lookup_bp.route('/api/dns-lookup/pdf', methods=['POST'])
@login_required
def dns_lookup_pdf():
    data = request.get_json()
    domain = data.get('domain', 'Unknown')
    options = data.get('options', [])
    dig = data.get('dig', '')

    class BlackBGFPDF(FPDF):
        def header(self):
            self.set_fill_color(0, 0, 0)
            self.rect(0, 0, 210, 297, 'F')
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
    pdf.cell(0, 12, "DNS Lookup Report", ln=True, align='C')
    pdf.ln(6)

    # Domain
    pdf.set_font("Courier", 'B', 12)
    pdf.set_text_color(0, 255, 0)
    pdf.cell(35, 10, "Domain:", ln=0)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Courier", '', 12)
    pdf.cell(0, 10, f"{domain}", ln=1)
    pdf.ln(4)

    # Options
    pdf.set_font("Courier", 'B', 13)
    pdf.set_text_color(0, 255, 0)
    pdf.cell(0, 10, "Options:", ln=1)
    pdf.set_font("Courier", '', 11)
    pdf.set_text_color(255, 255, 255)
    for opt in options:
        pdf.cell(0, 8, f"- {opt}", ln=1)
    pdf.ln(2)

    # Dig Output
    pdf.set_font("Courier", 'B', 13)
    pdf.set_text_color(0, 255, 0)
    pdf.cell(0, 10, "Dig Output:", ln=1)
    pdf.set_font("Courier", '', 9)
    pdf.set_text_color(255, 255, 255)
    for line in dig.splitlines():
        pdf.cell(0, 6, line, ln=1)

    with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp:
        pdf.output(tmp.name)
        tmp_path = tmp.name

    return send_file(tmp_path, as_attachment=True, download_name="dns_lookup_report.pdf") 