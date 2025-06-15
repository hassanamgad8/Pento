from flask import Blueprint, render_template, request, jsonify, send_file
from flask_login import login_required, current_user
import paramiko
from fpdf import FPDF
import tempfile
import os
from datetime import datetime


whois_lookup_bp = Blueprint('whois_lookup', __name__)

# SSH Configuration
KALI_HOST = "192.168.1.72"
KALI_PORT = 22
KALI_USERNAME = "kali"
KALI_PASSWORD = "kali"

WHOIS_OPTIONS = [
    {"flag": "-H", "name": "No Header", "desc": "Suppress legal disclaimers and headers."},
    {"flag": "-B", "name": "No Banner", "desc": "Suppress the initial whois banner."},
    {"flag": "-a", "name": "All Info", "desc": "Display detailed information (if available)."},
    {"flag": "-c", "name": "Country", "desc": "Show country-specific information."},
    {"flag": "-Q", "name": "Quick", "desc": "Quick lookup, minimal output."}
]

def run_whois(domain, options):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(KALI_HOST, KALI_PORT, KALI_USERNAME, KALI_PASSWORD)
        cmd = ["whois"]
        for opt in options:
            if opt in [o["flag"] for o in WHOIS_OPTIONS]:
                cmd.append(opt)
        cmd.append(domain)
        command = " ".join(cmd)
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode(errors='ignore')
        error = stderr.read().decode(errors='ignore')
        ssh.close()
        return output if output else error
    except Exception as e:
        return f"Error: {str(e)}"

@whois_lookup_bp.route('/whois-lookup')
@login_required
def whois_lookup():
    return render_template('whois_lookup.html', whois_options=WHOIS_OPTIONS)

@whois_lookup_bp.route('/api/whois-lookup', methods=['POST'])
@login_required
def api_whois_lookup():
    from app import db
    from app.models import Asset, Scan, RecentActivity
    data = request.get_json()
    domain = data.get('domain')
    options = data.get('options', [])
    if not domain:
        return jsonify({"error": "Domain is required"}), 400
    # Create Scan entry (status: running)
    scan = Scan(type='WHOIS Lookup', status='running', started_at=datetime.utcnow(), user_id=current_user.id)
    db.session.add(scan)
    db.session.commit()
    result = run_whois(domain, options)
    # Update Scan entry to finished
    scan.status = 'finished'
    scan.finished_at = datetime.utcnow()
    db.session.commit()
    # Log RecentActivity
    activity = RecentActivity(description=f"WHOIS lookup for {domain} completed", user_id=current_user.id, scan_id=scan.id)
    db.session.add(activity)
    db.session.commit()
    # --- Parse WHOIS output and insert Asset ---
    asset = Asset(
        hostname=domain,
        asset_type='Domain Registration',
        source='WHOIS Lookup',
        last_seen=datetime.utcnow(),
        tags=",".join(options),
        risk='Low'
    )
    db.session.add(asset)
    db.session.commit()
    # --- End parse/insert ---
    if result.startswith("Error:"):
        return jsonify({"error": result}), 500
    return jsonify({"whois": result})

@whois_lookup_bp.route('/api/whois-lookup/pdf', methods=['POST'])
@login_required
def whois_lookup_pdf():
    data = request.get_json()
    domain = data.get('domain', 'Unknown')
    options = data.get('options', [])
    whois = data.get('whois', '')

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
    pdf.cell(0, 12, "Whois Lookup Report", ln=True, align='C')
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

    # Whois Output
    pdf.set_font("Courier", 'B', 13)
    pdf.set_text_color(0, 255, 0)
    pdf.cell(0, 10, "Whois Output:", ln=1)
    pdf.set_font("Courier", '', 9)
    pdf.set_text_color(255, 255, 255)
    for line in whois.splitlines():
        pdf.cell(0, 6, line, ln=1)

    with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp:
        pdf.output(tmp.name)
        tmp_path = tmp.name

    return send_file(tmp_path, as_attachment=True, download_name="whois_lookup_report.pdf") 