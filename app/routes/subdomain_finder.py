from flask import Blueprint, render_template, request, jsonify, send_file
from flask_login import login_required, current_user
import paramiko
from fpdf import FPDF
import tempfile
import os
from datetime import datetime
import re

subdomain_finder_bp = Blueprint('subdomain_finder', __name__)

# SSH Configuration
KALI_HOST = "192.168.1.72"
KALI_PORT = 22
KALI_USERNAME = "kali"
KALI_PASSWORD = "kali"

def run_amass(domain):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(KALI_HOST, KALI_PORT, KALI_USERNAME, KALI_PASSWORD)
        # Run amass
        stdin, stdout, stderr = ssh.exec_command(f"amass enum -passive -d {domain}")
        amass_output = stdout.read().decode(errors='ignore')
        amass_error = stderr.read().decode(errors='ignore')
        ssh.close()
        return amass_output if amass_output else amass_error
    except Exception as e:
        return f"Error: {str(e)}"

@subdomain_finder_bp.route('/subdomain-finder')
@login_required
def subdomain_finder():
    return render_template('subdomain_finder.html')

@subdomain_finder_bp.route('/api/subdomain-finder', methods=['POST'])
@login_required
def api_subdomain_finder():
    from app import db
    from app.models import Asset, Scan, RecentActivity
    data = request.get_json()
    domain = data.get('domain')
    if not domain:
        return jsonify({"error": "Domain is required"}), 400
    # Create Scan entry (status: running)
    scan = Scan(type='Subdomain Finder', status='running', started_at=datetime.utcnow(), user_id=current_user.id)
    db.session.add(scan)
    db.session.commit()
    result = run_amass(domain)
    if result.startswith("Error:"):
        scan.status = 'finished'
        scan.finished_at = datetime.utcnow()
        db.session.commit()
        return jsonify({"error": result}), 500
    # --- Parse amass output and insert Assets ---
    discovered_subdomains = set()
    domain_regex = re.compile(r'([a-zA-Z0-9_.-]+\.[a-zA-Z]{2,})')
    for line in result.splitlines():
        matches = domain_regex.findall(line)
        for match in matches:
            discovered_subdomains.add(match.lower())
    existing = {a.hostname for a in Asset.query.filter(Asset.hostname.in_(discovered_subdomains)).all()}
    for d in discovered_subdomains:
        if d not in existing:
            try:
                asset = Asset(hostname=d, asset_type='Subdomain', source='Subdomain Finder', last_seen=datetime.utcnow())
                db.session.add(asset)
            except Exception as e:
                pass
    # Update Scan entry to finished
    scan.status = 'finished'
    scan.finished_at = datetime.utcnow()
    db.session.commit()
    # Log RecentActivity
    activity = RecentActivity(description=f"Subdomain scan on {domain} completed", user_id=current_user.id, scan_id=scan.id)
    db.session.add(activity)
    db.session.commit()
    # --- End parse/insert ---
    return jsonify({"amass": result})

@subdomain_finder_bp.route('/api/subdomain-finder/pdf', methods=['POST'])
@login_required
def subdomain_finder_pdf():
    data = request.get_json()
    domain = data.get('domain', 'Unknown')
    amass = data.get('amass', '')

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
    pdf.cell(0, 12, "Subdomain Finder Report", ln=True, align='C')
    pdf.ln(6)

    # Domain
    pdf.set_font("Courier", 'B', 12)
    pdf.set_text_color(0, 255, 0)
    pdf.cell(35, 10, "Domain:", ln=0)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Courier", '', 12)
    pdf.cell(0, 10, f"{domain}", ln=1)
    pdf.ln(4)

    # Subdomains Section
    pdf.set_font("Courier", 'B', 13)
    pdf.set_text_color(0, 255, 0)
    pdf.cell(0, 10, "Subdomains:", ln=1)
    pdf.set_font("Courier", '', 9)
    pdf.set_text_color(255, 255, 255)
    for line in amass.splitlines():
        pdf.cell(0, 6, line, ln=1)

    with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp:
        pdf.output(tmp.name)
        tmp_path = tmp.name

    return send_file(tmp_path, as_attachment=True, download_name="subdomain_finder_report.pdf") 