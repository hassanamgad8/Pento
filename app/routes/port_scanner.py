from flask import Blueprint, render_template, request, jsonify, send_file
from flask_login import login_required, current_user
import paramiko
import json
from fpdf import FPDF
import tempfile
import os
from datetime import datetime

port_scanner_bp = Blueprint('port_scanner', __name__)

# SSH Configuration
KALI_HOST = "192.168.1.72"
KALI_PORT = 22
KALI_USERNAME = "kali"
KALI_PASSWORD = "kali"

def run_nmap_scan(target, scan_type="quick", verbose=False, timing=False):
    try:
        # Create SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect to Kali Linux
        ssh.connect(KALI_HOST, KALI_PORT, KALI_USERNAME, KALI_PASSWORD)
        
        # Build the nmap command based on options
        command_parts = ["nmap"]
        
        # Add timing template if selected
        if timing:
            command_parts.append("-T4")
            
        # Add verbose flag if selected
        if verbose:
            command_parts.append("-v")
            
        # Add scan type specific options
        if scan_type == "quick":
            command_parts.extend(["-F", target])
        elif scan_type == "detailed":
            command_parts.extend(["-sV", "-sC", target])
        elif scan_type == "aggressive":
            command_parts.extend(["-A", target])
        elif scan_type == "stealth":
            command_parts.extend(["-sS", "-f", target])
        else:
            command_parts.append(target)
            
        # Join command parts and execute
        command = " ".join(command_parts)
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()
        
        # Close SSH connection
        ssh.close()
        
        if error:
            return {"error": error}
        return {"output": output}
        
    except Exception as e:
        return {"error": str(e)}

@port_scanner_bp.route('/port-scanner')
@login_required
def port_scanner():
    return render_template('port_scanner.html')

@port_scanner_bp.route('/api/port-scan', methods=['POST'])
@login_required
def api_port_scan():
    from app import db
    from app.models import Asset, Scan, RecentActivity
    data = request.get_json()
    target = data.get('target')
    scan_type = data.get('scan_type', 'quick')
    verbose = data.get('verbose', False)
    timing = data.get('timing', False)
    if not target:
        return jsonify({"error": "Target is required"}), 400
    # Create Scan entry (status: running)
    scan = Scan(type='Port Scanner', status='running', started_at=datetime.utcnow(), user_id=current_user.id)
    db.session.add(scan)
    db.session.commit()
    result = run_nmap_scan(target, scan_type, verbose, timing)
    if "error" in result:
        scan.status = 'finished'
        scan.finished_at = datetime.utcnow()
        db.session.commit()
        return jsonify(result), 500
    # --- Parse Nmap output and insert Asset ---
    output = result.get("output", "")
    hostname = target
    ip = ""
    ports = []
    services = []
    technologies = []
    for line in output.splitlines():
        if line.startswith("Nmap scan report for"):
            parts = line.split()
            if len(parts) >= 5:
                ip = parts[-1]
        elif "/tcp" in line or "/udp" in line:
            parts = line.split()
            if len(parts) >= 3:
                port_proto = parts[0]
                port = port_proto.split("/")[0]
                ports.append(port)
                services.append(parts[2])
    asset = Asset(
        hostname=hostname,
        ip=ip,
        ports=",".join(ports),
        services=",".join(services),
        technologies="",
        asset_type='IP Address',
        source='Port Scanner',
        last_seen=datetime.utcnow()
    )
    db.session.add(asset)
    # Update Scan entry to finished
    scan.status = 'finished'
    scan.finished_at = datetime.utcnow()
    db.session.commit()
    # Log RecentActivity
    activity = RecentActivity(description=f"Port scan on {target} completed", user_id=current_user.id, scan_id=scan.id)
    db.session.add(activity)
    db.session.commit()
    # --- End parse/insert ---
    return jsonify(result)

@port_scanner_bp.route('/api/port-scan/pdf', methods=['POST'])
@login_required
def port_scan_pdf():
    data = request.get_json()
    target = data.get('target', 'Unknown')
    scan_type = data.get('scan_type', 'Unknown')
    findings = data.get('findings', '')
    result = data.get('result', '')

    pdf = FPDF()
    pdf.add_page()

    # Set black background
    pdf.set_fill_color(0, 0, 0)
    pdf.rect(0, 0, 210, 297, 'F')  # A4 size in mm

    # Logo and App Name
    logo_path = os.path.join(os.path.dirname(__file__), '..', 'static', 'images', 'hacker_logo.png')
    logo_path = os.path.abspath(logo_path)
    if os.path.exists(logo_path):
        pdf.image(logo_path, x=10, y=8, w=18)
    pdf.set_xy(30, 10)
    pdf.set_font("Courier", 'B', 16)
    pdf.set_text_color(0, 255, 0)
    pdf.cell(0, 10, "Pento", ln=1, align='L')

    # Title
    pdf.set_xy(0, 25)
    pdf.set_font("Courier", 'B', 18)
    pdf.set_text_color(0, 255, 0)
    pdf.cell(0, 12, "Port Scan Report", ln=True, align='C')
    pdf.ln(6)

    # Target and Scan Type
    pdf.set_font("Courier", 'B', 12)
    pdf.set_text_color(0, 255, 0)
    pdf.cell(35, 10, "Target:", ln=0)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Courier", '', 12)
    pdf.cell(0, 10, f"{target}", ln=1)
    pdf.set_font("Courier", 'B', 12)
    pdf.set_text_color(0, 255, 0)
    pdf.cell(35, 10, "Scan Type:", ln=0)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Courier", '', 12)
    pdf.cell(0, 10, f"{scan_type}", ln=1)
    pdf.ln(4)

    # Findings Table
    pdf.set_font("Courier", 'B', 13)
    pdf.set_text_color(0, 255, 0)
    pdf.cell(0, 10, "Findings:", ln=1)
    pdf.set_font("Courier", '', 11)
    pdf.set_text_color(255, 255, 255)

    # Try to parse findings as a table (port, state, service)
    table_rows = []
    for line in findings.splitlines():
        # Try to match nmap table lines like: 80/tcp  open  http
        parts = line.split()
        if len(parts) >= 3 and '/' in parts[0]:
            table_rows.append(parts[:3])
    if table_rows:
        # Table header
        pdf.set_fill_color(0, 255, 0)
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Courier", 'B', 11)
        pdf.cell(40, 8, "Port", border=1, align='C', fill=True)
        pdf.cell(30, 8, "State", border=1, align='C', fill=True)
        pdf.cell(50, 8, "Service", border=1, align='C', fill=True)
        pdf.ln()
        pdf.set_font("Courier", '', 11)
        pdf.set_text_color(255, 255, 255)
        for row in table_rows:
            pdf.cell(40, 8, row[0], border=1, align='C')
            pdf.cell(30, 8, row[1], border=1, align='C')
            pdf.cell(50, 8, row[2], border=1, align='C')
            pdf.ln()
    else:
        # Fallback: print findings as text
        pdf.set_text_color(255, 255, 255)
        for line in findings.splitlines():
            pdf.cell(0, 8, line, ln=1)
    pdf.ln(2)

    # Scan Output
    pdf.set_text_color(0, 255, 0)
    pdf.set_font("Courier", 'B', 13)
    pdf.cell(0, 10, "Scan Output:", ln=1)
    pdf.set_font("Courier", '', 10)
    pdf.set_text_color(255, 255, 255)
    if result:
        for line in result.splitlines():
            pdf.cell(0, 7, line, ln=1)
    else:
        pdf.cell(0, 7, "No scan output.", ln=1)

    with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp:
        pdf.output(tmp.name)
        tmp_path = tmp.name

    return send_file(tmp_path, as_attachment=True, download_name="port_scan_report.pdf") 