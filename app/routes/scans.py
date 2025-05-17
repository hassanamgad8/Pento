from flask import Blueprint, render_template, jsonify
from flask_login import login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from app.models import Scan, Finding, Asset, RecentActivity
from app import db

scans_bp = Blueprint('scans', __name__)

@scans_bp.route('/scan')
def scan():
    return render_template('tools/port_scanner.html')

@scans_bp.route('/parse-scan-results', methods=['POST'])
@login_required
def parse_scan_results():
    # Simulate a scan result
    scan_id = 1  # Replace with actual scan ID from request
    finding = Finding(scan_id=scan_id, type="SQL Injection", description="Found SQL injection vulnerability", severity="High")
    asset = Asset(hostname="example.com", ip="192.168.1.1", ports="80,443", services="HTTP,HTTPS", technologies="Nginx,Python")
    activity = RecentActivity(description="Scan completed", user_id=current_user.id, scan_id=scan_id)
    
    db.session.add(finding)
    db.session.add(asset)
    db.session.add(activity)
    db.session.commit()
    
    return jsonify({"message": "Scan results parsed and inserted successfully"})
