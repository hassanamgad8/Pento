from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required, current_user
import subprocess
import datetime
import shutil
import sys
import os
from datetime import datetime

waf_bp = Blueprint("waf", __name__)

@waf_bp.route("/waf-detector")
@login_required
def waf_detector():
    return render_template("tools/waf_detector.html")

def check_wafw00f_installed():
    if not shutil.which("wafw00f"):
        return False
    return True

@waf_bp.route("/api/waf-scan", methods=['POST'])
@login_required
def waf_scan():
    from app import db
    from app.models import Asset, Scan, RecentActivity
    if not check_wafw00f_installed():
        return jsonify({"error": "wafw00f not found. Install it using: pip install wafw00f"}), 400

    data = request.get_json()
    target = data.get('target')
    aggressive = data.get('aggressive', False)
    findall = data.get('findall', False)
    verbose = data.get('verbose', False)

    if not target:
        return jsonify({"error": "Target URL is required"}), 400

    # Create Scan entry (status: running)
    scan = Scan(type='WAF Detector', status='running', started_at=datetime.utcnow(), user_id=current_user.id)
    db.session.add(scan)
    db.session.commit()

    cmd = ["wafw00f"]
    if findall:
        cmd.append("--findall")
    if aggressive:
        cmd.append("-a")
    if verbose:
        cmd.append("-v")
    cmd.append(target)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        # Save the output to a file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"waf_output_{timestamp}.txt"
        output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static', 'reports')
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, filename)
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(result.stdout)

        # --- Parse wafw00f output and insert Asset ---
        waf_output = result.stdout
        waf_name = None
        for line in waf_output.splitlines():
            if "is behind" in line:
                waf_name = line.split("is behind")[-1].strip()
                break
        if not waf_name:
            waf_name = "Unknown WAF"
        asset = Asset(
            hostname=target,
            asset_type='WAF',
            source='WAF Detector',
            last_seen=datetime.utcnow(),
            tags=waf_name,
            risk='Med'
        )
        db.session.add(asset)
        # Update Scan entry to finished
        scan.status = 'finished'
        scan.finished_at = datetime.utcnow()
        db.session.commit()
        # Log RecentActivity
        activity = RecentActivity(description=f"WAF scan on {target} completed", user_id=current_user.id, scan_id=scan.id)
        db.session.add(activity)
        db.session.commit()
        # --- End parse/insert ---

        return jsonify({
            "output": result.stdout,
            "report_path": f"/static/reports/{filename}"
        })

    except subprocess.CalledProcessError as e:
        scan.status = 'finished'
        scan.finished_at = datetime.utcnow()
        db.session.commit()
        return jsonify({"error": f"wafw00f error: {e.stderr}"}), 500
    except Exception as e:
        scan.status = 'finished'
        scan.finished_at = datetime.utcnow()
        db.session.commit()
        return jsonify({"error": str(e)}), 500 