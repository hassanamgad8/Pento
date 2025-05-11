from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required
import subprocess
import datetime
import shutil
import sys
import os

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
    if not check_wafw00f_installed():
        return jsonify({"error": "wafw00f not found. Install it using: pip install wafw00f"}), 400

    data = request.get_json()
    target = data.get('target')
    aggressive = data.get('aggressive', False)
    findall = data.get('findall', False)
    verbose = data.get('verbose', False)

    if not target:
        return jsonify({"error": "Target URL is required"}), 400

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
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"waf_output_{timestamp}.txt"
        output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static', 'reports')
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, filename)
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(result.stdout)

        return jsonify({
            "output": result.stdout,
            "report_path": f"/static/reports/{filename}"
        })

    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"wafw00f error: {e.stderr}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500 