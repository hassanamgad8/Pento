import subprocess
import datetime
import shutil
import sys
from flask import Blueprint, render_template, request, jsonify

waf_bp = Blueprint('waf', __name__)

def check_wafw00f_installed():
    if not shutil.which("wafw00f"):
        return False
    return True

@waf_bp.route('/waf-detector')
def waf_detector_page():
    if not check_wafw00f_installed():
        return render_template('error.html', 
                             message="wafw00f is not installed. Please install it using: pip install wafw00f")
    return render_template('waf_detector.html')

@waf_bp.route('/api/waf-scan', methods=['POST'])
def scan_waf():
    if not check_wafw00f_installed():
        return jsonify({"error": "wafw00f is not installed"}), 500

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
        return jsonify({"output": result.stdout})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": e.stderr}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@waf_bp.route('/partials/tools/waf_detector')
def waf_detector_partial():
    return render_template('partials/tools/waf_detector.html')

if __name__ == "__main__":
    scan_waf_interactive()
