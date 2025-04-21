from flask import Blueprint, render_template

scans_bp = Blueprint('scans', __name__)

@scans_bp.route('/scan')
def scan():
    return render_template('tools/port_scanner.html')
