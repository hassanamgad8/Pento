from flask import Blueprint, render_template
from flask_login import login_required

pages_bp = Blueprint("pages", __name__)



@pages_bp.route("/attack_surface")
@login_required
def attack_surface():
    return render_template("attack_surface.html")

@pages_bp.route("/findings")
@login_required
def findings():
    return render_template("findings.html")

@pages_bp.route("/assets")
@login_required
def assets():
    return render_template("assets.html")

@pages_bp.route("/reports")
@login_required
def reports():
    return render_template("reports.html")


@pages_bp.route("/new_scan")
@login_required
def new_scan():
    recent_tools = [
        {"title": "Port Scanner", "desc": "Scan open ports", "url": "/port-scanner", "icon": "port.png"},
        {"title": "Website Scanner", "desc": "Run ZAP scan", "url": "/zap_scan", "icon": "zap.png"},
        {"title": "Whois Lookup", "desc": "Domain ownership info", "url": "/whois-lookup", "icon": "whois.png"},
        {"title": "DNS Lookup", "desc": "Check DNS records", "url": "/dns-lookup", "icon": "dns.png"},
    ]
    return render_template("new_scan.html", recent_tools=recent_tools)


@pages_bp.route("/scan_progress")
@login_required
def scan_progress():
    return render_template("scan_progress.html")

@pages_bp.route("/scan_results")
@login_required
def scan_results():
    return render_template("scan_results.html")


@pages_bp.route("/website_scanner")
@login_required
def website_scanner():
    return render_template("website_scanner.html")