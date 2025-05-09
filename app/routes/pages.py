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
    return render_template("new_scan.html")




@pages_bp.route("/scan_progress")
@login_required
def scan_progress():
    return render_template("scan_progress.html")

@pages_bp.route("/scan_results")
@login_required
def scan_results():
    return render_template("scan_results.html")