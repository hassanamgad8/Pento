from flask import Blueprint, render_template
from flask_login import login_required

google_hacking_bp = Blueprint("google_hacking", __name__)

@google_hacking_bp.route("/google-hacking")
@login_required
def google_hacking():
    return render_template("google_hacking.html") 