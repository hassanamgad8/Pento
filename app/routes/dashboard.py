from flask import Blueprint, render_template, redirect, url_for, jsonify
from flask_login import login_required, current_user
from app.models import Scan, RecentActivity, Finding, Asset

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html')

@dashboard_bp.route('/active-scans')
@login_required
def active_scans():
    active_scans = Scan.query.filter_by(status="running").all()
    recent_activities = RecentActivity.query.order_by(RecentActivity.timestamp.desc()).limit(10).all()
    return render_template('active_scans.html', active_scans=active_scans, recent_activities=recent_activities)

@dashboard_bp.route('/api/active-scans')
@login_required
def api_active_scans():
    # Get all scans grouped by status
    queued_scans = Scan.query.filter_by(status="queued").all()
    running_scans = Scan.query.filter_by(status="running").all()
    finished_scans = Scan.query.filter_by(status="finished").order_by(Scan.finished_at.desc()).limit(10).all()
    recent_activities = RecentActivity.query.order_by(RecentActivity.timestamp.desc()).limit(5).all()
    return jsonify({
        "queued_scans": [{"id": scan.id, "type": scan.type, "status": scan.status} for scan in queued_scans],
        "running_scans": [{"id": scan.id, "type": scan.type, "status": scan.status} for scan in running_scans],
        "finished_scans": [{"id": scan.id, "type": scan.type, "status": scan.status, "finished_at": scan.finished_at.isoformat() if scan.finished_at else None} for scan in finished_scans],
        "recent_activities": [
            {"id": activity.id, "description": activity.description, "timestamp": activity.timestamp.isoformat()} for activity in recent_activities
        ]
    })

@dashboard_bp.route('/api/risk_score')
@login_required
def api_risk_score():
    # Simple risk calculation: more high/medium findings, open ports, and technologies = higher risk
    high = Finding.query.filter_by(severity='High').count()
    med = Finding.query.filter_by(severity='Med').count()
    open_ports = Asset.query.filter(Asset.ports != None, Asset.ports != '').count()
    technologies = Asset.query.filter(Asset.technologies != None, Asset.technologies != '').count()
    # Risk score: weighted sum
    score = high * 5 + med * 2 + open_ports + technologies
    if score >= 20:
        desc = 'Critical risk: Immediate action required!'
        color = 'red'
    elif score >= 10:
        desc = 'High risk: Review findings soon.'
        color = 'orange'
    elif score >= 5:
        desc = 'Moderate risk: Monitor regularly.'
        color = 'yellow'
    else:
        desc = 'Low risk: All clear.'
        color = 'green'
    return jsonify({"score": score, "desc": desc, "color": color})











