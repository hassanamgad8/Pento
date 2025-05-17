from flask import Blueprint, render_template, redirect, url_for, jsonify
from flask_login import login_required, current_user
from app.models import Scan, RecentActivity

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
    active_scans = Scan.query.filter_by(status="running").all()
    recent_activities = RecentActivity.query.order_by(RecentActivity.timestamp.desc()).limit(10).all()
    return jsonify({
        "active_scans": [{"id": scan.id, "type": scan.type, "status": scan.status} for scan in active_scans],
        "recent_activities": [{"id": activity.id, "description": activity.description, "timestamp": activity.timestamp.isoformat()} for activity in recent_activities]
    })











