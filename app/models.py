from flask_migrate import migrate
from app import db
from datetime import datetime
from flask_login import LoginManager, UserMixin
from werkzeug.security import generate_password_hash

class User(db.Model, UserMixin):  # <-- Notice UserMixin
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    password_hash = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(100))
    status = db.Column(db.String(50))
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    finished_at = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    findings = db.relationship('Finding', backref='scan', lazy=True)
    activities = db.relationship('RecentActivity', backref='scan', lazy=True)
    report = db.relationship('Report', backref='scan', uselist=False)
    attack_surfaces = db.relationship('AttackSurface', backref='scan', lazy=True)

class RecentActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'))

class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'))
    type = db.Column(db.String(100))
    description = db.Column(db.Text)
    severity = db.Column(db.String(50))
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255))
    ip = db.Column(db.String(45))
    ports = db.Column(db.String(255))  # Comma-separated or use a related table for normalization
    services = db.Column(db.String(255))
    technologies = db.Column(db.String(255))
    findings = db.relationship('Finding', backref='asset', lazy=True)
    asset_type = db.Column(db.String(50), default='Domain')
    risk = db.Column(db.String(10), default='Low')
    tags = db.Column(db.String(255), default='')
    source = db.Column(db.String(50), default='Unknown')
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

class AttackSurface(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'))
    endpoint = db.Column(db.String(255))
    param = db.Column(db.String(255))
    source = db.Column(db.String(100))

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'))
    summary = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
