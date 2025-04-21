from app import db
from datetime import datetime
from flask_login import UserMixin

class User(db.Model, UserMixin):  # <-- Notice UserMixin
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    password_hash = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
