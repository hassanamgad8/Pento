from flask import Flask, app
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from dotenv import load_dotenv
import os
from app.routes.chatbot import chatbot_bp
from app.routes.ai_scan import ai_scan_bp
from app.routes.pages import pages_bp
from app.routes.zap_scan import zap_bp
from app.routes.waf import waf_bp





db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
login_manager.login_view = 'auth.login'  # Ensure this line is set

def create_app():
    app = Flask(__name__)
    load_dotenv()

    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'replace_with_secure_key')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///pento.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['WTF_CSRF_SECRET_KEY'] = os.getenv('WTF_CSRF_SECRET_KEY', 'replace_with_secure_csrf_key')


    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)

    # Register blueprints
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.scans import scans_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(chatbot_bp)
    app.register_blueprint(ai_scan_bp)
    app.register_blueprint(pages_bp)
    app.register_blueprint(zap_bp)
    app.register_blueprint(waf_bp)
    






    from app.cli import create_user
    app.cli.add_command(create_user)



    # User loader function definition here:
    from app.models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    return app


