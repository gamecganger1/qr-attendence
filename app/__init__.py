import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_app():
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config["SECRET_KEY"] = "qr_attendance_secret_2025"
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///attendance.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    # QR and security related defaults
    # If set, QR links will use this host (useful behind proxies or with HTTPS)
    app.config['QR_HOST'] = os.environ.get('QR_HOST')
    # Max allowed age (seconds) for a QR to be accepted by student_mark
    app.config['QR_MAX_AGE'] = int(os.environ.get('QR_MAX_AGE', '45'))
    # If True, require student IP to be on same /24 subnet as server (helps prevent remote proxying)
    app.config['REQUIRE_SAME_SUBNET'] = os.environ.get('REQUIRE_SAME_SUBNET', 'False').lower() in ('1','true','yes')

    db.init_app(app)

    # import and register blueprint
    from app.routes import main
    app.register_blueprint(main)

    # create folders
    with app.app_context():
        os.makedirs(os.path.join(app.root_path, "static", "qrcodes"), exist_ok=True)
        os.makedirs(os.path.join(app.root_path, "static", "reports"), exist_ok=True)

    return app