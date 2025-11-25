from app import create_app, db
from app.models import Admin, Teacher, Student, Attendance, QRCode
import os

app = create_app()

# Ensure folders exist
with app.app_context():
    os.makedirs(os.path.join(app.root_path, "static", "qrcodes"), exist_ok=True)
    os.makedirs(os.path.join(app.root_path, "static", "reports"), exist_ok=True)
    db.create_all()

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)