import io
import os
import time
import hmac
import hashlib
import qrcode
import csv
import socket
from datetime import datetime, timedelta
from io import BytesIO
from flask import (Blueprint, render_template, request, redirect, url_for,
                   flash, session, current_app, send_file, jsonify, make_response)
import secrets
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from app.models import Admin, Teacher, Student, QRCode, Attendance
from urllib.parse import urlparse, parse_qs

main = Blueprint("main", __name__)

# CONFIG
QR_SLOT_SECONDS = 1800   # 30 minutes
HMAC_KEY = "very_secret_qr_key_2025"

# Previously a hard-coded SERVER_IP caused stale IPs to be embedded in QR codes.
# Prefer an explicit config override `QR_HOST` (app.config or env var). If not set,
# detect the current LAN IP dynamically so QR codes point to the machine currently
# running the app.
SERVER_IP = None

def detect_lan_ip():
    """Try to determine the machine's LAN IP by opening a UDP socket to the internet.
    This doesn't send data but yields the local IP used for outbound traffic.
    Falls back to 127.0.0.1 on error.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        try:
            s.close()
        except Exception:
            pass
    return ip

def get_qr_base_url():
    # priority: app.config['QR_HOST'] -> env QR_HOST -> detect_lan_ip()
    host_override = None
    try:
        host_override = current_app.config.get('QR_HOST')
    except Exception:
        host_override = None
    if not host_override:
        host_override = os.environ.get('QR_HOST')

    if host_override:
        ip = host_override
    else:
        ip = detect_lan_ip()

    # If request.host provides a port, use it; otherwise default to 5000
    try:
        port = request.host.split(':')[-1]
    except Exception:
        port = '5000'

    # Build http URL for local network; if you use HTTPS in production, override QR_HOST
    return f"http://{ip}:{port}"

def timeslot(ts=None):
    if ts is None:
        ts = int(time.time())
    return ts // QR_SLOT_SECONDS

def make_token(teacher_id, slot):
    msg = f"{teacher_id}:{slot}".encode()
    key = HMAC_KEY.encode()
    token = hmac.new(key, msg, hashlib.sha256).hexdigest()
    return token

def create_and_save_qr_image(url, teacher_id, token):
    fn = f"qr_t{teacher_id}_{token[:12]}.png"
    fn = secure_filename(fn)
    path = os.path.join(current_app.root_path, "static", "qrcodes", fn)
    img = qrcode.make(url)
    img.save(path)
    return fn

@main.before_app_request
def ensure_default_admin():
    try:
        if not Admin.query.first():
            a = Admin(username="admin", password_hash=generate_password_hash("admin123"))
            db.session.add(a)
            db.session.commit()
    except Exception:
        pass

@main.route("/")
def index():
    return render_template("index.html")

# ----------------- ADMIN -----------------
@main.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password_hash, password):
            session.clear()
            session["role"] = "admin"
            flash("Admin logged in", "success")
            return redirect(url_for("main.admin_dashboard"))
        flash("Invalid admin credentials", "danger")
    return render_template("adminlogin.html")

@main.route("/admin/dashboard")
def admin_dashboard():
    if session.get("role") != "admin":
        return redirect(url_for("main.admin_login"))
    teachers = Teacher.query.order_by(Teacher.created_at.desc()).all()
    return render_template("admindashboard.html", teachers=teachers)

@main.route("/admin/add_teacher", methods=["POST"])
def admin_add_teacher():
    if session.get("role") != "admin":
        return redirect(url_for("main.admin_login"))
    name = request.form["name"]
    email = request.form["email"]
    password = request.form["password"]
    if Teacher.query.filter_by(email=email).first():
        flash("Email already exists", "danger")
        return redirect(url_for("main.admin_dashboard"))
    t = Teacher(name=name, email=email, password_hash=generate_password_hash(password))
    db.session.add(t)
    db.session.commit()
    flash("Teacher added successfully", "success")
    return redirect(url_for("main.admin_dashboard"))

@main.route("/admin/remove_teacher/<int:tid>", methods=["POST", "GET"])
def admin_remove_teacher(tid):
    if session.get("role") != "admin":
        return redirect(url_for("main.admin_login"))
    t = Teacher.query.get_or_404(tid)
    db.session.delete(t)
    db.session.commit()
    flash("Teacher removed", "info")
    return redirect(url_for("main.admin_dashboard"))

@main.route("/admin/report")
def admin_report():
    if session.get("role") != "admin":
        return redirect(url_for("main.admin_login"))
    records = Attendance.query.order_by(Attendance.marked_at.desc()).all()
    # Convert UTC times to Indian time (UTC+5:30)
    for r in records:
        if r.marked_at:
            ist_time = r.marked_at + timedelta(hours=5, minutes=30)
            r.display_time = ist_time.strftime("%d-%m-%Y %I:%M:%S %p")
    return render_template("attendancereport.html", records=records)

import io

@main.route("/admin/report/download")
def admin_report_download():
    if session.get("role") != "admin":
        return redirect(url_for("main.admin_login"))

    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(["ID", "Student Name", "Roll No", "Teacher Name", "Time"])

    for r in Attendance.query.order_by(Attendance.marked_at.desc()).all():
        writer.writerow([
            r.id,
            r.student_name,
            r.roll_no,
            r.teacher_name,
            (r.marked_at + timedelta(hours=5, minutes=30)).strftime("%d-%m-%Y %I:%M:%S %p")
        ])

    si.seek(0)
    mem = io.BytesIO(si.getvalue().encode("utf-8"))
    return send_file(mem, as_attachment=True, download_name="attendance_report.csv", mimetype="text/csv")

# ----------------- TEACHER -----------------
@main.route("/teacher/login", methods=["GET", "POST"])
def teacher_login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        t = Teacher.query.filter_by(email=email).first()
        if t and check_password_hash(t.password_hash, password):
            session.clear()
            session["role"] = "teacher"
            session["teacher_id"] = t.id
            session["teacher_name"] = t.name
            return redirect(url_for("main.teacher_dashboard"))
        flash("Invalid credentials", "danger")
    return render_template("teacherlogin.html")

@main.route("/teacher/dashboard", methods=["GET", "POST"])
def teacher_dashboard():
    if session.get("role") != "teacher":
        return redirect(url_for("main.teacher_login"))

    teacher_id = session["teacher_id"]
    teacher_name = session["teacher_name"]

    now = int(time.time())
    current_slot = timeslot(now)
    token = make_token(teacher_id, current_slot)

    # Build an external URL reachable from phones on the local network. Use
    # get_qr_base_url() which prefers app.config['QR_HOST'] or env QR_HOST,
    # otherwise detects the current LAN IP dynamically.
    base = get_qr_base_url()
    url = f"{base}{url_for('main.student_mark')}?token={token}&teacher_id={teacher_id}"
    filename = create_and_save_qr_image(url, teacher_id, token)

    qr = QRCode(teacher_id=teacher_id, teacher_name=teacher_name, token=token, filename=filename)
    db.session.add(qr)
    db.session.commit()

    expires_in = 45
    return render_template("teacherdashboard.html",
                           teacher_name=teacher_name,
                           qr_filename=filename,
                           expires_in=expires_in)

@main.route("/teacher/refresh_qr", methods=["GET"])
def teacher_refresh_qr():
    if session.get("role") != "teacher":
        return jsonify({"status": "error", "message": "Not logged in as teacher"}), 403

    teacher_id = session["teacher_id"]
    teacher_name = session["teacher_name"]

    now = int(time.time())
    current_slot = timeslot(now)
    token = make_token(teacher_id, current_slot)

    # Build refresh QR URL using the detected QR base so mobile devices on same LAN can access it
    base = get_qr_base_url()
    url = f"{base}{url_for('main.student_mark')}?token={token}&teacher_id={teacher_id}"
    filename = create_and_save_qr_image(url, teacher_id, token)

    qr = QRCode(teacher_id=teacher_id, teacher_name=teacher_name, token=token, filename=filename)
    db.session.add(qr)
    db.session.commit()

    return jsonify({"status": "success", "filename": filename, "expires_in": 45})


# ----------------- TEACHER REPORT -----------------
@main.route("/teacher/report")
def teacher_report():
    if session.get("role") != "teacher":
        return redirect(url_for("main.teacher_login"))
    teacher_id = session.get("teacher_id")
    records = Attendance.query.filter_by(teacher_id=teacher_id).order_by(Attendance.marked_at.desc()).all()
    # Convert UTC times to Indian time (UTC+5:30)
    for r in records:
        if r.marked_at:
            ist_time = r.marked_at + timedelta(hours=5, minutes=30)
            r.display_time = ist_time.strftime("%d-%m-%Y %I:%M:%S %p")
    return render_template("attendancereport.html", records=records)


@main.route("/teacher/report/download")
def teacher_report_download():
    if session.get("role") != "teacher":
        return redirect(url_for("main.teacher_login"))

    teacher_id = session.get("teacher_id")

    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(["ID", "Student Name", "Roll No", "Teacher Name", "Time"])

    for r in Attendance.query.filter_by(teacher_id=teacher_id).order_by(Attendance.marked_at.desc()).all():
        writer.writerow([
            r.id,
            r.student_name,
            r.roll_no,
            r.teacher_name,
            r.marked_at.strftime("%Y-%m-%d %H:%M:%S")
        ])

    si.seek(0)
    mem = io.BytesIO(si.getvalue().encode("utf-8"))
    return send_file(mem, as_attachment=True, download_name=f"attendance_report_teacher_{teacher_id}.csv", mimetype="text/csv")

# ----------------- STUDENT -----------------
@main.route("/student/register", methods=["GET", "POST"])
def student_register():
    if request.method == "POST":
        name = request.form["name"]
        roll = request.form["roll_no"]
        email = request.form["email"]
        password = request.form["password"]
        if Student.query.filter((Student.email == email) | (Student.roll_no == roll)).first():
            flash("Already registered", "danger")
            return redirect(url_for("main.student_register"))
        s = Student(name=name, roll_no=roll, email=email, password_hash=generate_password_hash(password))
        # create a device token at registration time and bind it to this student
        token = secrets.token_urlsafe(32)
        s.device_token = token
        db.session.add(s)
        db.session.commit()
        flash("Student registered successfully!", "success")

        # set device cookie so this registering device can mark attendance
        resp = make_response(redirect(url_for("main.student_login")))
        resp.set_cookie("device_token", token, max_age=30*24*3600, httponly=True)
        return resp
    return render_template("register.html")

@main.route("/student/login", methods=["GET", "POST"])
def student_login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        s = Student.query.filter_by(email=email).first()
        if s and check_password_hash(s.password_hash, password):
            # Do NOT overwrite an existing registered device token here. We only
            # set a device token automatically at registration, or when a student
            # explicitly requests to register a new device (not implemented in UI
            # yet). This prevents a student from registering on phone and then
            # logging-in on PC and creating a new valid device token.
            session.clear()
            session["role"] = "student"
            session["student_id"] = s.id
            session["student_name"] = s.name
            session["student_roll"] = s.roll_no

            # If the student has no device_token (older accounts), create one now
            # and set the cookie. Otherwise, do not overwrite the stored token.
            if not s.device_token:
                token = secrets.token_urlsafe(32)
                s.device_token = token
                db.session.add(s)
                db.session.commit()
                resp = make_response(redirect(url_for("main.qr_scan_page")))
                resp.set_cookie("device_token", token, max_age=30*24*3600, httponly=True)
                return resp

            # If the incoming request already has the correct device cookie, keep it.
            incoming = request.cookies.get("device_token")
            if incoming and incoming == s.device_token:
                return redirect(url_for("main.qr_scan_page"))

            # Otherwise, allow login but do NOT set a cookie for this new device.
            # Marking attendance will fail until the student uses the registered device.
            return redirect(url_for("main.qr_scan_page"))
        flash("Invalid login", "danger")
    return render_template("studentlogin.html")

@main.route("/student/scan")
def qr_scan_page():
    teachers = Teacher.query.all()
    qr_list = []
    for t in teachers:
        latest = QRCode.query.filter_by(teacher_id=t.id).order_by(QRCode.created_at.desc()).first()
        if latest:
            qr_list.append({
                "teacher_name": t.name,
                "filename": latest.filename,
                "created_at": latest.created_at,
                "token": latest.token,        # added
                "teacher_id": t.id           # added
            })
    return render_template("qrdisplay.html", qr_list=qr_list)

@main.route("/student/mark", methods=["GET","POST"])
def student_mark():
    # prefer request.values (combines args and form)
    token = request.values.get("token")
    teacher_id = request.values.get("teacher_id")

    # fallback: try parse full URL query or fragment (some scanners put params in fragment)
    if not token or not teacher_id:
        try:
            parsed = urlparse(request.url)
            qs = parse_qs(parsed.query)
            if not token:
                token = qs.get("token", [None])[0]
            if not teacher_id:
                teacher_id = qs.get("teacher_id", [None])[0]
            # check fragment too
            if (not token or not teacher_id) and parsed.fragment:
                fq = parse_qs(parsed.fragment)
                if not token:
                    token = fq.get("token", [None])[0]
                if not teacher_id:
                    teacher_id = fq.get("teacher_id", [None])[0]
        except Exception:
            pass

    if not token or not teacher_id:
        flash("Invalid QR: Missing details", "danger")
        return redirect(url_for("main.qr_scan_page"))

    if session.get("role") != "student":
        flash("Please login as student first", "warning")
        return redirect(url_for("main.student_login"))

    try:
        teacher_id = int(teacher_id)
    except (TypeError, ValueError):
        flash("Invalid QR: teacher id", "danger")
        return redirect(url_for("main.qr_scan_page"))

    student = Student.query.get(session["student_id"])
    if not student:
        flash("Student not found", "danger")
        return redirect(url_for("main.qr_scan_page"))

    # verify the device token cookie matches the student's registered device token
    cookie_token = request.cookies.get("device_token")
    if not cookie_token or cookie_token != (student.device_token or None):
        flash("Device verification failed. Please login from your registered device.", "warning")
        return redirect(url_for("main.student_login"))

    now = int(time.time())
    current_slot = timeslot(now)
    valid = any(hmac.compare_digest(make_token(teacher_id, s), token)
                for s in [current_slot, current_slot - 1])

    if not valid:
        flash("Invalid or expired QR", "danger")
        return redirect(url_for("main.qr_scan_page"))

    # Additional server-side check: ensure the token was actually issued by a
    # teacher on this server recently. This prevents replaying a token from a
    # stale QR issued elsewhere (or via a proxy) even if the HMAC matches.
    qr_record = QRCode.query.filter_by(token=token, teacher_id=teacher_id).order_by(QRCode.created_at.desc()).first()
    if not qr_record:
        flash("Invalid QR: token not recognized", "danger")
        return redirect(url_for("main.qr_scan_page"))

    # enforce a short allowed age for the QR record (seconds). Configure via app.config['QR_MAX_AGE']
    max_qr_age = current_app.config.get('QR_MAX_AGE', 45)
    age = (datetime.utcnow() - qr_record.created_at).total_seconds()
    if age > max_qr_age:
        flash("Expired QR: please ask the teacher to refresh the QR", "danger")
        return redirect(url_for("main.qr_scan_page"))

    # Optional same-subnet check to reduce risk of remote proxies forwarding
    # QR scan requests. This compares the first three octets of the server's
    # detected LAN IP and the request.remote_addr. Enable with
    # app.config['REQUIRE_SAME_SUBNET']=True (or set env var REQUIRE_SAME_SUBNET=true).
    try:
        require_subnet = current_app.config.get('REQUIRE_SAME_SUBNET', False)
    except Exception:
        require_subnet = False

    if require_subnet:
        try:
            client_ip = request.remote_addr or ''
            server_ip = detect_lan_ip()
            # simple /24 match by comparing first three octets
            if client_ip.count('.') == 3 and server_ip.count('.') == 3:
                if '.'.join(client_ip.split('.')[:3]) != '.'.join(server_ip.split('.')[:3]):
                    flash('Request appears to come from a different network. Attendance marks are only allowed from the same LAN.', 'danger')
                    return redirect(url_for('main.qr_scan_page'))
        except Exception:
            # if anything goes wrong with the check, fail closed (reject the request)
            flash('Network verification failed. Please try again on the same Wi-Fi as the teacher.', 'danger')
            return redirect(url_for('main.qr_scan_page'))

    # prevent multiple marks same UTC day
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    existing = Attendance.query.filter(
        Attendance.student_id == student.id,
        Attendance.teacher_id == teacher_id,
        Attendance.marked_at >= today_start
    ).first()
    if existing:
        flash("Attendance already marked today!", "info")
        return redirect(url_for("main.qr_scan_page"))

    teacher_obj = Teacher.query.get(teacher_id)
    if not teacher_obj:
        flash("Teacher not found", "danger")
        return redirect(url_for("main.qr_scan_page"))

    rec = Attendance(
        student_id=student.id,
        student_name=student.name,
        roll_no=student.roll_no,
        teacher_id=teacher_id,
        teacher_name=teacher_obj.name,
        marked_at=datetime.utcnow()
    )
    db.session.add(rec)
    db.session.commit()

    flash(f"Attendance marked for {student.name}", "success")
    return redirect(url_for("main.qr_scan_page"))

@main.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for("main.index"))