# app.py
import os
import re
import json
import time
import uuid
import threading
import sqlite3
import smtplib
import requests
import logging
import hashlib,string,random
from email.message import EmailMessage
from datetime import datetime,timedelta
from functools import wraps
from dotenv import load_dotenv
import google.generativeai as genai

from flask import (
    Flask, request, jsonify, render_template, redirect, url_for, session,
    flash, send_from_directory, current_app
)
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer

# -------------------- Basic config -------------------- #
load_dotenv()
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'database.db')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = 'secret-key here'
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{DB_PATH}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB default

CORS(app)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# -------------------- Gemini API Config -------------------- #
# Hardcoding your API key here
GEMINI_API_KEY = "api-key here"
MODEL_NAME = "gemini-2.0-flash"

if not GEMINI_API_KEY:
    logging.error("GEMINI_API_KEY is missing!")
else:
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel(MODEL_NAME)
    logging.info("Gemini API configured successfully.")

# -------------------- DB / Models -------------------- #
db = SQLAlchemy(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def get_user_table_columns():
    if not os.path.exists(DB_PATH):
        return False, []
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user';")
        if cur.fetchone() is None:
            return False, []
        cur.execute("PRAGMA table_info('user');")
        cols = [row[1] for row in cur.fetchall()]
        return True, cols
    finally:
        conn.close()

def add_missing_columns(expected_cols):
    exists, cols = get_user_table_columns()
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        if not exists:
            col_defs = ["id INTEGER PRIMARY KEY"]
            for c, t in expected_cols.items():
                col_defs.append(f"{c} {t}")
            create_sql = f"CREATE TABLE user ({', '.join(col_defs)});"
            cur.execute(create_sql)
            conn.commit()
            return
        for col, coltype in expected_cols.items():
            if col not in cols:
                try:
                    cur.execute(f"ALTER TABLE user ADD COLUMN {col} {coltype};")
                    conn.commit()
                except Exception:
                    pass
    finally:
        conn.close()

exists, cols = get_user_table_columns()
if exists and 'password_hash' in cols:
    PASSWORD_DB_COL = 'password_hash'
else:
    PASSWORD_DB_COL = 'password'

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column('username', db.String(80), unique=True, nullable=False)
    email = db.Column('email', db.String(200), unique=True, nullable=False)
    password = db.Column(PASSWORD_DB_COL, db.String(512), nullable=False)
    reset_token = db.Column('reset_token', db.String(100), nullable=True)

    def get_reset_token(self):
        return serializer.dumps(self.id, salt='password-reset-salt')

    @staticmethod
    def verify_reset_token(token, expires_sec=1800):
        try:
            user_id = serializer.loads(token, salt='password-reset-salt', max_age=expires_sec)
        except Exception:
            return None
        return User.query.get(user_id)

expected = {
    'username': 'TEXT',
    'email': 'TEXT',
    PASSWORD_DB_COL: 'TEXT',
    'reset_token': 'TEXT'
}
add_missing_columns(expected)

with app.app_context():
    db.create_all()

# -------------------- Mail config -------------------- #
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_ADDRESS = "0xsecure.help@gmail.com"
EMAIL_PASSWORD = "Alberto/04"

verification_store = {}


# -------------------- Utilities -------------------- #
def validate_password(password):
    errors = []
    if not password:
        errors.append("Password required.")
        return errors
    if len(password) < 8:
        errors.append("Password must be at least 8 characters.")
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain a lowercase letter.")
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain an uppercase letter.")
    if not re.search(r'\d', password):
        errors.append("Password must contain a digit.")
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\'\":\\|,.<>\/?]', password):
        errors.append("Password must contain a special character.")
    return errors

def login_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please login first.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return inner

def send_email(to_email, subject, body):
    msg = EmailMessage()
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_key(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

@app.route("/forget-password", methods=["GET"])
def forget_password_page():
    return render_template("forgot_password.html")




@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")

    if not username or not email:
        return jsonify({"success": False, "message": "Username and email required"}), 400

    user = User.query.filter_by(username=username, email=email).first()
    if not user:
        return jsonify({"success": False, "message": "Invalid username/email combination"}), 404

    # Generate and store key
    key = generate_key()
    verification_store[username] = {"key": key, "expiry": datetime.now() + timedelta(minutes=10)}

    # Send email
    send_email(email, "Your Password Reset Key", f"Your password reset key is: {key}")

    return jsonify({"success": True, "message": "Verification key sent to your email"})

# Step 2: Verify Key
@app.route("/verify-key", methods=["POST"])
def verify_key():
    data = request.get_json()
    username = data.get("username")
    key = data.get("key")

    if username not in verification_store:
        return jsonify({"success": False, "message": "No verification request found"}), 400

    stored = verification_store[username]
    if datetime.now() > stored["expiry"]:
        return jsonify({"success": False, "message": "Verification key expired"}), 400

    if stored["key"] != key:
        return jsonify({"success": False, "message": "Invalid verification key"}), 400

    return jsonify({"success": True, "message": "Key verified"})

# Step 3: Reset Password
@app.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    new_password = data.get("new_password")

    if not username or not email or not new_password:
        return jsonify({"success": False, "message": "All fields are required"}), 400

    user = User.query.filter_by(username=username, email=email).first()
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    user.password_hash = hash_password(new_password)
    db.session.commit()

    # Remove from verification store
    verification_store.pop(username, None)

    return jsonify({"success": True, "message": "Password reset successful"})


# -------------------- Gemini API Call -------------------- #
def call_gemini_api_with_backoff(file_content_str, retries=3, delay=1):
    prompt = f"""
You are a senior software security and quality analyst.
Analyze the provided code for potential vulnerabilities and code quality issues.
Respond ONLY with a valid JSON array of findings.

Each finding must have:
- id (number)
- severity (low, medium, high, critical)
- title (short string)
- file (string)
- line (number)
- summary (string)
- code (string snippet)
- confidence (0-100 number)
- suggestedFix (string)

Do NOT include explanations outside the JSON.
Do NOT wrap the JSON in markdown code blocks.

File content:
---
{file_content_str}
---
"""

    for attempt in range(retries):
        try:
            response = gemini_model.generate_content(prompt)

            if response and response.candidates:
                text_output = response.candidates[0].content.parts[0].text.strip()

                # Remove markdown ```json fences if present
                if text_output.startswith("```"):
                    text_output = text_output.strip("`").replace("json", "", 1).strip()

                try:
                    return json.loads(text_output)
                except json.JSONDecodeError as e:
                    logging.error(f"JSON parsing failed: {e}")
                    logging.error(f"Raw Gemini output:\n{text_output}")
                    return []

        except Exception as e:
            logging.error(f"Gemini API error attempt {attempt+1}: {e}")
            time.sleep(delay)
            delay *= 2

    return []

# -------------------- Routes -------------------- #
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        confirm = request.form.get('confirm_password') or ''
        if not username or not email or not password or not confirm:
            flash("Please fill out all fields.")
            return redirect(url_for('register'))
        pw_errors = validate_password(password)
        if pw_errors:
            for err in pw_errors:
                flash(err)
            return redirect(url_for('register'))
        if password != confirm:
            flash("Passwords do not match.")
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash("Username already taken.")
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash("Email already registered.")
            return redirect(url_for('register'))
        hashed = generate_password_hash(password, method='pbkdf2:sha256')
        user = User(username=username, email=email)
        setattr(user, 'password', hashed)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. Please log in.")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        if '@' in identifier:
            user = User.query.filter_by(email=identifier.lower()).first()
        else:
            user = User.query.filter_by(username=identifier).first()
        if user and check_password_hash(getattr(user, 'password'), password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials.")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('index.html', username=session.get('username'))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {
        'py', 'js', 'java', 'cpp', 'c', 'php', 'rb', 'go', 'ts', 'html', 'css'
    }

@app.route("/scan", methods=["POST"])
@login_required
def scan_code():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "Empty filename"}), 400
        if not allowed_file(file.filename):
            return jsonify({"error": f"File type not allowed: {file.filename}"}), 400

        content = file.read().decode('utf-8', errors='ignore')
        logging.info(f"Scanning file: {file.filename} ({len(content)} bytes)")

        findings = call_gemini_api_with_backoff(content)

        if not findings:
            return jsonify([{
                "id": 0,
                "severity": "info",
                "title": "No issues detected",
                "file": file.filename,
                "line": 0,
                "summary": "The scan completed but found no issues.",
                "code": "",
                "confidence": 100,
                "suggestedFix": ""
            }])

        return jsonify(findings)
    except Exception as e:
        logging.exception("Scan error")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

# -------------------- Run -------------------- #
if __name__ == '__main__':
    app.run(debug=True)
