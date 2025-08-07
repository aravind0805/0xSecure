# Updated Flask App using Gemini API for Suggestions

from flask import Flask, render_template, request, send_file, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
import google.generativeai as genai

# Load environment variables from .env
load_dotenv()

# Analyzer modules
from analyzer.python_analyzer import analyze_python_code
from analyzer.javascript_analyzer import analyze_js_code
from analyzer.php_analyzer import analyze_php_code

# Flask App Setup
app = Flask(__name__)
app.secret_key = os.getenv('5b25cd73800dac5a584845618d77a22705241a3ecdba863c167728e80d5f0b15', 'GgiKNFHwC1R9FCktFNGxxhHisRtjRqUg8aycgK8fo79Tgk6KimP9jPKXskzZA')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# Gemini API Key and Configuration
genai.configure(api_key=os.getenv("AIzaSyB83hU-wYBOb-200pfz_CiYriNK1QbbuH4"))
gemini_model = genai.GenerativeModel('gemini-2.0-flash')

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
latest_file_path = ""

# -------------------- User Model -------------------- #
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')

# -------------------- Routes -------------------- #
@app.errorhandler(500)
def internal_error(error):
    return jsonify({"suggestion": "Internal Server Error. Please check Gemini API key and logs."}), 500

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash("Please enter both username and password")
            return redirect('/login')

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials")
            return redirect('/login')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash("All fields are required")
            return redirect('/register')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists")
            return redirect('/register')

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful. Please login.")
        return redirect('/login')

    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'], role=session['role'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    global latest_file_path
    if 'user_id' not in session:
        return redirect(url_for('login'))

    results = []
    if request.method == 'POST':
        file = request.files.get('code_file')
        if file:
            filename = file.filename
            ext = filename.split('.')[-1].lower()
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            latest_file_path = filepath

            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()

            if ext == 'py':
                results = analyze_python_code(code)
            elif ext == 'js':
                results = analyze_js_code(code)
            elif ext == 'php':
                results = analyze_php_code(code)
            else:
                results = [{'line': 0, 'issue': 'Unsupported file type', 'code': filename}]

    return render_template('index.html', results=results, username=session.get('username'))

@app.route('/download')
def download():
    global latest_file_path
    if not latest_file_path:
        return "No file scanned yet!", 400

    ext = latest_file_path.split('.')[-1].lower()
    with open(latest_file_path, 'r', encoding='utf-8', errors='ignore') as f:
        code = f.read()

    if ext == 'py':
        results = analyze_python_code(code)
    elif ext == 'js':
        results = analyze_js_code(code)
    elif ext == 'php':
        results = analyze_php_code(code)
    else:
        results = []

    report_path = "report.txt"
    with open(report_path, "w") as f:
        f.write("Scan Report\n")
        f.write("====================\n")
        for r in results:
            f.write(f"Line {r['line']}: {r['issue']} -> {r['code']}\n")

    return send_file(report_path, as_attachment=True)

# -------------------- Gemini Suggestion Endpoint -------------------- #
@app.route("/suggest_fix", methods=["POST"])
def suggest_fix():
    try:
        data = request.json
        issue = data['issue']
        code = data['code']
        prompt = f"Here is a vulnerability:\nIssue: {issue}\nCode: {code}\nHow can I fix this issue?"

        response = gemini_model.generate_content(prompt)
        suggestion = response.text
        return jsonify({'suggestion': suggestion})

    except Exception as e:
        return jsonify({'suggestion': f"\u274c Gemini failed to respond.\n{str(e)}"}), 500

# -------------------- Run Server -------------------- #
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

