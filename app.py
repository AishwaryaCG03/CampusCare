from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")  # fallback secret key for dev

DB_PATH = "complaints.db"

# ---------------------- Database Initialization ----------------------

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            role TEXT DEFAULT 'student',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            category TEXT NOT NULL,
            content TEXT NOT NULL,
            status TEXT DEFAULT 'Pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved_at TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    # Create default admin user if not exists
    c.execute("SELECT id FROM users WHERE username = 'admin'")
    if c.fetchone() is None:
        admin_hash = generate_password_hash('admin123')  # CHANGE THIS IN PRODUCTION!
        c.execute("INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
                  ('admin', admin_hash, 'admin', 'admin@campuscare.com'))
        conn.commit()

    conn.close()

# ---------------------- Utility Functions ----------------------

def generate_random_string(length=6):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def send_credentials_email(to_email, username, password):
    SMTP_SERVER = os.getenv("SMTP_SERVER")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
    SMTP_USER = os.getenv("SMTP_USER")
    SMTP_PASS = os.getenv("SMTP_PASS")

    if not all([SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASS]):
        print("SMTP configuration is incomplete. Cannot send email.")
        return

    msg = EmailMessage()
    msg['Subject'] = 'Your CampusCare Credentials'
    msg['From'] = SMTP_USER
    msg['To'] = to_email
    msg.set_content(f"""
Hello,

Your CampusCare login credentials have been generated:

Username: {username}
Password: {password}

Please log in using these credentials.

Regards,
CampusCare Team
    """)

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASS)
            smtp.send_message(msg)
    except Exception as e:
        print(f"Failed to send email: {e}")

# ---------------------- Routes ----------------------

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form.get('username', '').strip()
        pwd = request.form.get('password', '')

        if not uname or not pwd:
            flash('Please provide both username and password.', 'error')
            return redirect('/login')

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT id, username, password, role FROM users WHERE username=?", (uname,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], pwd):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[3]
            flash(f'{user[3].capitalize()} login successful!', 'success')

            if user[3] == 'admin':
                return redirect('/admin')
            else:
                return redirect('/dashboard')
        else:
            flash('Invalid credentials!', 'error')
            return redirect('/login')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')

    if session.get('role') == 'admin':
        return redirect('/admin')

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM complaints WHERE user_id=?", (session['user_id'],))
    total_complaints = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM complaints WHERE user_id=? AND status='Resolved'", (session['user_id'],))
    resolved_complaints = c.fetchone()[0] or 0
    conn.close()

    return render_template('dashboard.html',
                           username=session.get('username'),
                           role=session.get('role'),
                           total_complaints=total_complaints,
                           resolved_complaints=resolved_complaints)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'username' not in session or session.get('role') != 'admin':
        flash("Admin access only!", "error")
        return redirect('/login')

    new_user_data = None

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            flash('Email is required!', 'error')
            return redirect('/admin')

        username = generate_random_string(6)
        password = generate_random_string(6)
        password_hash = generate_password_hash(password)

        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                      (username, password_hash, email, 'student'))
            conn.commit()
            conn.close()

            send_credentials_email(email, username, password)
            flash(f'User credentials generated and sent to {email}', 'success')
            new_user_data = {"username": username, "password": password}

        except sqlite3.IntegrityError:
            flash('Email or username already exists. Please try again.', 'error')
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')

    return render_template('admin.html',
                           username=session.get('username'),
                           new_user_data=new_user_data)

@app.route('/register_complaint', methods=['GET', 'POST'])
def register_complaint():
    if 'user_id' not in session:
        flash("Please log in to register a complaint.", "error")
        return redirect('/login')

    if session.get('role') == 'admin':
        flash("Admins cannot register complaints.", "error")
        return redirect('/admin')

    if request.method == 'POST':
        category = request.form.get('category')
        content = request.form.get('content')

        if not category or not content:
            flash("Please fill all fields.", "error")
            return redirect('/register_complaint')

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO complaints (user_id, username, category, content) VALUES (?, ?, ?, ?)",
                  (session['user_id'], session['username'], category, content))
        conn.commit()
        conn.close()

        flash("Complaint registered successfully!", "success")
        return redirect('/dashboard')

    return render_template('register_complaint.html')

@app.route('/show_complaints', methods=['GET', 'POST'])
def show_complaints():
    if 'user_id' not in session:
        flash("Please log in to view complaints.", "error")
        return redirect('/login')

    role = session.get('role')
    user_id = session.get('user_id')

    # Filtering parameters from query string
    search_query = request.args.get('q', '').strip()
    selected_category = request.args.get('category', '').strip()
    selected_status = request.args.get('status', '').strip()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Get distinct categories for filter dropdown
    c.execute("SELECT DISTINCT category FROM complaints")
    categories = [row[0] for row in c.fetchall()]

    # Build query based on role and filters
    base_query = "SELECT id, category, content, status, created_at FROM complaints"
    conditions = []
    params = []

    if role not in ['admin', 'faculty']:
        # User sees only their own complaints
        conditions.append("user_id = ?")
        params.append(user_id)

    if selected_category:
        conditions.append("category = ?")
        params.append(selected_category)

    if selected_status:
        conditions.append("status = ?")
        params.append(selected_status)

    if search_query:
        conditions.append("content LIKE ?")
        params.append(f"%{search_query}%")

    if conditions:
        base_query += " WHERE " + " AND ".join(conditions)

    base_query += " ORDER BY created_at DESC"

    c.execute(base_query, params)
    complaints = c.fetchall()
    conn.close()

    return render_template('show_complaints.html',
                           complaints=complaints,
                           role=role,
                           categories=categories,
                           search_query=search_query,
                           selected_category=selected_category,
                           selected_status=selected_status)

@app.route('/complaint/<int:complaint_id>', methods=['GET', 'POST'])
def complaint_details(complaint_id):
    if 'user_id' not in session:
        flash("Please log in to view complaint details.", "error")
        return redirect('/login')

    role = session.get('role')
    user_id = session.get('user_id')

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, user_id, username, category, content, status, created_at, resolved_at FROM complaints WHERE id=?", (complaint_id,))
    complaint = c.fetchone()

    if complaint is None:
        conn.close()
        flash("Complaint not found.", "error")
        return redirect('/show_complaints')

    # Check if user is allowed to view this complaint
    if role not in ['admin', 'faculty'] and complaint[1] != user_id:
        conn.close()
        flash("You do not have permission to view this complaint.", "error")
        return redirect('/show_complaints')

    # Handle status update if admin/faculty and POST
    if request.method == 'POST' and role in ['admin', 'faculty']:
        new_status = request.form.get('status')
        if new_status in ['Pending', 'In Progress', 'Resolved']:
            if new_status == 'Resolved' and complaint[5] != 'Resolved':
                # Mark resolved_at timestamp
                c.execute("UPDATE complaints SET status=?, resolved_at=CURRENT_TIMESTAMP WHERE id=?", (new_status, complaint_id))
            else:
                c.execute("UPDATE complaints SET status=? WHERE id=?", (new_status, complaint_id))
            conn.commit()
            flash("Complaint status updated.", "success")
            # Refresh complaint data after update
            c.execute("SELECT id, user_id, username, category, content, status, created_at, resolved_at FROM complaints WHERE id=?", (complaint_id,))
            complaint = c.fetchone()

    conn.close()

    return render_template('complaint_details.html', complaint=complaint, role=role)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect('/')

# ---------------------- Run App ----------------------

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
