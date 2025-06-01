from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
import smtplib
from email.message import EmailMessage

app = Flask(__name__)
app.secret_key = "campuscare_secret"  # In production, store this in an environment variable

DB_PATH = "complaints.db"

# ---------------------- Database Initialization ----------------------

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Create users table
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

    # Create complaints table
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

    # Create default admin if not exists
    c.execute("SELECT id FROM users WHERE username = 'admin'")
    if c.fetchone() is None:
        admin_hash = generate_password_hash('admin123')  # Change in production
        c.execute("INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
                  ('admin', admin_hash, 'admin', 'admin@campuscare.com'))
        conn.commit()

    conn.close()

# ---------------------- Utility Functions ----------------------

def generate_random_string(length=6):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def send_credentials_email(to_email, username, password):
    SMTP_SERVER = 'smtp.example.com'  # Replace with your SMTP server
    SMTP_PORT = 587
    SMTP_USER = 'your-email@example.com'
    SMTP_PASS = 'your-email-password'

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
            flash('Login successful!', 'success')
            return redirect('/dashboard')
        else:
            flash('Invalid credentials!', 'error')
            return redirect('/login')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    if session.get('role') == 'admin':
        c.execute("SELECT COUNT(*) FROM complaints")
        total_complaints = c.fetchone()[0] or 0
        c.execute("SELECT COUNT(*) FROM complaints WHERE status='Resolved'")
        resolved_complaints = c.fetchone()[0] or 0
    else:
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

    generated_credentials = None

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
            generated_credentials = {'username': username, 'password': password}

        except sqlite3.IntegrityError:
            flash('Email or username already exists. Please try again.', 'error')
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')

    return render_template('admin.html', username=session.get('username'), credentials=generated_credentials)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect('/')

# ---------------------- Run App ----------------------

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
