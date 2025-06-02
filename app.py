from flask import Flask, render_template, request, redirect, session, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import sqlite3
from io import BytesIO
from reportlab.pdfgen import canvas
from openpyxl import Workbook
import os
from flask_apscheduler import APScheduler

app = Flask(__name__)
app.secret_key = "campuscare_secret"  # Use environment variable in production

# Configure upload settings
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# Initialize scheduler
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Initialize DB
def init_db():
    conn = sqlite3.connect("complaints.db")
    c = conn.cursor()

    # Drop tables (for development only)
    c.execute("DROP TABLE IF EXISTS users")
    c.execute("DROP TABLE IF EXISTS complaints")

    # Create tables
    c.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'student',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            category TEXT NOT NULL,
            content TEXT NOT NULL,
            status TEXT DEFAULT 'Pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved_at TIMESTAMP,
            evidence TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    # Create default admin user
    try:
        admin_hash = generate_password_hash('admin123')  # Change in production
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                  ('admin', admin_hash, 'admin'))
        conn.commit()
    except sqlite3.IntegrityError:
        pass

    conn.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form['username']
        pwd = request.form['password']

        conn = sqlite3.connect("complaints.db")
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
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect("complaints.db")
    c = conn.cursor()

    if session['role'] == 'admin':
        c.execute("SELECT COUNT(*) FROM complaints")
        total_complaints = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM complaints WHERE status='Resolved'")
        resolved_complaints = c.fetchone()[0]
    else:
        c.execute("SELECT COUNT(*) FROM complaints WHERE user_id=?", (session['user_id'],))
        total_complaints = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM complaints WHERE user_id=? AND status='Resolved'", 
                  (session['user_id'],))
        resolved_complaints = c.fetchone()[0]

    conn.close()

    return render_template('dashboard.html',
                           username=session['username'],
                           role=session['role'],
                           total_complaints=total_complaints,
                           resolved_complaints=resolved_complaints)

@app.route('/register_complaint', methods=['GET', 'POST'])
def register_complaint():
    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        content = request.form['content']
        category = request.form['category']
        
        # Handle file upload
        file = request.files.get('evidence')
        filename = None
        if file and allowed_file(file.filename):
            filename = secure_filename(f"{session['user_id']}_{datetime.now().timestamp()}.{file.filename.rsplit('.', 1)[1].lower()}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        if not content or not category:
            flash('All fields are required!', 'error')
            return redirect('/register_complaint')

        conn = sqlite3.connect("complaints.db")
        c = conn.cursor()
        c.execute("INSERT INTO complaints (user_id, username, category, content, evidence) VALUES (?, ?, ?, ?, ?)",
                  (session['user_id'], session['username'], category, content, filename))
        conn.commit()
        conn.close()
        flash('Complaint registered successfully!', 'success')
        return redirect('/dashboard')

    return render_template('register_complaint.html')

@app.route('/show_complaints')
def show_complaints():
    if 'user_id' not in session:
        return redirect('/login')

    search_query = request.args.get('q', '')
    category_filter = request.args.get('category', '')
    status_filter = request.args.get('status', '')

    conn = sqlite3.connect("complaints.db")
    c = conn.cursor()

    query = '''
        SELECT id, category, content, status, created_at, resolved_at, evidence
        FROM complaints
        WHERE 1=1
    '''
    params = []

    if session['role'] != 'admin':
        query += " AND user_id = ?"
        params.append(session['user_id'])

    if search_query:
        query += " AND (content LIKE ? OR category LIKE ?)"
        params.extend([f'%{search_query}%', f'%{search_query}%'])

    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)

    if status_filter:
        query += " AND status = ?"
        params.append(status_filter)

    query += " ORDER BY created_at DESC"
    c.execute(query, params)
    complaints = c.fetchall()

    if session['role'] == 'admin':
        c.execute("SELECT DISTINCT category FROM complaints")
    else:
        c.execute("SELECT DISTINCT category FROM complaints WHERE user_id=?", (session['user_id'],))
    categories = [row[0] for row in c.fetchall()]

    conn.close()

    return render_template('show_complaints.html',
                           complaints=complaints,
                           search_query=search_query,
                           categories=categories,
                           selected_category=category_filter,
                           selected_status=status_filter,
                           role=session['role'])

@app.route('/complaint/<int:complaint_id>', methods=['GET', 'POST'])
def complaint_detail(complaint_id):
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect("complaints.db")
    c = conn.cursor()

    if session['role'] == 'admin':
        c.execute('''
            SELECT c.*, u.username 
            FROM complaints c
            JOIN users u ON c.user_id = u.id
            WHERE c.id = ?
        ''', (complaint_id,))
    else:
        c.execute("SELECT * FROM complaints WHERE id = ? AND user_id = ?", 
                  (complaint_id, session['user_id']))

    complaint = c.fetchone()

    if not complaint:
        conn.close()
        flash('Complaint not found!', 'error')
        return redirect('/show_complaints')

    if request.method == 'POST' and session['role'] in ['admin', 'faculty']:
        new_status = request.form.get('status')
        if new_status in ['Pending', 'In Progress', 'Resolved']:
            resolved_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S') if new_status == 'Resolved' else None
            c.execute('''
                UPDATE complaints 
                SET status = ?, resolved_at = ?
                WHERE id = ?
            ''', (new_status, resolved_at, complaint_id))
            conn.commit()
            flash('Status updated successfully!', 'success')

    conn.close()
    return render_template('complaint_detail.html',
                           complaint=complaint,
                           role=session['role'])

@app.route('/generate_report', methods=['GET', 'POST'])
def generate_report():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect('/login')

    if request.method == 'POST':
        report_type = request.form.get('report_type')
        format_type = request.form.get('format')

        conn = sqlite3.connect("complaints.db")
        c = conn.cursor()

        query = "SELECT * FROM complaints"
        if report_type == 'PENDING':
            query += " WHERE status='Pending'"
        elif report_type == 'RESOLVED':
            query += " WHERE status='Resolved'"
        elif report_type == 'CATEGORY':
            category = request.form.get('category')
            query += f" WHERE category='{category}'"

        c.execute(query)
        complaints = c.fetchall()
        conn.close()

        if format_type == 'PDF':
            return generate_pdf_report(complaints, report_type)
        else:
            return generate_excel_report(complaints, report_type)

    conn = sqlite3.connect("complaints.db")
    c = conn.cursor()
    c.execute("SELECT DISTINCT category FROM complaints")
    categories = [row[0] for row in c.fetchall()]
    conn.close()

    return render_template('generate_report.html', categories=categories)

def generate_pdf_report(complaints, report_type):
    buffer = BytesIO()
    p = canvas.Canvas(buffer)

    # PDF Header
    p.setFont("Helvetica-Bold", 16)
    p.drawString(100, 800, f"CampusCare {report_type} Report")
    p.drawString(100, 780, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M')}")

    # PDF Content
    y = 750
    p.setFont("Helvetica", 12)
    for complaint in complaints:
        p.drawString(100, y, f"ID: {complaint[0]} | Category: {complaint[3]}")
        p.drawString(100, y-20, f"Status: {complaint[5]} | Created: {complaint[6].split()[0]}")
        p.drawString(100, y-40, f"Description: {complaint[4][:100]}...")
        y -= 80
        if y < 100:
            p.showPage()
            y = 800

    p.save()
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"{report_type}_report_{datetime.now().date()}.pdf",
        mimetype='application/pdf'
    )

def generate_excel_report(complaints, report_type):
    buffer = BytesIO()
    workbook = Workbook()
    worksheet = workbook.active
    worksheet.title = report_type

    # Excel Header
    headers = ['ID', 'Username', 'Category', 'Content', 'Status', 'Created At', 'Resolved At', 'Evidence']
    worksheet.append(headers)

    # Excel Content
    for complaint in complaints:
        worksheet.append([
            complaint[0],  # ID
            complaint[2],  # Username
            complaint[3],  # Category
            complaint[4],  # Content
            complaint[5],  # Status
            complaint[6],  # Created At
            complaint[7] if complaint[7] else '',  # Resolved At
            complaint[8] if complaint[8] else ''   # Evidence
        ])

    workbook.save(buffer)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"{report_type}_report_{datetime.now().date()}.xlsx",
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )

# Scheduled Reports
@scheduler.task('cron', id='daily_report', day_of_week='*', hour=8)
def generate_daily_report():
    with app.app_context():
        conn = sqlite3.connect("complaints.db")
        c = conn.cursor()
        c.execute("SELECT * FROM complaints WHERE date(created_at) = date('now', '-1 day')")
        complaints = c.fetchall()
        conn.close()

        if complaints:
            buffer = BytesIO()
            workbook = Workbook()
            worksheet = workbook.active
            worksheet.title = "Daily Report"
            
            headers = ['ID', 'Username', 'Category', 'Content', 'Status']
            worksheet.append(headers)
            
            for complaint in complaints:
                worksheet.append([complaint[0], complaint[2], complaint[3], complaint[4], complaint[5]])
            
            workbook.save(buffer)
            buffer.seek(0)
            
            # Save to reports directory
            if not os.path.exists('reports'):
                os.makedirs('reports')
            with open(f"reports/daily_report_{datetime.now().date()}.xlsx", "wb") as f:
                f.write(buffer.getvalue())

@app.route('/admin')
def admin():
    if 'username' not in session or session['role'] != 'admin':
        flash("Admin access only!", "error")
        return redirect('/login')
    
    conn = sqlite3.connect("complaints.db")
    c = conn.cursor()
    c.execute("SELECT * FROM complaints ORDER BY created_at DESC")
    complaints = c.fetchall()
    conn.close()
    
    return render_template('admin.html', 
                         username=session['username'],
                         complaints=complaints)

@app.route('/search')
def search_complaints():
    return redirect('/show_complaints?q=' + request.args.get('q', ''))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect('/')

if __name__ == '__main__':
    # Create necessary directories
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    if not os.path.exists('reports'):
        os.makedirs('reports')
    
    init_db()
    app.run(debug=True)