from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = "campuscare_secret"  # In production, use a strong secret key from environment variables

# Initialize DB
def init_db():
    conn = sqlite3.connect("complaints.db")
    c = conn.cursor()
    
    # Drop existing tables if they exist (only for development!)
    c.execute("DROP TABLE IF EXISTS users")
    c.execute("DROP TABLE IF EXISTS complaints")
    
    # Create new tables with updated schema
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
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    
    # Create admin user
    try:
        admin_hash = generate_password_hash('admin123')  # Change this in production
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                 ('admin', admin_hash, 'admin'))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
        
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        uname = request.form['username']
        pwd = request.form['password']
        role = request.form.get('role', 'student')
        
        if not uname or not pwd:
            flash('Username and password are required!', 'error')
            return redirect('/register')
            
        conn = sqlite3.connect("complaints.db")
        c = conn.cursor()
        try:
            hashed_pwd = generate_password_hash(pwd)
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                     (uname, hashed_pwd, role))
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect('/login')
        except sqlite3.IntegrityError:
            flash('Username already exists!', 'error')
        finally:
            conn.close()
    return render_template('register.html')

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
        
    # Get basic stats for dashboard
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
        
        if not content or not category:
            flash('All fields are required!', 'error')
            return redirect('/register_complaint')
            
        conn = sqlite3.connect("complaints.db")
        c = conn.cursor()
        c.execute("INSERT INTO complaints (user_id, username, category, content) VALUES (?, ?, ?, ?)",
                 (session['user_id'], session['username'], category, content))
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
    
    # Base query
    query = '''
        SELECT id, category, content, status, created_at, resolved_at
        FROM complaints
        WHERE 1=1
    '''
    params = []
    
    # Apply filters
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
    
    # Get available categories for filter dropdown
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
    
    # Get complaint
    if session['role'] == 'admin':
        c.execute('''
            SELECT c.*, u.username 
            FROM complaints c
            JOIN users u ON c.user_id = u.id
            WHERE c.id = ?
        ''', (complaint_id,))
    else:
        c.execute('''
            SELECT * FROM complaints 
            WHERE id = ? AND user_id = ?
        ''', (complaint_id, session['user_id']))
    
    complaint = c.fetchone()
    
    if not complaint:
        conn.close()
        flash('Complaint not found!', 'error')
        return redirect('/show_complaints')
    
    # Handle status update
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

@app.route('/search')
def search_complaints():
    return redirect('/show_complaints?q=' + request.args.get('q', ''))

@app.route('/admin')
def admin():
    if 'username' not in session or session['role'] != 'admin':
        return redirect('/login')
    return redirect('/show_complaints')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect('/')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)