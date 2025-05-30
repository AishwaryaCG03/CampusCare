from flask import Flask, render_template, request, redirect, session, flash
import sqlite3

app = Flask(__name__)
app.secret_key = "campuscare_secret"

# Initialize DB
def init_db():
    conn = sqlite3.connect("complaints.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS complaints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        content TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
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
        conn = sqlite3.connect("complaints.db")
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (uname, pwd))
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username already exists"
        conn.close()
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form['username']
        pwd = request.form['password']
        conn = sqlite3.connect("complaints.db")
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (uname, pwd))
        user = c.fetchone()
        conn.close()
        if user:
            session['user_id'] = user[0]
            session['username'] = uname
            return redirect('/dashboard')
        else:
            return "Invalid credentials"
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('dashboard.html', username=session['username'])

@app.route('/register_complaint', methods=['GET', 'POST'])
def register_complaint():
    if 'user_id' not in session:
        return redirect('/login')
    if request.method == 'POST':
        content = request.form['content']
        conn = sqlite3.connect("complaints.db")
        c = conn.cursor()
        c.execute("INSERT INTO complaints (user_id, content) VALUES (?, ?)", (session['user_id'], content))
        conn.commit()
        conn.close()
        flash("Complaint registered successfully!")
        return redirect('/register_complaint')
    return render_template('register_complaint.html')

@app.route('/show_complaints')
def show_complaints():
    if 'user_id' not in session:
        return redirect('/login')
    conn = sqlite3.connect("complaints.db")
    c = conn.cursor()
    c.execute("SELECT content FROM complaints WHERE user_id=?", (session['user_id'],))
    complaints = [row[0] for row in c.fetchall()]
    conn.close()
    return render_template('show_complaints.html', complaints=complaints)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
