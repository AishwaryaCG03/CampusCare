import sqlite3

conn = sqlite3.connect("complaints.db")
c = conn.cursor()
try:
    c.execute("ALTER TABLE complaints ADD COLUMN category TEXT")
    print("Column 'category' added successfully.")
except sqlite3.OperationalError as e:
    print("Error:", e)
conn.commit()
conn.close()
