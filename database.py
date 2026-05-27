import sqlite3
import os
import json
import traceback

# Ensure the database path is ALWAYS absolute relative to this script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'app.db')
LOG_PATH = os.path.join(BASE_DIR, 'db_errors.log')

def get_db_connection():
    # Increase timeout and enable WAL for multi-threaded concurrency
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with users and reports tables."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    
    # Reports table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE NOT NULL,
            user_id INTEGER,
            target_url TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            status TEXT NOT NULL,
            data_json TEXT, -- Serialized results dictionary
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

def save_report(scan_id, user_id, target_url, timestamp, status, data_dict):
    """Save or update a scan report."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        data_json = json.dumps(data_dict)
        
        cursor.execute('''
            INSERT OR REPLACE INTO reports (scan_id, user_id, target_url, timestamp, status, data_json)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (scan_id, user_id, target_url, timestamp, status, data_json))
        
        conn.commit()
    except Exception as e:
        error_msg = f"DATABASE ERROR during save_report: {str(e)}\n{traceback.format_exc()}"
        print(error_msg)
        with open(LOG_PATH, 'a') as f:
            f.write(f"\n[{timestamp}] {error_msg}\n")
    finally:
        if 'conn' in locals():
            conn.close()

def get_report(scan_id):
    """Retrieve a report by its UUID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM reports WHERE scan_id = ?', (scan_id,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        report = dict(row)
        report['data'] = json.loads(row['data_json'])
        return report
    return None

def get_reports_by_user(user_id):
    """Retrieve all reports belonging to a specific user, ordered by date."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT scan_id, target_url, timestamp, status 
        FROM reports 
        WHERE user_id = ? 
        ORDER BY id DESC
    ''', (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_user_by_username(username):
    """Retrieve a user record."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def create_user(username, password_hash):
    """Register a new user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

if __name__ == '__main__':
    init_db()
    print("Database initialized.")
