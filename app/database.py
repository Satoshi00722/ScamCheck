
import sqlite3

DB_NAME = "users.db"

def _conn():
    return sqlite3.connect(DB_NAME)

def init_db():
    conn = _conn()
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        email TEXT UNIQUE,
        password_hash TEXT,
        subscription INTEGER DEFAULT 0
    )""")
    conn.commit()
    conn.close()

def create_user(email, password_hash):
    conn = _conn()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, password_hash))
        conn.commit()
        ok, err = True, None
    except sqlite3.IntegrityError:
        ok, err = False, "Email already registered"
    finally:
        conn.close()
    return ok, err

def get_user(email):
    conn = _conn()
    cur = conn.cursor()
    cur.execute("SELECT email, password_hash, subscription FROM users WHERE email=?", (email,))
    row = cur.fetchone()
    conn.close()
    return row

def set_subscription(email, sub: int):
    conn = _conn()
    cur = conn.cursor()
    cur.execute("UPDATE users SET subscription=? WHERE email=?", (1 if sub else 0, email))
    conn.commit()
    conn.close()
