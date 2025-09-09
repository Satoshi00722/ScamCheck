# app/database.py
import sqlite3, os, time
from datetime import date

DB_NAME = "users.db"
DEFAULT_SUBSCRIPTION_DAYS = int(os.getenv("SUBSCRIPTION_DAYS", "30"))
MAX_FREE_WALLET_CHECKS = int(os.getenv("MAX_FREE_WALLET_CHECKS", "3"))

def _conn():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = _conn(); cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY,
      email TEXT UNIQUE,
      password_hash TEXT,
      subscription INTEGER DEFAULT 0,
      subscription_until INTEGER,
      wallet_checks_today INTEGER DEFAULT 0 NOT NULL,
      last_wallet_check TEXT
    )""")
    conn.commit(); conn.close()

def create_user(email: str, password_hash: str) -> None:
    conn = _conn(); cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users(email,password_hash) VALUES(?,?)",
            (email.strip().lower(), password_hash)
        )
        conn.commit()
    finally:
        conn.close()

def get_user(email: str):
    conn = _conn(); cur = conn.cursor()
    cur.execute(
        "SELECT id,email,password_hash,subscription,subscription_until,wallet_checks_today,last_wallet_check "
        "FROM users WHERE email=?", (email.strip().lower(),)
    )
    row = cur.fetchone(); conn.close()
    return row

def _now_ts() -> int: return int(time.time())

def has_active_subscription(email: str) -> bool:
    row = get_user(email)
    if not row: return False
    sub = int(row["subscription"] or 0)
    until = int(row["subscription_until"] or 0)
    return sub == 1 and until > _now_ts()

def days_left(email: str) -> int:
    row = get_user(email)
    if not row or not row["subscription_until"]: return 0
    delta = int(row["subscription_until"]) - _now_ts()
    return max(0, delta // (24*60*60))

def set_subscription(email: str, sub: int, days: int | None = None):
    if days is None: days = DEFAULT_SUBSCRIPTION_DAYS
    conn = _conn(); cur = conn.cursor()
    if sub:
        cur.execute("SELECT subscription,subscription_until FROM users WHERE email=?", (email.strip().lower(),))
        row = cur.fetchone(); now = _now_ts()
        start_ts = int(row["subscription_until"]) if row and int(row["subscription"] or 0)==1 and int(row["subscription_until"] or 0) > now else now
        until_ts = start_ts + days*24*60*60
        cur.execute("UPDATE users SET subscription=?,subscription_until=? WHERE email=?",
                    (1, until_ts, email.strip().lower()))
        cur.execute("UPDATE users SET wallet_checks_today=?, last_wallet_check=? WHERE email=?",
                    (0, date.today().isoformat(), email.strip().lower()))
    else:
        cur.execute("UPDATE users SET subscription=?,subscription_until=NULL WHERE email=?",
                    (0, email.strip().lower()))
    conn.commit(); conn.close()

def _reset_daily_if_needed(cur, email: str):
    today = date.today().isoformat()
    cur.execute("SELECT wallet_checks_today,last_wallet_check FROM users WHERE email=?",
                (email.strip().lower(),))
    row = cur.fetchone()
    if not row: return
    if row["last_wallet_check"] != today:
        cur.execute("UPDATE users SET wallet_checks_today=?, last_wallet_check=? WHERE email=?",
                    (0, today, email.strip().lower()))

def get_wallet_usage(email: str) -> tuple[int,int]:
    conn = _conn(); cur = conn.cursor()
    _reset_daily_if_needed(cur, email)
    cur.execute("SELECT wallet_checks_today FROM users WHERE email=?", (email.strip().lower(),))
    row = cur.fetchone(); conn.commit(); conn.close()
    used = int(row["wallet_checks_today"] if row else 0)
    left = max(0, MAX_FREE_WALLET_CHECKS - used)
    return used, left

def try_consume_wallet_check(email: str) -> tuple[bool,int,str|None]:
    if has_active_subscription(email): return True, -1, None
    conn = _conn(); cur = conn.cursor()
    _reset_daily_if_needed(cur, email)
    cur.execute("SELECT wallet_checks_today FROM users WHERE email=?", (email.strip().lower(),))
    row = cur.fetchone()
    used = int(row["wallet_checks_today"] if row else 0)
    if used >= MAX_FREE_WALLET_CHECKS:
        conn.commit(); conn.close()
        return False, 0, "Free limit reached (5/day)."
    used += 1
    cur.execute("UPDATE users SET wallet_checks_today=? WHERE email=?", (used, email.strip().lower()))
    conn.commit(); conn.close()
    left_after = max(0, MAX_FREE_WALLET_CHECKS - used)
    return True, left_after, None

def get_limits_badge(email: str) -> dict:
    premium = has_active_subscription(email)
    dleft = days_left(email) if premium else 0
    used, left = get_wallet_usage(email) if not premium else (0, -1)
    return {"is_premium": premium, "days_left": dleft, "used_today": used,
            "left_today": left, "max_free": MAX_FREE_WALLET_CHECKS}
