# app/auth.py
from pathlib import Path
from dotenv import load_dotenv
# .env лежит в корне проекта (на уровень выше папки app)
load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

from fastapi import Request, Response
import os, hmac, hashlib, re
from typing import Tuple, Optional

# Админы
_env_admins = [e.strip().lower() for e in os.getenv("ADMIN_EMAILS", "").split(",") if e.strip()]
DEFAULT_ADMINS = {"illypanferov09@gmail.com", "illypanferov2@gmail.com"}
ADMIN_EMAILS = set(_env_admins) | DEFAULT_ADMINS

# Перец для паролей (не менять после запуска прод!)
AUTH_PEPPER = os.getenv("AUTH_PEPPER", "dev_pepper_change_me")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def _norm_email(e: Optional[str]) -> Optional[str]:
    return e.strip().lower() if e else None

def hash_pw(pw: str) -> str:
    pwd = (pw or "").strip().encode("utf-8")
    pepper = AUTH_PEPPER.encode("utf-8")
    return hmac.new(pepper, pwd, hashlib.sha256).hexdigest()

def verify_pw(pw_plain: str, pw_hash: str) -> bool:
    return hash_pw(pw_plain) == (pw_hash or "")

def is_logged_in(request: Request) -> bool:
    return request.cookies.get("user") is not None

def current_user(request: Request) -> Optional[str]:
    return _norm_email(request.cookies.get("user"))

def is_admin(email: Optional[str]) -> bool:
    e = _norm_email(email)
    return bool(e and e in ADMIN_EMAILS)

# Cookies
COOKIE_NAME = "user"
COOKIE_MAX_AGE = 60 * 60 * 24 * 90  # 90 дней

def set_login_cookie(resp: Response, email: str) -> None:
    resp.set_cookie(
        key=COOKIE_NAME,
        value=_norm_email(email) or "",
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        secure=False,   # локально False; на проде True
        samesite="lax",
        path="/",
    )

def clear_login_cookie(resp: Response) -> None:
    resp.delete_cookie(COOKIE_NAME, path="/")

# Работа с БД
from app.database import get_user, create_user

def _validate(email: str, password: str) -> Tuple[Optional[str], Optional[str]]:
    e = _norm_email(email)
    if not e or not EMAIL_RE.match(e): return None, "Bad email"
    if not password or len(password) < 6: return None, "Password >= 6 chars"
    return e, None

def register_user(email: str, password: str) -> Tuple[bool, str]:
    e, err = _validate(email, password)
    if err: return False, err
    if get_user(e): return False, "Email already registered"
    try:
        create_user(e, hash_pw(password))
    except Exception as ex:
        return False, f"DB error: {ex}"
    return True, "OK"

def authenticate_user(email: str, password: str) -> Tuple[bool, str]:
    e, err = _validate(email, password)
    if err: return False, err
    row = get_user(e)
    if not row: return False, "User not found"
    if not verify_pw(password, str(row["password_hash"])): return False, "Invalid password"
    return True, "OK"
