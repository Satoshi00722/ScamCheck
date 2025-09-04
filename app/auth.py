
from fastapi import Request
import hashlib, os

ADMIN_EMAILS = set([e.strip() for e in os.getenv("ADMIN_EMAILS","").split(",") if e.strip()])

def hash_pw(pw: str) -> str:
    return hashlib.sha256((pw or "").encode()).hexdigest()

def is_logged_in(request: Request) -> bool:
    return request.cookies.get("user") is not None

def current_user(request: Request) -> str | None:
    return request.cookies.get("user")

def is_admin(email: str | None) -> bool:
    return bool(email and email in ADMIN_EMAILS)
