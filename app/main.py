# app/main.py
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

from fastapi import FastAPI, Request, Form, Header
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import os, hmac, hashlib, json

from app.database import (
    init_db,
    set_subscription,
    try_consume_wallet_check,
    get_limits_badge,
    has_active_subscription,
)

from app.auth import (
    register_user,
    authenticate_user,
    set_login_cookie,
    clear_login_cookie,
    is_logged_in,
    current_user,
    is_admin,
)

from app.checks import wallet_check
from app.sources import (
    token_dex_info,
    token_honeypot_check,
    etherscan_contract_source,
    create_nowpayments_invoice,
    group_quick_check,
)

app = FastAPI(title="ScamCheck")
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

init_db()

# --------- helpers ----------
def require_login(request: Request):
    """Redirects to /register if the user is not logged in."""
    if not is_logged_in(request):
        return RedirectResponse(url="/register?next=/", status_code=302)


def has_premium(email: str | None) -> bool:
    """Admins are always premium; otherwise check subscription."""
    if is_admin(email):
        return True
    return bool(email and has_active_subscription(email))


# --------- pages ----------
@app.get("/", response_class=HTMLResponse)
async def home(request: Request, msg: str | None = None):
    redir = require_login(request)
    if redir:
        return redir
    email = current_user(request)
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "result": None, "user": email, "msg": msg, "badge": get_limits_badge(email)},
    )


@app.post("/check_wallet", response_class=HTMLResponse)
async def check_wallet_route(request: Request, address: str = Form(...)):
    """
    Wallet checks: Free plan is limited per day; Premium/Admin is unlimited.
    The quota applies ONLY to wallet checks (not to token/contract pages).
    """
    redir = require_login(request)
    if redir:
        return redir

    email = current_user(request)
    msg = None

    # Apply quota only if NOT admin and NO active subscription
    if not is_admin(email) and not has_active_subscription(email):
        ok, left_after, err = try_consume_wallet_check(email)
        if not ok:
            return templates.TemplateResponse(
                "index.html",
                {
                    "request": request,
                    "result": None,
                    "user": email,
                    "msg": err or "Free limit reached. Upgrade to Premium for unlimited checks.",
                    "badge": get_limits_badge(email),
                },
                status_code=200,
            )
        else:
            msg = f"Free checks left today: {left_after}"

    result = await wallet_check(address)
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "result": result, "user": email, "msg": msg, "badge": get_limits_badge(email)},
    )


@app.get("/token", response_class=HTMLResponse)
async def token_page(request: Request, token: str | None = None, chain: str = "eth"):
    redir = require_login(request)
    if redir:
        return redir
    email = current_user(request)
    prem = has_premium(email)
    info = None
    hp = None
    if token and prem:
        info = await token_dex_info(token)
        hp = await token_honeypot_check(token, chain=chain)
    return templates.TemplateResponse(
        "token.html",
        {
            "request": request,
            "user": email,
            "sub": prem,
            "info": info,
            "hp": hp,
            "token": token,
            "chain": chain,
            "badge": get_limits_badge(email),
        },
    )


@app.get("/contract", response_class=HTMLResponse)
async def contract_page(request: Request, address: str | None = None, chain_code: str = "ETH"):
    redir = require_login(request)
    if redir:
        return redir
    email = current_user(request)
    prem = has_premium(email)
    res = None
    if address and prem:
        res = await etherscan_contract_source(address, chain_code=chain_code)
    return templates.TemplateResponse(
        "contract.html",
        {
            "request": request,
            "user": email,
            "sub": prem,
            "result": res,
            "address": address,
            "chain_code": chain_code,
            "badge": get_limits_badge(email),
        },
    )


@app.get("/group", response_class=HTMLResponse)
async def group_page(request: Request, link: str | None = None):
    redir = require_login(request)
    if redir:
        return redir
    email = current_user(request)
    prem = has_premium(email)
    result = None
    if prem and link:
        result = await group_quick_check(link)
    return templates.TemplateResponse(
        "group.html",
        {"request": request, "user": email, "sub": prem, "result": result, "link": link, "badge": get_limits_badge(email)},
    )


@app.get("/knowledge", response_class=HTMLResponse)
async def knowledge_page(request: Request):
    redir = require_login(request)
    if redir:
        return redir
    email = current_user(request)
    return templates.TemplateResponse("knowledge.html", {"request": request, "user": email, "badge": get_limits_badge(email)})


# --------- subscription ----------
@app.get("/subscription", response_class=HTMLResponse)
async def subscription_page(request: Request):
    redir = require_login(request)
    if redir:
        return redir
    email = current_user(request)
    prem = has_premium(email)
    return templates.TemplateResponse(
        "subscription.html",
        {"request": request, "user": email, "sub": prem, "is_admin": is_admin(email), "pay_error": None, "badge": get_limits_badge(email)},
    )


@app.post("/subscription/demo-activate")
async def subscription_demo_activate(request: Request):
    email = current_user(request)
    if not email:
        return RedirectResponse(url="/login", status_code=302)
    if not is_admin(email):                        # <-- критично
        return RedirectResponse(url="/subscription?msg=Forbidden", status_code=302)
    set_subscription(email, 1)                     # +SUBSCRIPTION_DAYS (30)
    return RedirectResponse(url="/subscription", status_code=302)


@app.post("/subscription/pay")
async def subscription_pay(request: Request):
    email = current_user(request)
    if not email:
        return RedirectResponse(url="/login", status_code=302)

    res = await create_nowpayments_invoice(email)
    if not res.get("ok"):
        prem = has_premium(email)
        return templates.TemplateResponse(
            "subscription.html",
            {
                "request": request,
                "user": email,
                "sub": prem,
                "is_admin": is_admin(email),
                "pay_error": str(res.get("error")),
                "badge": get_limits_badge(email),
            },
            status_code=400,
        )
    return RedirectResponse(res["url"], status_code=302)


@app.get("/subscription/success", response_class=HTMLResponse)
async def subscription_success(request: Request):
    """
    DO NOT extend subscription here.
    This page only says "Thanks"; subscription is extended ONLY via IPN after verified payment.
    """
    email = current_user(request)
    return templates.TemplateResponse("subscription_success.html", {"request": request, "user": email})


@app.post("/subscription/ipn")
async def subscription_ipn(request: Request, x_nowpayments_sig: str = Header(None)):
    """
    NOWPayments IPN handler with HMAC verification.
    We extend subscription when status is 'finished' or 'confirmed'.
    """
    secret = os.getenv("NOWPAYMENTS_IPN_SECRET", "")
    body = await request.body()

    if not secret:
        return {"ok": False, "error": "no secret configured"}

    # HMAC-SHA512 signature check
    h = hmac.new(secret.encode(), body, hashlib.sha512).hexdigest()
    if h != (x_nowpayments_sig or "").lower():
        return {"ok": False, "error": "bad signature"}

    data = json.loads(body.decode())

    payment_status = (data.get("payment_status") or "").lower()
    order_id = str(data.get("order_id") or "")

    # Extract email from order_id. Our format is "sub_<email>"
    email = ""
    if order_id.startswith("sub_"):
        try:
            email = order_id.split("_", 1)[1]
        except Exception:
            email = ""

    if payment_status in ("finished", "confirmed") and email:
        # NOTE: If you need strict idempotency, add a payments table and store processed payment_id.
        set_subscription(email, 1)  # +SUBSCRIPTION_DAYS (default 30)

    return {"ok": True}


# --------- auth ----------
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, msg: str | None = None):
    return templates.TemplateResponse("login.html", {"request": request, "msg": msg})


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, msg: str | None = None):
    return templates.TemplateResponse("register.html", {"request": request, "msg": msg})


@app.post("/register")
async def register(email: str = Form(...), password: str = Form(...)):
    ok, msg = register_user(email, password)
    if not ok:
        return RedirectResponse(url=f"/register?msg={msg.replace(' ', '%20')}", status_code=302)
    resp = RedirectResponse(url="/?msg=Welcome", status_code=302)
    set_login_cookie(resp, email)
    return resp


@app.post("/login")
async def login(email: str = Form(...), password: str = Form(...)):
    ok, msg = authenticate_user(email, password)
    if not ok:
        return RedirectResponse(url="/login?msg=Invalid%20email%20or%20password", status_code=302)
    resp = RedirectResponse(url="/?msg=Welcome", status_code=302)
    set_login_cookie(resp, email)
    return resp


@app.get("/logout")
async def logout():
    resp = RedirectResponse(url="/login?msg=Logged%20out", status_code=302)
    clear_login_cookie(resp)
    return resp


# --------- public JSON API ----------
@app.get("/api/telegram/check")
async def api_telegram_check(url: str):
    return await group_quick_check(url)


@app.get("/api/group/check")
async def api_group_check(url: str):
    return await group_quick_check(url)


@app.get("/api/check")
async def api_check(url: str):
    return await group_quick_check(url)
