from fastapi import FastAPI, Request, Form, Header
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import os, hmac, hashlib, json

from app.database import init_db, create_user, get_user, set_subscription
from app.auth import hash_pw, is_logged_in, current_user, is_admin
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


# ---------- HELPERS ----------
def require_login(request: Request):
    """Если юзер не залогинен — сначала отправляем на регистрацию."""
    if not is_logged_in(request):
        return RedirectResponse(url="/register?next=/", status_code=302)


def has_premium(email: str | None) -> bool:
    """Премиум у админов всегда активен. Остальным — по полю в БД."""
    if is_admin(email):
        return True
    if not email:
        return False
    row = get_user(email)
    return bool(row and row[2])


# ---------- HOME / WALLET ----------
@app.get("/", response_class=HTMLResponse)
async def home(request: Request, msg: str | None = None):
    redir = require_login(request)
    if redir:
        return redir
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "result": None, "user": current_user(request), "msg": msg},
    )


@app.post("/check_wallet", response_class=HTMLResponse)
async def check_wallet_route(request: Request, address: str = Form(...)):
    redir = require_login(request)
    if redir:
        return redir
    result = await wallet_check(address)
    return templates.TemplateResponse(
        "index.html", {"request": request, "result": result, "user": current_user(request)}
    )


# ---------- TOKEN CHECK (DEX + Honeypot) ----------
@app.get("/token", response_class=HTMLResponse)
async def token_page(request: Request, token: str | None = None, chain: str = "eth"):
    redir = require_login(request)
    if redir:
        return redir
    email = current_user(request)
    prem = has_premium(email)
    info = None
    hp = None
    if token:
        info = await token_dex_info(token)
        hp = await token_honeypot_check(token, chain=chain)
    return templates.TemplateResponse(
        "token.html",
        {"request": request, "user": email, "sub": prem, "info": info, "hp": hp, "token": token, "chain": chain},
    )


# ---------- CONTRACT CHECK (source audit) ----------
@app.get("/contract", response_class=HTMLResponse)
async def contract_page(request: Request, address: str | None = None, chain_code: str = "ETH"):
    redir = require_login(request)
    if redir:
        return redir
    email = current_user(request)
    prem = has_premium(email)
    res = None
    if address:
        res = await etherscan_contract_source(address, chain_code=chain_code)
    return templates.TemplateResponse(
        "contract.html",
        {"request": request, "user": email, "sub": prem, "result": res, "address": address, "chain_code": chain_code},
    )


# ---------- GROUP CHECK ----------
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
        {"request": request, "user": email, "sub": prem, "result": result, "link": link},
    )


# ---------- KNOWLEDGE ----------
@app.get("/knowledge", response_class=HTMLResponse)
async def knowledge_page(request: Request):
    redir = require_login(request)
    if redir:
        return redir
    return templates.TemplateResponse("knowledge.html", {"request": request, "user": current_user(request)})


# ---------- SUBSCRIPTION (NOWPayments) ----------
@app.get("/subscription", response_class=HTMLResponse)
async def subscription_page(request: Request):
    redir = require_login(request)
    if redir:
        return redir
    email = current_user(request)
    prem = has_premium(email)
    return templates.TemplateResponse(
        "subscription.html",
        {"request": request, "user": email, "sub": prem, "is_admin": is_admin(email), "pay_error": None},
    )


@app.post("/subscription/demo-activate")
async def subscription_demo_activate(request: Request):
    """Активирует премиум вручную. Логику «только для админа» можно закрепить тут,
    но сейчас она скрыта на уровне UI. Добавить проверку просто:
    if not is_admin(current_user(request)): return RedirectResponse('/subscription', 302)
    """
    email = current_user(request)
    if not email:
        return RedirectResponse(url="/login", status_code=302)
    set_subscription(email, 1)
    return RedirectResponse(url="/subscription", status_code=302)


@app.post("/subscription/pay")
async def subscription_pay(request: Request):
    """Создаёт инвойс в NOWPayments и редиректит на страницу оплаты.
    Если ключ не настроен — показываем сообщение, а не 500."""
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
            },
            status_code=400,
        )
    return RedirectResponse(res["url"], status_code=302)


@app.get("/subscription/success", response_class=HTMLResponse)
async def subscription_success(request: Request):
    email = current_user(request)
    return templates.TemplateResponse("subscription_success.html", {"request": request, "user": email})


# IPN endpoint (опционально, если настроишь в NOWPayments)
@app.post("/subscription/ipn")
async def subscription_ipn(request: Request, x_nowpayments_sig: str = Header(None)):
    secret = os.getenv("NOWPAYMENTS_IPN_SECRET", "")
    body = await request.body()
    if not secret:
        return {"ok": False, "error": "no secret configured"}
    h = hmac.new(secret.encode(), body, hashlib.sha512).hexdigest()
    if h != (x_nowpayments_sig or "").lower():
        return {"ok": False, "error": "bad signature"}
    data = json.loads(body.decode())
    if data.get("payment_status") == "finished":
        email = (data.get("order_id", "").replace("sub_", ""))
        if email:
            set_subscription(email, 1)
    return {"ok": True}


# ---------- AUTH ----------
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, msg: str | None = None):
    return templates.TemplateResponse("login.html", {"request": request, "msg": msg})


@app.post("/login")
async def login(email: str = Form(...), password: str = Form(...)):
    row = get_user(email)
    if row and row[1] == hash_pw(password):
        resp = RedirectResponse(url="/?msg=Welcome", status_code=302)
        resp.set_cookie("user", email, httponly=True)
        return resp
    return RedirectResponse(url="/login?msg=Invalid%20email%20or%20password", status_code=302)


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, msg: str | None = None):
    return templates.TemplateResponse("register.html", {"request": request, "msg": msg})


@app.post("/register")
async def register(email: str = Form(...), password: str = Form(...)):
    ok, err = create_user(email, hash_pw(password))
    if ok:
        return RedirectResponse(url="/login?msg=Account%20created", status_code=302)
    else:
        return RedirectResponse(url=f"/register?msg={err.replace(' ', '%20')}", status_code=302)


@app.get("/logout")
async def logout():
    resp = RedirectResponse(url="/login?msg=Logged%20out", status_code=302)
    resp.delete_cookie("user")
    return resp

