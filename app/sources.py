# app/sources.py
import os
import re
import time
import uuid
import httpx
from dotenv import load_dotenv

load_dotenv()

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "")
NOWPAYMENTS_API_KEY = os.getenv("NOWPAYMENTS_API_KEY", "")
BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:8000")

# Explorer endpoints for multiple EVM chains
SCAN_BASE = {
    "ETH": "https://api.etherscan.io/api",
    "POLYGON": "https://api.polygonscan.com/api",
    "BSC": "https://api.bscscan.com/api",
    "ARB": "https://api.arbiscan.io/api",
    "OPT": "https://api-optimistic.etherscan.io/api",
    "AVAX-C": "https://api.snowtrace.io/api",
    "FTM": "https://api.ftmscan.com/api",
    "CRO": "https://api.cronoscan.com/api",
}

# Common HTTP settings
DEFAULT_TIMEOUT = 15
UA = {"User-Agent": "ScamCheck/1.0 (+support@scamcheck.app)"}


# ---------------- Wallet (EVM) ----------------
async def check_evm_wallet(addr: str, chain_code: str = "ETH") -> dict:
    base = SCAN_BASE.get(chain_code, SCAN_BASE["ETH"])
    if not ETHERSCAN_API_KEY:
        return {"ok": False, "error": "ETHERSCAN_API_KEY missing"}

    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, headers=UA) as client:
        bal_url = f"{base}?module=account&action=balance&address={addr}&tag=latest&apikey={ETHERSCAN_API_KEY}"
        bal = (await client.get(bal_url)).json()
        try:
            balance_wei = int(bal.get("result", "0"))
        except Exception:
            balance_wei = 0

        tx_url = f"{base}?module=account&action=txlist&address={addr}&page=1&offset=1&sort=desc&apikey={ETHERSCAN_API_KEY}"
        tx = (await client.get(tx_url)).json()
        tx_count = len(tx.get("result", [])) if isinstance(tx.get("result"), list) else 0

        return {"ok": True, "balance_wei": balance_wei, "balance_native": balance_wei / 1e18, "tx_count": tx_count}


# ---------------- Token: DEX info ----------------
async def token_dex_info(token_address: str) -> dict:
    url = f"https://api.dexscreener.com/latest/dex/tokens/{token_address}"
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, headers=UA) as client:
        r = await client.get(url)
        if r.status_code != 200:
            return {"ok": False, "error": f"dexscreener HTTP {r.status_code}"}
        data = r.json()
        pairs = data.get("pairs") or []
        best = None
        for p in pairs:
            if best is None or (p.get("liquidity", {}).get("usd", 0) > best.get("liquidity", {}).get("usd", 0)):
                best = p
        if not best:
            return {"ok": True, "found": False}
        return {
            "ok": True,
            "found": True,
            "pair": {
                "dex": best.get("dexId"),
                "base": best.get("baseToken", {}).get("symbol"),
                "quote": best.get("quoteToken", {}).get("symbol"),
                "priceUsd": best.get("priceUsd"),
                "liquidityUsd": best.get("liquidity", {}).get("usd"),
                "fdv": best.get("fdv"),
                "url": best.get("url"),
            },
        }


# ---------------- Token: Honeypot check ----------------
async def token_honeypot_check(token_address: str, chain: str = "eth") -> dict:
    url = f"https://api.honeypot.is/v2/IsHoneypot?address={token_address}&chain={chain}"
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, headers=UA) as client:
        r = await client.get(url)
        try:
            data = r.json()
        except Exception:
            return {"ok": False, "error": f"honeypot HTTP {r.status_code}"}
        sim = data.get("simulation", {})
        buy = sim.get("buyTax")
        sell = sim.get("sellTax")
        is_hp = bool(data.get("honeypotResult", {}).get("isHoneypot", False))
        return {"ok": True, "buyTax": buy, "sellTax": sell, "isHoneypot": is_hp, "raw": data}


# ---------------- Contract source (Etherscan family) ----------------
async def etherscan_contract_source(address: str, chain_code: str = "ETH") -> dict:
    name_map = {
        "ETHEREUM": "ETH",
        "ETH": "ETH",
        "BSC": "BSC",
        "BINANCE": "BSC",
        "POLYGON": "POLYGON",
        "MATIC": "POLYGON",
        "ARBITRUM": "ARB",
        "ARB": "ARB",
        "OPTIMISM": "OPT",
        "OPT": "OPT",
    }
    key = name_map.get((chain_code or "ETH").upper(), "ETH")
    base = SCAN_BASE.get(key, SCAN_BASE["ETH"])

    if not (isinstance(address, str) and address.startswith("0x") and len(address) == 42):
        return {
            "ok": True,
            "verified": False,
            "flags": [],
            "compiler": None,
            "license": None,
            "error": f"Invalid {key} contract address. Must be 0x + 40 hex chars.",
        }

    if not ETHERSCAN_API_KEY:
        return {"ok": True, "verified": False, "flags": [], "compiler": None, "license": None, "error": "ETHERSCAN_API_KEY missing"}

    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, headers=UA) as client:
            url = f"{base}?module=contract&action=getsourcecode&address={address}&apikey={ETHERSCAN_API_KEY}"
            r = await client.get(url)
    except Exception as e:
        return {"ok": True, "verified": False, "flags": [], "compiler": None, "license": None, "error": f"Explorer request failed: {type(e).__name__}"}

    if r.status_code != 200:
        return {"ok": True, "verified": False, "flags": [], "compiler": None, "license": None, "error": f"{key}scan HTTP {r.status_code}"}

    try:
        data = r.json()
    except Exception:
        return {"ok": True, "verified": False, "flags": [], "compiler": None, "license": None, "error": "Bad JSON from explorer"}

    result = data.get("result")

    if isinstance(result, str):
        msg = result or data.get("message") or "Explorer error"
        if "not verified" in (msg or "").lower():
            return {"ok": True, "verified": False, "flags": [], "compiler": None, "license": None, "note": msg}
        return {"ok": True, "verified": False, "flags": [], "compiler": None, "license": None, "error": msg}

    if not isinstance(result, list) or not result:
        msg = data.get("message") or "No result from explorer"
        return {"ok": True, "verified": False, "flags": [], "compiler": None, "license": None, "error": msg}

    res0 = result[0] or {}
    src = res0.get("SourceCode") or ""
    verified = bool(src)

    flags = []
    if verified:
        lowersrc = (src or "").lower()
        for p in ["blacklist", "whitelist", "pause", "mint(", "setfee", "owner()", "transferownership"]:
            if p in lowersrc:
                flags.append(p)

    return {
        "ok": True,
        "verified": verified,
        "flags": flags,
        "compiler": res0.get("CompilerVersion"),
        "license": res0.get("LicenseType"),
        "address": address,
        "chain_code": key,
        "note": None if verified else "Contract source is not verified on explorer",
    }


# ---------------- NOWPayments invoice ----------------
async def create_nowpayments_invoice(email: str) -> dict:
    """
    Create an invoice on NOWPayments for EXACT 20 USDT (TRC20):
      - price is set in crypto (usdttrc20), not in USD
      - pay_currency is USDTTRC20 (no conversion)
      - fixed rate disabled to avoid extra markup
    """
    if not NOWPAYMENTS_API_KEY:
        return {"ok": False, "error": "NOWPAYMENTS_API_KEY missing"}

    order_id = f"sub_{email}_{int(time.time())}_{uuid.uuid4().hex[:6]}"

    payload = {
        "price_amount": 20,                 # exact amount
        "price_currency": "usdttrc20",      # set price IN crypto
        "order_id": order_id,
        "order_description": "ScamCheck Premium Monthly",
        "success_url": f"{BASE_URL}/subscription/success",
        "cancel_url": f"{BASE_URL}/subscription",
        "ipn_callback_url": f"{BASE_URL}/subscription/ipn",

        "pay_currency": "USDTTRC20",        # force TRC20 USDT
        "is_fixed_rate": False,             # no rate-lock markup for crypto
    }

    headers = {"x-api-key": NOWPAYMENTS_API_KEY, "Content-Type": "application/json"}

    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, headers=headers) as client:
        r = await client.post("https://api.nowpayments.io/v1/invoice", json=payload)
        if r.status_code != 200:
            try:
                data = r.json()
            except Exception:
                data = {"error": f"NOWPayments HTTP {r.status_code}"}
            return {"ok": False, "error": data}

        try:
            data = r.json()
        except Exception:
            return {"ok": False, "error": "NOWPayments returned invalid JSON"}

        invoice_url = data.get("invoice_url")
        if invoice_url:
            return {"ok": True, "url": invoice_url, "id": data.get("id"), "order_id": order_id}
        return {"ok": False, "error": data}


# ---------------- Telegram/Discord group quick-check (mannequin rules) ----------------
TG_USER_RE = re.compile(r"(?:https?://)?(?:t\.me|telegram\.me)/([A-Za-z0-9_]{3,})$")
TG_JOIN_RE = re.compile(r"(?:https?://)?(?:t\.me|telegram\.me)/(?:\+|joinchat/)([A-Za-z0-9_\-]{6,})")
DC_INV_RE = re.compile(r"(?:https?://)?(?:discord\.gg|discord\.com/invite)/([A-Za-z0-9\-]+)")


def _label_pack(r: int):
    if r >= 70:
        return ("Risk", "red", "High probability of invalid or unsafe link.")
    if r >= 40:
        return ("Caution", "yellow", "Neutral risk level.")
    return ("Safe", "green", "No obvious red flags found.")


async def group_quick_check(url: str) -> dict:
    u = (url or "").strip()
    if not u:
        return {"ok": False, "error": "Empty link."}

    signals, tips = [], []

    # ---- Discord (invites) ----
    m_dc = DC_INV_RE.search(u)
    if m_dc:
        dc_code = m_dc.group(1)
        signals.append("Detected platform: Discord")
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, headers=UA, follow_redirects=True) as client:
            api = f"https://discord.com/api/v9/invites/{dc_code}?with_counts=true&with_expiration=true"
            r = await client.get(api)
            if r.status_code == 404:
                return {
                    "ok": True,
                    "platform": "Discord",
                    "url": u,
                    "risk": 85,
                    "label": "Risk",
                    "color": "red",
                    "summary": "Discord invite is invalid or expired.",
                    "signals": signals + ["Discord API: invite not found (404)"],
                    "tips": ["Ask admins for a fresh invite", "Check official site/socials for links"],
                }
            if r.status_code != 200:
                return {
                    "ok": True,
                    "platform": "Discord",
                    "url": u,
                    "risk": 55,
                    "label": "Caution",
                    "color": "yellow",
                    "summary": f"Discord API returned {r.status_code}",
                    "signals": signals,
                    "tips": ["Try again later"],
                }
            data = r.json()
            approx = int(data.get("approximate_member_count") or 0)
            online = int(data.get("approximate_presence_count") or 0)
            risk = 50 if approx >= 100 else (75 if approx < 10 else 55)
            L, C, S = _label_pack(risk)
            return {
                "ok": True,
                "platform": "Discord",
                "url": u,
                "risk": risk,
                "label": L,
                "color": C,
                "summary": S,
                "signals": signals + [f"Members ~ {approx}, Online ~ {online}"],
                "tips": ["Check pinned rules and roles", "Do not DM unknown users"],
            }

    # ---- Telegram ----
    m_tg_join = TG_JOIN_RE.search(u)
    m_tg_user = TG_USER_RE.search(u)

    if not (m_tg_join or m_tg_user):
        return {"ok": False, "error": "Provide a valid Telegram link (t.me/<username> or t.me/+invite)."}

    signals.append("Detected platform: Telegram")

    if m_tg_join:
        risk = 50
        L, C, S = _label_pack(risk)
        return {
            "ok": True,
            "platform": "Telegram",
            "type": "invite",
            "url": u,
            "risk": risk,
            "label": L,
            "color": C,
            "summary": "Group/Channel (invite)",
            "signals": signals + ["Invite link pattern (+/joinchat)"],
            "tips": ["Open in Telegram app and verify admins"],
        }

    username = m_tg_user.group(1)
    try:
        async with httpx.AsyncClient(timeout=10, headers=UA, follow_redirects=True) as client:
            r = await client.get(f"https://t.me/{username}")
            text = (r.text or "").lower()
    except Exception:
        risk = 45
        L, C, S = _label_pack(risk)
        return {
            "ok": True,
            "platform": "Telegram",
            "type": "user",
            "url": u,
            "risk": risk,
            "label": L,
            "color": C,
            "summary": "Personal account",
            "signals": signals + ["Network error — mannequin fallback"],
            "tips": ["Open in Telegram app to verify profile"],
        }

    nf = (r.status_code in (404, 410)) or ("was not found" in text) or ("page not found" in text) or ("not found" in text)
    if nf:
        risk = 85
        L, C, S = _label_pack(risk)
        return {
            "ok": True,
            "platform": "Telegram",
            "type": "user_or_chat_missing",
            "url": u,
            "risk": risk,
            "label": L,
            "color": C,
            "summary": "User not found",
            "signals": signals + [f"Username @{username} not found on t.me"],
            "tips": ["Check spelling or share a correct link"],
        }

    is_chat = any(s in text for s in ("tgme_channel_history", "tgme_channel_info", "join channel", "join group"))
    if is_chat:
        risk = 50
        L, C, S = _label_pack(risk)
        return {
            "ok": True,
            "platform": "Telegram",
            "type": "chat",
            "url": u,
            "risk": risk,
            "label": L,
            "color": C,
            "summary": "Group/Channel",
            "signals": signals + ["Channel/group markers on page"],
            "tips": ["Open in Telegram app and verify admins"],
        }

    risk = 45
    L, C, S = _label_pack(risk)
    return {
        "ok": True,
        "platform": "Telegram",
        "type": "user",
        "url": u,
        "risk": risk,
        "label": L,
        "color": C,
        "summary": "Personal account",
        "signals": signals + ["Username page reachable — treated as personal account"],
        "tips": ["Open in Telegram app to verify profile"],
    }
