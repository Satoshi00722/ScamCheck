import os
import re
import httpx
from dotenv import load_dotenv

load_dotenv()

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "")
NOWPAYMENTS_API_KEY = os.getenv("NOWPAYMENTS_API_KEY", "")
BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:8000")

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


async def check_evm_wallet(addr: str, chain_code: str = "ETH") -> dict:
    base = SCAN_BASE.get(chain_code, SCAN_BASE["ETH"])
    if not ETHERSCAN_API_KEY:
        return {"ok": False, "error": "ETHERSCAN_API_KEY missing"}
    async with httpx.AsyncClient(timeout=12) as client:
        bal_url = f"{base}?module=account&action=balance&address={addr}&tag=latest&apikey={ETHERSCAN_API_KEY}"
        bal = (await client.get(bal_url)).json()
        try:
            balance_wei = int(bal.get("result", "0"))
        except ValueError:
            balance_wei = 0

        tx_url = f"{base}?module=account&action=txlist&address={addr}&page=1&offset=1&sort=desc&apikey={ETHERSCAN_API_KEY}"
        tx = (await client.get(tx_url)).json()
        tx_count = len(tx.get("result", [])) if isinstance(tx.get("result"), list) else 0

        return {
            "ok": True,
            "balance_wei": balance_wei,
            "balance_native": balance_wei / 1e18,
            "tx_count": tx_count,
        }


async def token_dex_info(token_address: str) -> dict:
    # Dexscreener API — без ключа
    url = f"https://api.dexscreener.com/latest/dex/tokens/{token_address}"
    async with httpx.AsyncClient(timeout=12) as client:
        r = await client.get(url)
        if r.status_code != 200:
            return {"ok": False, "error": f"dexscreener {r.status_code}"}
        data = r.json()
        pairs = data.get("pairs") or []
        best = None
        for p in pairs:
            if best is None or (
                p.get("liquidity", {}).get("usd", 0)
                > best.get("liquidity", {}).get("usd", 0)
            ):
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


async def token_honeypot_check(token_address: str, chain: str = "eth") -> dict:
    # Honeypot.is — публичный эндпоинт
    url = f"https://api.honeypot.is/v2/IsHoneypot?address={token_address}&chain={chain}"
    async with httpx.AsyncClient(timeout=12) as client:
        r = await client.get(url)
        try:
            data = r.json()
        except Exception:
            return {"ok": False, "error": f"honeypot {r.status_code}"}
        sim = data.get("simulation", {})
        buy = sim.get("buyTax")
        sell = sim.get("sellTax")
        is_hp = bool(data.get("honeypotResult", {}).get("isHoneypot", False))
        return {
            "ok": True,
            "buyTax": buy,
            "sellTax": sell,
            "isHoneypot": is_hp,
            "raw": data,
        }


async def etherscan_contract_source(address: str, chain_code: str = "ETH") -> dict:
    # <-- ЭТА функция нужна main.py
    base = SCAN_BASE.get(chain_code, SCAN_BASE["ETH"])
    if not ETHERSCAN_API_KEY:
        return {"ok": False, "error": "ETHERSCAN_API_KEY missing"}
    async with httpx.AsyncClient(timeout=15) as client:
        url = f"{base}?module=contract&action=getsourcecode&address={address}&apikey={ETHERSCAN_API_KEY}"
        r = await client.get(url)
        data = r.json()
        res = (data.get("result") or [{}])[0]
        src = res.get("SourceCode") or ""
        verified = bool(src)
        flags = []
        lowersrc = src.lower()
        danger_patterns = [
            "blacklist",
            "whitelist",
            "pause",
            "mint(",
            "setfee",
            "owner()",
            "transferownership",
        ]
        for p in danger_patterns:
            if p in lowersrc:
                flags.append(p)
        return {
            "ok": True,
            "verified": verified,
            "flags": flags,
            "compiler": res.get("CompilerVersion"),
            "license": res.get("LicenseType"),
        }


async def create_nowpayments_invoice(email: str) -> dict:
    if not NOWPAYMENTS_API_KEY:
        return {"ok": False, "error": "NOWPAYMENTS_API_KEY missing"}
    payload = {
        "price_amount": 20,
        "price_currency": "usd",
        "order_id": f"sub_{email}",
        "order_description": "ScamCheck Premium Monthly",
        "success_url": f"{BASE_URL}/subscription/success",
        "cancel_url": f"{BASE_URL}/subscription",
        "ipn_callback_url": f"{BASE_URL}/subscription/ipn",
    }
    headers = {"x-api-key": NOWPAYMENTS_API_KEY, "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(
            "https://api.nowpayments.io/v1/invoice", headers=headers, json=payload
        )
        try:
            data = r.json()
        except Exception:
            return {"ok": False, "error": f"NOWPayments {r.status_code}"}
        if "invoice_url" in data:
            return {"ok": True, "url": data["invoice_url"], "id": data.get("id")}
        return {"ok": False, "error": data}


# -------- УМНЫЙ GROUP CHECK (Telegram/Discord + эвристики) --------
async def group_quick_check(url: str) -> dict:
    """
    Smart group checker:
    - Discord: публичный invite API (with_counts/with_expiration) -> members/online, expired/invalid
    - Telegram: парсинг публичной страницы t.me для признаков валидности
    - Общие эвристики: шортнеры, ключевые слова (airdrop/bonus/claim...), http, странные коды
    """
    u = (url or "").strip()
    if not u:
        return {"ok": False, "error": "Empty link."}

    # стартовые эвристики
    risk = 10
    signals = []
    tips = []

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "cutt.ly",
        "goo.gl",
        "t.co",
        "rb.gy",
        "is.gd",
        "s.id",
        "linktr.ee",
    ]
    if any(s in u.lower() for s in shorteners):
        risk = max(risk, 60)
        signals.append("Link uses a URL shortener (hides destination)")

    bad_kw = ["airdrop", "claim", "bonus", "double", "giveaway", "support", "unlock", "free", "fast profit"]
    if any(k in u.lower() for k in bad_kw):
        risk = max(risk, 55)
        signals.append("Suspicious keywords in link")

    if u.startswith("http://"):
        risk = max(risk, 40)
        signals.append("Insecure http link")

    # распознаём платформу
    tg_user = None
    tg_join = None
    dc_code = None

    m_tg_user = re.search(r"(?:https?://)?(?:t\.me|telegram\.me)/([A-Za-z0-9_]{3,})$", u)
    m_tg_join = re.search(r"(?:https?://)?(?:t\.me|telegram\.me)/\+([A-Za-z0-9_\-]{6,})", u)
    m_dc = re.search(r"(?:https?://)?(?:discord\.gg|discord\.com/invite)/([A-Za-z0-9\-]+)", u)

    if m_tg_join:
        platform = "Telegram"
        tg_join = m_tg_join.group(1)
    elif m_tg_user:
        platform = "Telegram"
        tg_user = m_tg_user.group(1)
    elif m_dc:
        platform = "Discord"
        dc_code = m_dc.group(1)
    else:
        return {"ok": False, "error": "Provide a valid Telegram/Discord invite link."}

    signals.append(f"Detected platform: {platform}")

    try:
        async with httpx.AsyncClient(timeout=12, headers={"User-Agent": "ScamCheck/1.0"}) as client:
            if dc_code:
                # Discord official invite endpoint
                api = f"https://discord.com/api/v9/invites/{dc_code}?with_counts=true&with_expiration=true"
                r = await client.get(api)
                if r.status_code == 404:
                    risk = max(risk, 80)
                    return {
                        "ok": True,
                        "platform": "Discord",
                        "url": u,
                        "risk": risk,
                        "label": "Risk",
                        "color": "red",
                        "summary": "Discord invite is invalid or expired.",
                        "signals": signals + ["Discord API: invite not found (404)"],
                        "tips": ["Ask admins for a fresh invite", "Check official site/socials for links"],
                    }
                if r.status_code != 200:
                    risk = max(risk, 50)
                    signals.append(f"Discord API returned {r.status_code}")
                else:
                    data = r.json()
                    approx = data.get("approximate_member_count") or 0
                    online = data.get("approximate_presence_count") or 0
                    expires = data.get("expires_at")
                    verif = data.get("guild", {}).get("verification_level")

                    if approx < 10:
                        risk = max(risk, 70)
                        signals.append("Very small server (members < 10)")
                    elif approx < 100:
                        risk = max(risk, 45)
                        signals.append("Small server (members < 100)")

                    if expires is not None:
                        signals.append("Invite has expiration set")
                    if verif is not None and verif == 0:
                        risk = max(risk, 40)
                        signals.append("Low verification level in guild")

                    tips += ["Check pinned rules and roles", "Do not DM unknown users"]

                    label, color, summary = (
                        ("Risk", "red", "High probability of spam/bots.") if risk >= 60
                        else ("Caution", "yellow", "Some risk indicators were detected.") if risk >= 40
                        else ("Safe", "green", "No obvious red flags found.")
                    )

                    return {
                        "ok": True,
                        "platform": "Discord",
                        "url": u,
                        "risk": risk,
                        "label": label,
                        "color": color,
                        "summary": summary,
                        "signals": signals + [f"Members ~ {approx}, Online ~ {online}"],
                        "tips": tips,
                    }

            # Telegram: пробуем загрузить страницу t.me
            page = f"https://t.me/{tg_user}" if tg_user else f"https://t.me/+{tg_join}"
            r = await client.get(page, follow_redirects=True)
            text = r.text.lower() if r.text else ""

            if "invite link is invalid" in text or "link is invalid" in text or r.status_code in (404, 410):
                risk = max(risk, 80)
                summary = "Telegram invite appears invalid or expired."
                label, color = "Risk", "red"
                signals.append(f"HTTP {r.status_code} on t.me")
            else:
                if "join channel" in text or "join group" in text or "view in telegram" in text:
                    signals.append("Page is reachable on t.me")
                summary = "No obvious red flags found."
                label, color = (
                    ("Risk", "red") if risk >= 60 else
                    ("Caution", "yellow") if risk >= 40 else
                    ("Safe", "green")
                )

            tips += ["Open in Telegram app and verify admins", "Beware of fake support accounts"]

            return {
                "ok": True,
                "platform": "Telegram",
                "url": u,
                "risk": risk,
                "label": label,
                "color": color,
                "summary": summary,
                "signals": signals,
                "tips": tips,
            }

    except Exception as e:
        # сеть упала — вернём эвристическую оценку
        risk = max(risk, 40)
        return {
            "ok": True,
            "platform": "Discord" if dc_code else "Telegram",
            "url": u,
            "risk": risk,
            "label": "Caution",
            "color": "yellow",
            "summary": "Network error while checking link; using heuristics only.",
            "signals": signals + [f"Exception: {type(e).__name__}"],
            "tips": ["Try again later", "Verify link in the official website/socials"],
        }
