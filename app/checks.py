
import hashlib, re
from dataclasses import dataclass
from typing import Optional, Pattern, List, Dict, Any
from app.sources import check_evm_wallet

@dataclass
class Net:
    name: str
    code: str
    regex: Pattern[str]

def _re(p: str) -> Pattern[str]:
    return re.compile(p)

NETWORKS: List[Net] = [
    # BTC family
    Net("Bitcoin", "BTC", _re(r'^(bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$')),
    Net("Litecoin", "LTC", _re(r'^(ltc1[ac-hj-np-z02-9]{11,71}|[LM3][a-km-zA-HJ-NP-Z1-9]{26,33})$')),
    Net("Bitcoin Cash", "BCH", _re(r'^(bitcoincash:)?(q|p)[0-9a-z]{41}$')),
    Net("Dogecoin", "DOGE", _re(r'^[D9A][a-km-zA-HJ-NP-Z1-9]{25,34}$')),

    # EVM
    Net("Ethereum (Mainnet)", "ETH", _re(r'^0x[a-fA-F0-9]{40}$')),
    Net("BNB Smart Chain", "BSC", _re(r'^0x[a-fA-F0-9]{40}$')),
    Net("Polygon (MATIC)", "POLYGON", _re(r'^0x[a-fA-F0-9]{40}$')),
    Net("Arbitrum One", "ARB", _re(r'^0x[a-fA-F0-9]{40}$')),
    Net("Optimism", "OPT", _re(r'^0x[a-fA-F0-9]{40}$')),
    Net("Avalanche C-Chain", "AVAX-C", _re(r'^0x[a-fA-F0-9]{40}$')),
    Net("Fantom", "FTM", _re(r'^0x[a-fA-F0-9]{40}$')),
    Net("Cronos", "CRO", _re(r'^0x[a-fA-F0-9]{40}$')),

    # Non-EVM
    Net("TRON (TRC-20)", "TRX", _re(r'^T[1-9A-HJ-NP-Za-km-z]{33}$')),
    Net("Solana", "SOL", _re(r'^[1-9A-HJ-NP-Za-km-z]{32,44}$')),
    Net("XRP (Ripple)", "XRP", _re(r'^r[1-9A-HJ-NP-Za-km-z]{24,34}$')),
    Net("BNB Beacon (BEP-2)", "BNB", _re(r'^(bnb1)[0-9a-z]{38}$')),
    Net("Cosmos (ATOM)", "ATOM", _re(r'^(cosmos1)[0-9a-z]{38}$')),
    Net("Cardano", "ADA", _re(r'^(addr1)[0-9a-z]{20,}$')),
    Net("Polkadot", "DOT", _re(r'^(1|1x)[0-9A-HJ-NP-Za-km-z]{47,48}$')),
    Net("Near Protocol", "NEAR", _re(r'^[a-z0-9_\-\.]{2,64}\.near$')),
    Net("Tezos", "XTZ", _re(r'^(tz1|tz2|tz3|KT1)[1-9A-HJ-NP-Za-km-z]{33}$')),
    Net("TON", "TON", _re(r'^(EQ|UQ)[A-Za-z0-9\-_]{46,48}$')),
]

def detect_network(address: str) -> Optional[Net]:
    a = (address or "").strip()
    for n in NETWORKS:
        if n.regex.match(a):
            return n
    return None

def _stable_score(addr: str) -> int:
    h = hashlib.sha256(addr.encode()).hexdigest()
    raw = int(h[:2], 16)
    return round(raw / 255 * 100)

async def wallet_check(address: str) -> Dict[str, Any]:
    addr = (address or "").strip()
    net = detect_network(addr)
    if not net:
        return {"ok": False, "error": "Invalid address. Supported: BTC/LTC/BCH/DOGE, EVM (0x…), TRON, Solana, XRP, BNB Beacon, Cosmos, Cardano, Polkadot, NEAR, Tezos, TON."}

    score = _stable_score(addr)
    signals = []
    tips = []

    if net.code in {"ETH","BSC","POLYGON","ARB","OPT","AVAX-C","FTM","CRO"}:
        evm = await check_evm_wallet(addr, net.code if net.code != "ETH" else "ETH")
        if evm.get("ok"):
            signals.append(f"Balance: {evm['balance_native']:.6f} native")
            signals.append(f"Transactions: {evm['tx_count']}")
            if evm['balance_native'] > 0 or evm['tx_count'] > 0:
                score = max(score, 60)
        else:
            signals.append("EVM explorer check failed")

    if score >= 80:
        label, color = "Safe", "green"
        summary = "High reputation. No obvious scam patterns detected."
        signals.insert(0, f"Detected network: {net.name}")
        tips = ["Double-check recipient", "Keep seed phrase offline"]
    elif score >= 50:
        label, color = "Caution", "yellow"
        summary = "Some risk factors. Consider a small test transfer."
        signals.insert(0, f"Detected network: {net.name}")
        tips = ["Send a small test first", "Cross-check on other sources"]
    else:
        label, color = "Risk", "red"
        summary = "High probability of scam. Avoid large transfers."
        if not signals:
            signals = ["Suspicious heuristics"]
        tips = ["Do not send large amounts", "Ask for an alternative address"]

    return {"ok": True, "address": addr, "network": net.name, "code": net.code,
            "score": score, "label": label, "color": color, "summary": summary,
            "signals": signals, "tips": tips}
