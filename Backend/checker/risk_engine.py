"""
TraceHost ThreatVector Engine
Multi-factor domain risk scoring with entropy analysis, brand impersonation
detection, infrastructure profiling, and registration intelligence.
"""

import math
import re
from datetime import datetime, timezone as _tz

import logging

logger = logging.getLogger(__name__)

# ── Threat Intelligence Data ──────────────────────────────────────────────────

POPULAR_BRANDS = [
    "google", "facebook", "paypal", "amazon", "apple", "microsoft", "netflix",
    "instagram", "twitter", "linkedin", "youtube", "yahoo", "ebay", "walmart",
    "chase", "bankofamerica", "wellsfargo", "citibank", "dropbox", "adobe",
    "spotify", "discord", "steam", "roblox", "tiktok", "snapchat", "whatsapp",
    "telegram", "zoom", "slack", "github", "gitlab", "wordpress", "shopify",
    "stripe", "coinbase", "binance", "blockchain", "office365", "onedrive",
    "icloud", "outlook", "hotmail", "gmail", "protonmail", "cloudflare",
    "godaddy", "namecheap", "bluehost", "hostgator", "siteground",
]

PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "logon", "account", "verify", "verification",
    "secure", "security", "update", "confirm", "banking", "payment", "invoice",
    "billing", "support", "helpdesk", "service", "customer", "portal", "wallet",
    "reset", "password", "credential", "access", "authenticate", "recovery",
    "suspended", "unusual", "activity", "limited", "unlock", "validate",
]

# Risk points per TLD (higher = riskier)
HIGH_RISK_TLDS = {
    ".tk": 9, ".ml": 9, ".ga": 9, ".cf": 9, ".gq": 9,
    ".xyz": 6, ".top": 6, ".click": 7, ".loan": 8, ".work": 5,
    ".online": 4, ".site": 4, ".info": 3, ".biz": 3, ".club": 4,
    ".space": 5, ".icu": 7, ".vip": 5, ".win": 7, ".download": 8,
    ".stream": 6, ".gdn": 7, ".racing": 7, ".date": 7, ".faith": 7,
    ".review": 6, ".accountant": 7, ".men": 6, ".trade": 6,
    ".cricket": 7, ".party": 6, ".science": 5, ".webcam": 7,
}

TRUSTED_TLDS = [".edu", ".gov", ".ac", ".sch", ".mil", ".int"]

# Ports that indicate malicious or highly exposed infrastructure
HIGH_RISK_PORTS = {
    4444: 10, 1337: 8, 31337: 10,  # Common backdoor/RAT ports
    3389: 7,   # RDP — remote desktop exposure
    5900: 6,   # VNC — desktop exposure
    23: 7,     # Telnet — unencrypted remote access
    135: 6, 137: 5, 445: 8,  # Windows SMB/NetBIOS (WannaCry vector)
    1433: 6, 3306: 5, 5432: 5,  # Exposed databases
    6379: 7,   # Redis — often unauthenticated
    9200: 6,   # Elasticsearch
    2375: 9,   # Docker API exposed
    2222: 5,   # Non-standard SSH
}

# Known bulletproof hosting ASN prefixes
BULLETPROOF_ASNS = [
    "AS40676", "AS29073", "AS60404", "AS202425", "AS206898",
    "AS9002", "AS48282", "AS197414", "AS47142", "AS35624",
    "AS209588", "AS59711", "AS31034", "AS62282",
]

# Country risk weights (elevated — not definitive)
HIGH_RISK_COUNTRIES = {
    "KP": 10,  # North Korea — state-sponsored threats
    "IR": 8,   # Iran
    "CN": 6,   # China
    "RU": 6,   # Russia
    "NG": 5,   # Nigeria
    "UA": 4,   # Ukraine
    "RO": 3,   # Romania
    "BG": 3,   # Bulgaria
    "KZ": 4,   # Kazakhstan
    "BY": 5,   # Belarus
}


# ── Core Algorithms ───────────────────────────────────────────────────────────

def calculate_entropy(text: str) -> float:
    """Shannon entropy — high value suggests algorithmically generated domain."""
    if not text:
        return 0.0
    freq: dict = {}
    for ch in text.lower():
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def levenshtein_distance(s1: str, s2: str) -> int:
    """Edit distance between two strings (Levenshtein)."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def find_brand_similarity(domain: str):
    """
    Return brand impersonation details if the domain closely resembles
    a popular brand, or None if no match.
    Detects both close-spelling variants and embedded brand names.
    """
    parts = domain.lower().split(".")
    sld = parts[-2] if len(parts) >= 2 else domain.lower()

    # 1. Exact SLD == brand → legitimate, skip
    for brand in POPULAR_BRANDS:
        if sld == brand:
            return None

    # 2. Brand name embedded in SLD (e.g., "microsoft-verify", "secure-paypal-login")
    #    Only flag if the sld is longer than the brand (otherwise it IS the brand)
    for brand in POPULAR_BRANDS:
        if len(brand) < 5:
            continue
        if brand in sld and len(sld) > len(brand):
            # Calculate how much of the sld the brand occupies
            coverage = round(len(brand) / len(sld) * 100)
            return {
                "brand": brand,
                "distance": 0,
                "similarity": max(75, coverage),
            }

    # 3. Typosquat: strip common phishing pre/suffixes and check edit distance
    stripped = sld
    for prefix in ["secure-", "login-", "account-", "my-", "www-", "mail-", "verify-", "signin-"]:
        if stripped.startswith(prefix):
            stripped = stripped[len(prefix):]
    for suffix in ["-verify", "-login", "-secure", "-account", "-signin", "-support"]:
        if stripped.endswith(suffix):
            stripped = stripped[: -len(suffix)]

    best: dict | None = None
    best_dist = float("inf")
    for brand in POPULAR_BRANDS:
        if len(stripped) < 3 or len(brand) < 3:
            continue
        if stripped == brand:
            return None
        dist = levenshtein_distance(stripped, brand)
        ratio = dist / max(len(stripped), len(brand))
        if (dist <= 2 or ratio <= 0.25) and dist < best_dist:
            best_dist = dist
            best = {
                "brand": brand,
                "distance": dist,
                "similarity": round((1 - ratio) * 100),
            }
    return best


def check_homograph_attack(domain: str) -> bool:
    """Detect IDN homograph attacks (non-ASCII Unicode characters)."""
    try:
        domain.encode("ascii")
        return False
    except UnicodeEncodeError:
        return True


def _parse_date(val) -> datetime | None:
    """Safely parse a date from string or datetime."""
    if val is None:
        return None
    if isinstance(val, datetime):
        return val
    if isinstance(val, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
            try:
                return datetime.strptime(val.split("+")[0].split("Z")[0], fmt)
            except ValueError:
                continue
    return None


# ── Main Scoring Engine ───────────────────────────────────────────────────────

def calculate_advanced_risk_score(
    domain: str,
    whois_info: dict,
    dns_info,
    asn_info: dict,
    shodan_info: dict | None = None,
) -> tuple[int, dict]:
    """
    ThreatVector Engine: score a domain 0–100 across four categories.

    Returns
    -------
    (score: int, breakdown: dict)
        breakdown contains per-category scores, factor lists, and auxiliary data.
    """
    domain_lower = domain.lower()
    entropy = 0.0

    # ── Trusted TLD fast path ─────────────────────────────────────────────────
    if any(domain_lower.endswith(tld) for tld in TRUSTED_TLDS):
        return 8, {
            "domain_name":   {"score": 0, "max": 30, "factors": []},
            "registration":  {"score": 0, "max": 25, "factors": []},
            "infrastructure":{"score": 0, "max": 25, "factors": []},
            "dns_analysis":  {"score": 0, "max": 20, "factors": []},
            "total": 8,
            "entropy": 0.0,
            "override": "Trusted institutional TLD (.edu/.gov/.mil) — low risk baseline",
        }

    # ── CATEGORY 1: Domain Name Analysis (0–30) ───────────────────────────────
    name_score = 0
    name_factors: list[str] = []

    sld = domain_lower.split(".")[-2] if "." in domain_lower else domain_lower
    entropy = calculate_entropy(sld)

    # 1a. Shannon entropy — DGA domain generation detection
    if entropy > 3.5:
        pts = min(10, int((entropy - 3.5) * 6))
        name_score += pts
        name_factors.append(
            f"High entropy ({entropy:.2f} bits) — likely algorithmically generated (+{pts})"
        )

    # 1b. Brand impersonation (phishing similarity)
    brand_match = find_brand_similarity(domain_lower)
    if brand_match:
        pts = min(15, max(5, 15 - brand_match["distance"] * 4))
        name_score += pts
        name_factors.append(
            f"Resembles brand '{brand_match['brand']}' "
            f"({brand_match['similarity']}% similarity, edit dist {brand_match['distance']}) (+{pts})"
        )

    # 1c. Phishing keywords in domain string
    found_kw = [kw for kw in PHISHING_KEYWORDS if kw in domain_lower]
    if found_kw:
        pts = min(10, len(found_kw) * 4)
        name_score += pts
        name_factors.append(
            f"Phishing keywords detected: {', '.join(found_kw[:4])} (+{pts})"
        )

    # 1d. High-risk TLD
    for tld, pts in HIGH_RISK_TLDS.items():
        if domain_lower.endswith(tld):
            name_score += pts
            name_factors.append(f"High-risk TLD '{tld}' used (+{pts})")
            break

    # 1e. Excessive hyphens (common in spoofed domains)
    hyphen_count = sld.count("-")
    if hyphen_count >= 2:
        pts = min(6, hyphen_count * 2)
        name_score += pts
        name_factors.append(f"{hyphen_count} hyphens in second-level domain (+{pts})")

    # 1f. IDN homograph attack
    if check_homograph_attack(domain):
        name_score += 15
        name_factors.append("Unicode IDN homograph attack detected (+15)")

    # 1g. Numeric substitution (g00gle, paypa1)
    digits_in_sld = sum(1 for c in sld if c.isdigit())
    digit_ratio = digits_in_sld / max(len(sld), 1)
    if digit_ratio > 0.3 and len(sld) > 3:
        pts = min(5, int(digit_ratio * 10))
        name_score += pts
        name_factors.append(
            f"High digit ratio in domain name ({digit_ratio:.0%}) — possible leet substitution (+{pts})"
        )

    cat1 = min(30, name_score)

    # ── CATEGORY 2: Registration Intelligence (0–25) ──────────────────────────
    reg_score = 0
    reg_factors: list[str] = []

    creation_dt = _parse_date(whois_info.get("creation_date"))
    if creation_dt:
        if creation_dt.tzinfo is None:
            creation_dt = creation_dt.replace(tzinfo=_tz.utc)
        age_days = (datetime.now(_tz.utc) - creation_dt).days

        if age_days < 30:
            pts = 20
            reg_factors.append(f"Domain is only {age_days} days old — extremely new (+{pts})")
        elif age_days < 90:
            pts = 14
            reg_factors.append(f"Domain is {age_days} days old — very new (+{pts})")
        elif age_days < 180:
            pts = 8
            reg_factors.append(f"Domain is {age_days} days old — new (+{pts})")
        elif age_days < 365:
            pts = 4
            reg_factors.append(f"Domain is {age_days} days old — less than 1 year (+{pts})")
        else:
            pts = 0
        reg_score += pts
    else:
        reg_score += 8
        reg_factors.append("Registration date unavailable — possible WHOIS shield (+8)")

    if not whois_info.get("registrar"):
        reg_score += 6
        reg_factors.append("Registrar information missing (+6)")

    if not whois_info.get("registrant_organization") and not whois_info.get("registrant_name"):
        reg_score += 4
        reg_factors.append("Registrant identity hidden (privacy protection active) (+4)")

    # Short registration window (attackers often register for 1 year max)
    exp_dt = _parse_date(whois_info.get("expiration_date"))
    if exp_dt and creation_dt:
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=_tz.utc)
        reg_days = (exp_dt - creation_dt).days
        if 0 < reg_days <= 365:
            pts = 3
            reg_score += pts
            reg_factors.append(f"Short registration window ({reg_days} days) (+{pts})")

    cat2 = min(25, reg_score)

    # ── CATEGORY 3: Infrastructure Profiling (0–25) ───────────────────────────
    infra_score = 0
    infra_factors: list[str] = []

    country_code = asn_info.get("country", "")
    if country_code in HIGH_RISK_COUNTRIES:
        pts = HIGH_RISK_COUNTRIES[country_code]
        infra_score += pts
        infra_factors.append(f"Hosted in elevated-risk region: {country_code} (+{pts})")
    elif not country_code or country_code in ("Unknown", ""):
        infra_score += 5
        infra_factors.append("Hosting location unknown (+5)")

    # Bulletproof hosting ASN check
    asn_str = asn_info.get("asn", "")
    for bad_asn in BULLETPROOF_ASNS:
        if bad_asn in asn_str.upper():
            infra_score += 12
            infra_factors.append(f"Known bulletproof hosting provider ({bad_asn}) (+12)")
            break

    if isinstance(shodan_info, dict) and not shodan_info.get("error"):
        ports = shodan_info.get("ports", [])
        # Dangerous port exposure
        dangerous_found = [p for p in ports if p in HIGH_RISK_PORTS]
        if dangerous_found:
            pts = min(12, sum(HIGH_RISK_PORTS[p] for p in dangerous_found[:5]))
            infra_score += pts
            infra_factors.append(
                f"Dangerous ports exposed: {', '.join(str(p) for p in dangerous_found[:5])} (+{pts})"
            )
        # Known CVE vulnerabilities
        vulns = shodan_info.get("vulns", [])
        if vulns:
            pts = min(10, len(vulns) * 2)
            infra_score += pts
            infra_factors.append(f"{len(vulns)} CVE vulnerabilities detected by Shodan (+{pts})")
        # Massive open attack surface
        if len(ports) > 20:
            pts = 3
            infra_score += pts
            infra_factors.append(f"Large attack surface: {len(ports)} open ports (+{pts})")

    cat3 = min(25, infra_score)

    # ── CATEGORY 4: DNS Pattern Analysis (0–20) ───────────────────────────────
    dns_score = 0
    dns_factors: list[str] = []

    if isinstance(dns_info, list):
        # Fast flux: many A records cycling rapidly is a classic C2 indicator
        if len(dns_info) > 4:
            pts = min(10, (len(dns_info) - 4) * 2 + 4)
            dns_score += pts
            dns_factors.append(
                f"{len(dns_info)} A records detected — possible fast-flux network (+{pts})"
            )
        elif len(dns_info) == 0:
            dns_score += 3
            dns_factors.append("No DNS A records resolved (+3)")

    cat4 = min(20, dns_score)

    # ── Final Score ───────────────────────────────────────────────────────────
    final_score = min(100, max(0, cat1 + cat2 + cat3 + cat4))

    breakdown = {
        "domain_name":    {"score": cat1, "max": 30, "factors": name_factors},
        "registration":   {"score": cat2, "max": 25, "factors": reg_factors},
        "infrastructure": {"score": cat3, "max": 25, "factors": infra_factors},
        "dns_analysis":   {"score": cat4, "max": 20, "factors": dns_factors},
        "total": final_score,
        "entropy": round(entropy, 2),
    }
    if brand_match:
        breakdown["phishing"] = brand_match

    logger.info(
        f"ThreatVector score for {domain}: {final_score} "
        f"(name={cat1} reg={cat2} infra={cat3} dns={cat4})"
    )
    return final_score, breakdown
