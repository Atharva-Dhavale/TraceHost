from django.http import JsonResponse, StreamingHttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.cache import cache
from django.utils import timezone
import requests
import whois
import dns.resolver
import ipinfo
import logging
import time
import os
import json
import re
from datetime import timedelta, datetime
from decouple import config

from .risk_engine import calculate_advanced_risk_score
from .threat_intel import get_threat_summary
from . import mongo_store

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# ── API Keys ──────────────────────────────────────────────────────────────────
IPINFO_API_KEY        = config("IPINFO_API_KEY")
SHODAN_API_KEY        = config("SHODAN_API_KEY")
SECURITY_TRAILS_API_KEY = config("SECURITY_TRAILS_API_KEY")
OPENROUTER_API_KEY    = config("OPENROUTER_API_KEY")
OPENROUTER_MODEL      = config("OPENROUTER_MODEL", default="openai/gpt-oss-120b:free")

OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
logger.info("OpenRouter API configured (model: %s)", OPENROUTER_MODEL)


# ── OpenRouter helpers ────────────────────────────────────────────────────────

def call_openrouter_api(prompt, max_output_tokens=256, temperature=0.2):
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": OPENROUTER_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_output_tokens,
    }
    resp = requests.post(OPENROUTER_API_URL, headers=headers, json=payload, timeout=45)
    resp.raise_for_status()
    data = resp.json()
    choices = data.get("choices", [])
    if choices:
        return choices[0].get("message", {}).get("content", "")
    raise ValueError("No text returned from OpenRouter API")


def call_with_retry(func, *args, max_retries=3, **kwargs):
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            logger.warning("API call failed (attempt %d/%d): %s", attempt + 1, max_retries, exc)
            if attempt == max_retries - 1:
                raise
            time.sleep(1)


# ── Data-collection helpers ───────────────────────────────────────────────────

def get_whois_info(domain):
    logger.info("Getting WHOIS info for %s", domain)
    t0 = time.time()

    def _norm(val):
        if val is None:
            return None
        if isinstance(val, list):
            val = val[0] if val else None
        if val and hasattr(val, "isoformat"):
            return val.isoformat()
        return str(val) if val else None

    try:
        w = whois.whois(domain)
        logger.info("WHOIS completed in %.2fs", time.time() - t0)
        return {
            "registrar": w.registrar,
            "registrant_name": w.name[0] if isinstance(w.name, list) else w.name,
            "registrant_organization": w.org[0] if isinstance(w.org, list) else w.org,
            "country": w.country[0] if isinstance(w.country, list) else w.country,
            "updated_date": _norm(w.updated_date),
            "creation_date": _norm(w.creation_date),
            "expiration_date": _norm(w.expiration_date),
        }
    except Exception as exc:
        logger.error("WHOIS failed: %s", exc)
        return {"error": str(exc)}


def get_dns_info(domain):
    logger.info("Getting DNS info for %s", domain)
    t0 = time.time()
    try:
        answers = dns.resolver.resolve(domain, "A")
        logger.info("DNS completed in %.2fs", time.time() - t0)
        return [a.to_text() for a in answers]
    except dns.resolver.NXDOMAIN:
        return {"error": "non_existent_domain", "message": f"Domain {domain} does not exist"}
    except Exception as exc:
        return {"error": "dns_lookup_failed", "message": str(exc)}


def get_historical_dns(domain):
    logger.info("Getting historical DNS for %s", domain)
    url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
    try:
        resp = requests.get(url, headers={"apikey": SECURITY_TRAILS_API_KEY}, timeout=10)
        return resp.json() if resp.status_code == 200 else []
    except Exception as exc:
        logger.error("Historical DNS failed: %s", exc)
        return []


def enumerate_subdomains(domain):
    logger.info("Enumerating subdomains for %s", domain)
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    try:
        resp = requests.get(url, headers={"apikey": SECURITY_TRAILS_API_KEY}, timeout=10)
        return resp.json().get("subdomains", []) if resp.status_code == 200 else []
    except Exception as exc:
        logger.error("Subdomain enum failed: %s", exc)
        return []


def get_ssl_cert_logs(domain):
    logger.info("Getting SSL cert logs for %s", domain)
    try:
        resp = requests.get(f"https://crt.sh/?q={domain}&output=json", timeout=10)
        return resp.json() if resp.status_code == 200 else []
    except Exception as exc:
        return []


def get_shodan_info(ip):
    logger.info("Getting Shodan info for %s", ip)
    try:
        resp = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}", timeout=15
        )
        if resp.status_code == 200:
            d = resp.json()
            return {
                "ip": d.get("ip_str", ip),
                "ports": d.get("ports", []),
                "hostnames": d.get("hostnames", []),
                "os": d.get("os", "Unknown"),
                "isp": d.get("isp", "Unknown"),
                "org": d.get("org", "Unknown"),
                "country_name": d.get("country_name", "Unknown"),
                "city": d.get("city", "Unknown"),
                "vulns": list(d.get("vulns", [])) if d.get("vulns") else [],
                "last_update": d.get("last_update", "Unknown"),
                "services": [
                    {
                        "port": s.get("port"),
                        "transport": s.get("transport", "tcp"),
                        "product": s.get("product", "Unknown"),
                        "version": s.get("version", ""),
                    }
                    for s in d.get("data", [])[:10]
                ],
            }
        return {"error": f"Shodan returned {resp.status_code}"}
    except Exception as exc:
        return {"error": str(exc)}


def get_asn_info(ip):
    logger.info("Getting ASN info for %s", ip)
    try:
        handler = ipinfo.getHandler(IPINFO_API_KEY)
        details = handler.getDetails(ip)
        lat, lon = details.loc.split(",")
        return {
            "asn": details.org,
            "city": details.city,
            "region": details.region,
            "country": details.country_name,
            "country_code": details.country,
            "latitude": lat,
            "longitude": lon,
        }
    except Exception as exc:
        logger.error("ASN lookup failed: %s", exc)
        return {"asn": "Unknown", "city": "Unknown", "region": "Unknown",
                "country": "Unknown", "country_code": "", "latitude": "0", "longitude": "0"}


# ── AI Summary ────────────────────────────────────────────────────────────────

def generate_domain_summary(domain_data: dict) -> str:
    domain = domain_data.get("Domain", "N/A")
    trusted_tlds = [".edu", ".gov", ".ac", ".sch", ".mil", ".int"]
    is_trusted = any(domain.lower().endswith(t) for t in trusted_tlds)

    if not domain_data.get("Domain_Exists", True):
        return "Domain does not exist — not registered or cannot be resolved."

    shodan = domain_data.get("Shodan_Info", {}) or {}
    risk_breakdown = domain_data.get("Risk_Breakdown", {}) or {}
    breakdown_factors = []
    for cat in ("domain_name", "registration", "infrastructure", "dns_analysis"):
        for f in risk_breakdown.get(cat, {}).get("factors", []):
            breakdown_factors.append(f)

    subdomains = domain_data.get("Subdomains", [])
    threat_intel = domain_data.get("Threat_Intel", {}) or {}
    urlhaus = threat_intel.get("feeds", {}).get("urlhaus", {})

    prompt = f"""
You are a senior cybersecurity analyst at a threat intelligence firm. Produce a detailed, professional domain security report.

=== DOMAIN INFORMATION ===
Domain: {domain}
IP Address: {domain_data.get('IP_Address', 'N/A')}
Location: {domain_data.get('ASN_Info', {}).get('city', '?')}, {domain_data.get('ASN_Info', {}).get('country', '?')}
ASN: {domain_data.get('ASN_Info', {}).get('asn', '?')}

=== REGISTRATION ===
Registrar: {domain_data.get('Registrar', 'N/A')}
Created: {domain_data.get('Creation_Date', 'N/A')}
Expires: {domain_data.get('Expiration_Date', 'N/A')}
Registrant: {domain_data.get('Registrant_Organization', domain_data.get('Registrant_Name', 'Hidden'))}

=== THREAT VECTOR SCORE ===
ThreatVector Risk Score: {domain_data.get('Security_Analysis', {}).get('risk_score', 0)}/100
Flagged Suspicious: {domain_data.get('Security_Analysis', {}).get('is_suspicious', False)}
Detected Risk Factors:
{chr(10).join('- ' + f for f in breakdown_factors) if breakdown_factors else '- None identified'}

=== THREAT INTELLIGENCE ===
URLhaus Listed: {urlhaus.get('listed', 'Unknown')}
Active Malicious URLs: {urlhaus.get('active_urls', 0)}
Threat Level: {threat_intel.get('threat_level', 'unknown')}

=== NETWORK EXPOSURE (Shodan) ===
Open Ports: {', '.join(str(p) for p in shodan.get('ports', [])) or 'No data'}
CVE Vulnerabilities: {', '.join(shodan.get('vulns', [])) or 'None detected'}
ISP: {shodan.get('isp', 'Unknown')}
OS: {shodan.get('os', 'Unknown')}

=== INFRASTRUCTURE ===
Subdomains Found: {len(subdomains)} ({', '.join(subdomains[:8])}{'...' if len(subdomains) > 8 else ''})

{"NOTE: This is a trusted institutional domain (.edu/.gov/.mil) — treat as low risk unless clear evidence of compromise." if is_trusted else ""}

Provide a detailed security assessment with these exact sections (no asterisks or hash symbols, use plain text and dashes for lists):

Summary
(2-3 sentence executive overview with risk score context)

Domain Reputation Analysis
(Domain age, registrar, registrant identity, naming patterns, brand similarity if any)

Hosting Infrastructure
(Server location, ASN, hosting provider, risk profile of the infrastructure)

Network Exposure Assessment
(Open ports, CVEs, services, overall attack surface)

Threat Intelligence
(URLhaus status, threat feeds, historical malicious activity indicators)

DNS and Subdomain Analysis
(Subdomain count, patterns, DNS health, anomalies)

Risk Evaluation
(Walk through each ThreatVector factor and its significance)

Security Recommendations
(Specific actionable advice for users and security teams)

Use only plain text. No asterisks, no hash symbols. Use dashes for bullet points.
"""
    try:
        text = call_with_retry(call_openrouter_api, prompt, max_output_tokens=1200, temperature=0.2)
        return text.replace("*", "").replace("#", "")
    except Exception as exc:
        logger.error("OpenRouter summary failed: %s", exc)
        if is_trusted:
            return (
                f"Summary\n{domain} belongs to a trusted institutional TLD "
                f"(.edu/.gov/.mil) and is considered low-risk by default.\n\n"
                f"Domain Reputation Analysis\nInstitutional domains are governed by "
                f"strict registration policies and are generally legitimate.\n\n"
                f"Security Recommendations\nMaintain standard browser security practices."
            )
        return "AI security summary temporarily unavailable."


# ── Core Analysis ─────────────────────────────────────────────────────────────

def analyze_domain_for_response(domain: str) -> dict:
    """Full domain analysis pipeline — returns the JSON-ready response dict."""
    logger.info("Analyzing domain for response: %s", domain)
    t0 = time.time()

    try:
        whois_info = get_whois_info(domain)
        dns_info   = get_dns_info(domain)

        # Non-existent domain fast path
        if isinstance(dns_info, dict) and dns_info.get("error") == "non_existent_domain":
            logger.info("Domain %s does not exist", domain)
            return {
                "Domain": domain,
                "Domain_Exists": False,
                "Summary": "Domain does not exist",
                "Security_Analysis": {
                    "result": ["Domain does not exist"],
                    "is_suspicious": False,
                    "risk_score": 0,
                },
                "Risk_Breakdown": None,
                "Threat_Intel": None,
                "AI_Summary": "Domain does not exist and cannot be resolved to an IP address.",
            }

        historical_dns = get_historical_dns(domain)
        subdomains     = enumerate_subdomains(domain)
        ip_address     = dns_info[0] if isinstance(dns_info, list) and dns_info else None
        asn_info       = get_asn_info(ip_address) if ip_address else {}
        shodan_info    = get_shodan_info(ip_address) if ip_address else {}

        # ── ThreatVector Engine ───────────────────────────────────────────────
        risk_score, risk_breakdown = calculate_advanced_risk_score(
            domain, whois_info, dns_info, asn_info, shodan_info
        )
        is_suspicious = risk_score > 60

        # ── Threat Intel Feeds ────────────────────────────────────────────────
        threat_intel = get_threat_summary(domain)

        # Elevate risk score if actively listed on URLhaus
        if threat_intel.get("feeds", {}).get("urlhaus", {}).get("listed") is True:
            active = threat_intel["feeds"]["urlhaus"].get("active_urls", 0)
            bonus = 20 if active > 0 else 10
            risk_score = min(100, risk_score + bonus)
            risk_breakdown.setdefault("domain_name", {}).setdefault("factors", []).append(
                f"Listed on URLhaus threat feed (+{bonus})"
            )
            risk_breakdown["total"] = risk_score
            is_suspicious = risk_score > 60

        # ── Risk factors (human-readable list) ────────────────────────────────
        risk_factors = []
        for cat in ("domain_name", "registration", "infrastructure", "dns_analysis"):
            for f in risk_breakdown.get(cat, {}).get("factors", []):
                risk_factors.append(f)

        location = (
            f"{asn_info.get('city', 'Unknown')}, "
            f"{asn_info.get('region', 'Unknown')}, "
            f"{asn_info.get('country', 'Unknown')}"
        )
        summary = f"Host IP Address: {ip_address or 'N/A'}, Location: {location}"

        lat = asn_info.get("latitude")
        lon = asn_info.get("longitude")
        server_location = {"lat": lat, "lng": lon} if lat and lon else "Location data unavailable"
        location_link = (
            f"https://www.google.com/maps?q={lat},{lon}" if lat and lon else None
        )

        response_data = {
            "Domain":         domain,
            "Domain_Exists":  True,
            "Summary":        summary,
            "Location Link":  location_link,
            "Registrar":      whois_info.get("registrar", "N/A"),
            "IP_Address":     ip_address or "N/A",
            "ASN_Info":       asn_info,
            "Country":        whois_info.get("country", "N/A"),
            "Updated_Date":   whois_info.get("updated_date", "N/A"),
            "Creation_Date":  whois_info.get("creation_date", "N/A"),
            "Expiration_Date":whois_info.get("expiration_date", "N/A"),
            "Registrant_Name":whois_info.get("registrant_name", "N/A"),
            "Registrant_Organization": whois_info.get("registrant_organization", "N/A"),
            "Subdomains":     subdomains,
            "Historical_DNS": historical_dns,
            "Server_Location":server_location,
            "Security_Analysis": {
                "result":       risk_factors,
                "is_suspicious":is_suspicious,
                "risk_score":   risk_score,
            },
            "Risk_Breakdown": risk_breakdown,
            "Threat_Intel":   threat_intel,
            "Shodan_Info":    shodan_info,
        }

        # ── AI narrative ──────────────────────────────────────────────────────
        ai_summary = generate_domain_summary({**response_data})
        response_data["AI_Summary"] = ai_summary

        # ── Persist to MongoDB ────────────────────────────────────────────────
        scan_doc = {
            "domain":          domain,
            "ip_address":      ip_address,
            "risk_score":      risk_score,
            "is_suspicious":   is_suspicious,
            "is_flagged":      mongo_store.is_domain_flagged(domain),
            "country":         whois_info.get("country"),
            "city":            asn_info.get("city"),
            "registrar":       whois_info.get("registrar"),
            "creation_date":   whois_info.get("creation_date"),
            "expiration_date": whois_info.get("expiration_date"),
            "category":        "Phishing" if risk_breakdown.get("phishing") else (
                               "Suspicious" if is_suspicious else "Clean"),
            "status":          "Active",
            "risk_breakdown":  risk_breakdown,
            "threat_intel":    threat_intel,
            "whois_info":      whois_info,
            "asn_info":        asn_info,
            "shodan_info":     shodan_info,
            "subdomains":      subdomains,
            "ai_summary":      ai_summary,
        }
        try:
            mongo_store.save_scan(scan_doc)
        except Exception as exc:
            logger.warning("Could not persist scan to MongoDB: %s", exc)

        logger.info("Analysis completed in %.2fs (score=%d)", time.time() - t0, risk_score)
        return response_data

    except Exception as exc:
        logger.error("analyze_domain_for_response failed: %s", exc)
        return {
            "Domain": domain,
            "error": f"Analysis failed: {exc}",
            "Domain_Exists": True,
        }


# ── API Views ─────────────────────────────────────────────────────────────────

@csrf_exempt
def analyze_domain(request):
    domain = request.GET.get("domain", "").strip()
    logger.info("Analyze request for: %s", domain)

    if not domain:
        return JsonResponse({"error": "No domain provided"}, status=400)

    try:
        result = analyze_domain_for_response(domain)
        return JsonResponse(result)
    except Exception as exc:
        logger.error("analyze_domain error: %s", exc)
        return JsonResponse({"error": "Analysis failed", "message": str(exc)}, status=500)


@csrf_exempt
def suspicious_view(request):
    domain = request.GET.get("domain", "").strip()
    if not domain:
        return JsonResponse({"error": "Domain parameter required"}, status=400)
    result = analyze_domain_for_response(domain)
    return JsonResponse({"domain": domain, "analysis": result})


@csrf_exempt
def get_dashboard_data(request):
    logger.info("Dashboard data request")
    cache_key = "dashboard_data_v2"
    cached = cache.get(cache_key)
    if cached:
        return JsonResponse(cached)

    try:
        page      = int(request.GET.get("page", 1))
        page_size = int(request.GET.get("page_size", 10))
        data = mongo_store.get_dashboard_stats(page=page, page_size=page_size)
        cache.set(cache_key, data, 300)
        return JsonResponse(data)
    except Exception as exc:
        logger.error("Dashboard error: %s", exc)
        # Return empty structure so frontend doesn't crash
        return JsonResponse({
            "basic_stats": {"total_scans": 0, "total_domains": 0, "avg_risk_score": 0,
                            "suspicious_domains": 0, "safe_domains": 0},
            "time_based_stats": {"today_scans": 0, "week_scans": 0, "month_scans": 0},
            "risk_distribution": [],
            "recent_scans": [],
            "daily_trends": [],
            "top_suspicious": [],
            "geo_distribution": [],
            "last_updated": datetime.utcnow().isoformat(),
            "pagination": {"page": 1, "page_size": 10, "total": 0},
        })


@csrf_exempt
def suspicious_domains_list(request):
    logger.info("Suspicious domains list request")
    try:
        page   = int(request.GET.get("page", 1))
        limit  = int(request.GET.get("limit", 10))
        search = request.GET.get("search", "")
        filt   = request.GET.get("filter", None)
        result = mongo_store.get_suspicious_domains(page, limit, search, filt)
        return JsonResponse(result)
    except Exception as exc:
        logger.error("Suspicious list error: %s", exc)
        return JsonResponse({"error": str(exc)}, status=500)


@csrf_exempt
def scan_history(request):
    """Return historical scan records for a domain from MongoDB."""
    domain = request.GET.get("domain", "").strip()
    if not domain:
        return JsonResponse({"error": "Domain required"}, status=400)
    try:
        limit   = min(int(request.GET.get("limit", 10)), 50)
        history = mongo_store.get_domain_history(domain, limit=limit)
        return JsonResponse({"domain": domain, "history": history, "count": len(history)})
    except Exception as exc:
        logger.error("Scan history error: %s", exc)
        return JsonResponse({"error": str(exc)}, status=500)


@csrf_exempt
def health_check(request):
    return JsonResponse({"status": "ok", "version": "2.0"})


@csrf_exempt
def flag_domain(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)
    try:
        data   = json.loads(request.body)
        domain = data.get("domain")
        flag   = data.get("flag", True)
        if not domain:
            return JsonResponse({"error": "Domain required"}, status=400)

        logger.info("Flag request: %s -> %s", domain, flag)
        ok = mongo_store.flag_domain(domain, flag)

        return JsonResponse({
            "success": ok,
            "domain":    domain,
            "is_flagged": flag,
            "message": f"Domain {'flagged' if flag else 'unflagged'} successfully",
        })
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    except Exception as exc:
        logger.error("Flag domain error: %s", exc)
        return JsonResponse({"error": str(exc)}, status=500)
