"""
TraceHost Threat Intelligence Module
Real-time checks against public threat feeds.

Note: abuse.ch now requires a (free) Auth-Key for API queries. Set
URLHAUS_AUTH_KEY in Backend/.env to enable live URLhaus lookups; without it
the feed reports listed=None ("unknown") rather than a false "clean".
"""

import logging
import requests
from decouple import config

logger = logging.getLogger(__name__)

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/host/"
URLHAUS_AUTH_KEY = config("URLHAUS_AUTH_KEY", default="")
REQUEST_TIMEOUT = 6


def check_urlhaus(domain: str) -> dict:
    """
    Query URLhaus (abuse.ch) for the domain.
    Returns a dict with 'listed' bool (None when the feed can't be queried)
    and optional details.
    """
    try:
        headers = {"Auth-Key": URLHAUS_AUTH_KEY} if URLHAUS_AUTH_KEY else {}
        resp = requests.post(
            URLHAUS_API, data={"host": domain}, headers=headers, timeout=REQUEST_TIMEOUT
        )
        if resp.status_code in (401, 403):
            return {
                "listed": None,
                "source": "URLhaus",
                "error": "URLhaus API requires an Auth-Key (set URLHAUS_AUTH_KEY in Backend/.env)",
            }
        if resp.status_code == 200:
            data = resp.json()
            status = data.get("query_status", "")
            # "ok" is the documented success status; "is_host" kept for
            # compatibility with older API responses.
            if status in ("ok", "is_host"):
                urls = data.get("urls", []) or []
                active = [u for u in urls if u.get("url_status") == "online"]
                return {
                    "listed": len(urls) > 0,
                    "urls_count": len(urls),
                    "active_urls": len(active),
                    "tags": sorted({tag for u in urls for tag in (u.get("tags") or [])}),
                    "blacklists": data.get("blacklists", {}),
                    "source": "URLhaus",
                }
            if status == "no_results":
                return {"listed": False, "source": "URLhaus"}
            return {"listed": None, "source": "URLhaus", "error": f"query_status: {status or 'missing'}"}
        return {"listed": None, "source": "URLhaus", "error": f"HTTP {resp.status_code}"}
    except requests.Timeout:
        logger.warning("URLhaus check timed out for %s", domain)
        return {"listed": None, "source": "URLhaus", "error": "Timeout"}
    except Exception as exc:
        logger.warning("URLhaus check failed for %s: %s", domain, exc)
        return {"listed": None, "source": "URLhaus", "error": str(exc)}


def get_threat_summary(domain: str) -> dict:
    """
    Aggregate threat intelligence from all available free feeds.
    Returns a unified threat_intel dict to embed in the scan response.
    """
    urlhaus = check_urlhaus(domain)

    # Derive overall threat_level from intel results
    threat_level = "unknown"
    listed_count = 0
    if urlhaus.get("listed") is True:
        listed_count += 1

    if listed_count >= 1:
        threat_level = "malicious"
    elif urlhaus.get("listed") is False:
        threat_level = "clean"

    return {
        "threat_level": threat_level,
        "listed_on_feeds": listed_count,
        "feeds": {
            "urlhaus": urlhaus,
        },
    }
