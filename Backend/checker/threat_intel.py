"""
TraceHost Threat Intelligence Module
Real-time checks against public threat feeds — no API key required.
"""

import logging
import requests

logger = logging.getLogger(__name__)

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/host/"
REQUEST_TIMEOUT = 6


def check_urlhaus(domain: str) -> dict:
    """
    Query URLhaus (abuse.ch) for the domain.
    Returns a dict with 'listed' bool and optional details.
    """
    try:
        resp = requests.post(URLHAUS_API, data={"host": domain}, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            status = data.get("query_status", "")
            if status == "is_host":
                urls = data.get("urls", [])
                active = [u for u in urls if u.get("url_status") == "online"]
                return {
                    "listed": True,
                    "urls_count": len(urls),
                    "active_urls": len(active),
                    "tags": list({tag for u in urls for tag in (u.get("tags") or [])}),
                    "blacklists": data.get("blacklists", {}),
                    "source": "URLhaus",
                }
            return {"listed": False, "source": "URLhaus"}
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
