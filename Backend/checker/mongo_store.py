"""
TraceHost MongoDB Store
All persistent scan data is stored in MongoDB Atlas (TraceHostUpdated database).
"""

import logging
from datetime import datetime, timezone, timedelta
from decouple import config
from pymongo import MongoClient, DESCENDING, ASCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

logger = logging.getLogger(__name__)

MONGO_URI = config("MONGO_URI", default="")

_client = None
_db = None


def get_db():
    """Return MongoDB database, creating the connection on first call."""
    global _client, _db
    if _db is not None:
        return _db
    try:
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=6000)
        _client.admin.command("ping")  # Validate connection
        _db = _client.get_database()   # Uses DB name from URI path
        _ensure_indexes(_db)
        logger.info("MongoDB Atlas connected — database: %s", _db.name)
    except (ConnectionFailure, ServerSelectionTimeoutError) as exc:
        logger.error("MongoDB connection failed: %s", exc)
        raise
    return _db


def _ensure_indexes(db):
    """Create indexes on first connect (idempotent)."""
    scans = db["scans"]
    scans.create_index([("domain", ASCENDING)], background=True)
    scans.create_index([("scan_date", DESCENDING)], background=True)
    scans.create_index([("risk_score", DESCENDING)], background=True)
    scans.create_index([("is_suspicious", ASCENDING)], background=True)
    scans.create_index([("is_flagged", ASCENDING)], background=True)
    scans.create_index([("country", ASCENDING)], background=True)


# ── Write Operations ──────────────────────────────────────────────────────────

def save_scan(scan_doc: dict) -> str:
    """
    Persist a scan document.  Always inserts a new record (full history).
    Returns the inserted _id as a string.
    """
    try:
        db = get_db()
        scan_doc["scan_date"] = datetime.now(timezone.utc)
        result = db["scans"].insert_one(scan_doc)
        logger.info("Scan saved to MongoDB for %s", scan_doc.get("domain"))
        return str(result.inserted_id)
    except Exception as exc:
        logger.error("Failed to save scan to MongoDB: %s", exc)
        return ""


def flag_domain(domain: str, flag: bool = True) -> bool:
    """Set or clear the is_flagged flag on the most recent scan for a domain."""
    try:
        db = get_db()
        db["scans"].update_many(
            {"domain": domain},
            {"$set": {"is_flagged": flag, "last_flagged_date": datetime.now(timezone.utc)}},
        )
        logger.info("Domain %s %s", domain, "flagged" if flag else "unflagged")
        return True
    except Exception as exc:
        logger.error("Failed to flag domain in MongoDB: %s", exc)
        return False


# ── Read Operations ───────────────────────────────────────────────────────────

def get_domain_history(domain: str, limit: int = 10) -> list:
    """Return the last N scans for a domain, newest first."""
    try:
        db = get_db()
        docs = (
            db["scans"]
            .find({"domain": domain}, {"_id": 0, "domain": 1, "scan_date": 1,
                                        "risk_score": 1, "is_suspicious": 1,
                                        "risk_breakdown": 1, "ip_address": 1})
            .sort("scan_date", DESCENDING)
            .limit(limit)
        )
        history = []
        for d in docs:
            if isinstance(d.get("scan_date"), datetime):
                d["scan_date"] = d["scan_date"].isoformat()
            history.append(d)
        return history
    except Exception as exc:
        logger.error("Failed to fetch domain history: %s", exc)
        return []


def is_domain_flagged(domain: str) -> bool:
    try:
        db = get_db()
        return bool(db["scans"].find_one({"domain": domain, "is_flagged": True}))
    except Exception:
        return False


def get_latest_scan(domain: str) -> dict | None:
    """Return the most recent scan document for a domain."""
    try:
        db = get_db()
        doc = db["scans"].find_one({"domain": domain}, sort=[("scan_date", DESCENDING)])
        if doc:
            doc.pop("_id", None)
            if isinstance(doc.get("scan_date"), datetime):
                doc["scan_date"] = doc["scan_date"].isoformat()
        return doc
    except Exception as exc:
        logger.error("Failed to get latest scan: %s", exc)
        return None


# ── Dashboard Aggregations ────────────────────────────────────────────────────

def get_dashboard_stats(page: int = 1, page_size: int = 10) -> dict:
    """Build dashboard statistics using MongoDB aggregation pipelines."""
    try:
        db = get_db()
        scans = db["scans"]
        now = datetime.now(timezone.utc)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = today_start - timedelta(days=7)
        month_start = today_start - timedelta(days=30)

        # ── Basic stats ───────────────────────────────────────────────────────
        basic_pipeline = [
            {"$group": {
                "_id": None,
                "total_scans": {"$sum": 1},
                "avg_risk_score": {"$avg": "$risk_score"},
                "suspicious_count": {"$sum": {"$cond": ["$is_suspicious", 1, 0]}},
                "safe_count": {"$sum": {"$cond": [{"$not": ["$is_suspicious"]}, 1, 0]}},
            }}
        ]
        basic_result = list(scans.aggregate(basic_pipeline))
        basic = basic_result[0] if basic_result else {
            "total_scans": 0, "avg_risk_score": 0,
            "suspicious_count": 0, "safe_count": 0
        }
        total_domains = scans.distinct("domain")

        # ── Time-based stats ──────────────────────────────────────────────────
        time_stats = {
            "today_scans": scans.count_documents({"scan_date": {"$gte": today_start}}),
            "week_scans":  scans.count_documents({"scan_date": {"$gte": week_start}}),
            "month_scans": scans.count_documents({"scan_date": {"$gte": month_start}}),
        }

        # ── Risk distribution ─────────────────────────────────────────────────
        total = basic["total_scans"] or 1
        ranges = [("Very Low", 0, 20), ("Low", 21, 40), ("Medium", 41, 60),
                  ("High", 61, 80), ("Very High", 81, 100)]
        risk_distribution = []
        for label, lo, hi in ranges:
            count = scans.count_documents({"risk_score": {"$gte": lo, "$lte": hi}})
            risk_distribution.append({
                "range": label, "count": count,
                "percentage": round(count / total * 100, 2),
            })

        # ── Recent scans ──────────────────────────────────────────────────────
        skip = (page - 1) * page_size
        raw_recent = list(
            scans.find(
                {},
                {"_id": 0, "domain": 1, "risk_score": 1, "scan_date": 1,
                 "is_suspicious": 1, "ip_address": 1, "country": 1}
            ).sort("scan_date", DESCENDING).skip(skip).limit(page_size)
        )
        recent_scans = []
        for r in raw_recent:
            if isinstance(r.get("scan_date"), datetime):
                r["scan_date"] = r["scan_date"].isoformat()
            recent_scans.append(r)

        # ── Daily trends (last 7 days) ────────────────────────────────────────
        daily_pipeline = [
            {"$match": {"scan_date": {"$gte": week_start}}},
            {"$group": {
                "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$scan_date"}},
                "total_scans": {"$sum": 1},
                "suspicious_count": {"$sum": {"$cond": ["$is_suspicious", 1, 0]}},
                "avg_risk_score": {"$avg": "$risk_score"},
            }},
            {"$sort": {"_id": 1}},
        ]
        daily_trends = []
        for d in scans.aggregate(daily_pipeline):
            daily_trends.append({
                "date": d["_id"],
                "total_scans": d["total_scans"],
                "suspicious_count": d["suspicious_count"],
                "avg_risk_score": round(d["avg_risk_score"] or 0, 1),
            })

        # ── Top suspicious ────────────────────────────────────────────────────
        raw_top = list(
            scans.find(
                {"is_suspicious": True},
                {"_id": 0, "domain": 1, "risk_score": 1, "scan_date": 1}
            ).sort("risk_score", DESCENDING).limit(5)
        )
        top_suspicious = []
        for t in raw_top:
            if isinstance(t.get("scan_date"), datetime):
                t["scan_date"] = t["scan_date"].isoformat()
            top_suspicious.append(t)

        # ── Geographic distribution ───────────────────────────────────────────
        geo_pipeline = [
            {"$match": {"country": {"$nin": [None, "", "Unknown"]}}},
            {"$group": {"_id": "$country", "count": {"$sum": 1}}},
            {"$sort": {"count": DESCENDING}},
            {"$limit": 10},
        ]
        geo_distribution = [
            {"country": g["_id"], "count": g["count"]}
            for g in scans.aggregate(geo_pipeline)
        ]

        return {
            "basic_stats": {
                "total_scans": basic["total_scans"],
                "total_domains": len(total_domains),
                "avg_risk_score": round(basic.get("avg_risk_score") or 0, 2),
                "suspicious_domains": basic["suspicious_count"],
                "safe_domains": basic["safe_count"],
            },
            "time_based_stats": time_stats,
            "risk_distribution": risk_distribution,
            "recent_scans": recent_scans,
            "daily_trends": daily_trends,
            "top_suspicious": top_suspicious,
            "geo_distribution": geo_distribution,
            "last_updated": now.isoformat(),
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total": basic["total_scans"],
            },
        }
    except Exception as exc:
        logger.error("Dashboard aggregation failed: %s", exc)
        raise


def get_suspicious_domains(
    page: int = 1,
    limit: int = 10,
    search: str = "",
    filter_category: str | None = None,
) -> dict:
    """Paginated suspicious domains list with optional search and risk-level filter."""
    try:
        db = get_db()
        scans = db["scans"]
        query: dict = {"is_suspicious": True}

        if search:
            query["domain"] = {"$regex": search, "$options": "i"}

        risk_map = {"high": (70, 100), "medium": (40, 69), "low": (0, 39)}
        if filter_category and filter_category.lower() in risk_map:
            lo, hi = risk_map[filter_category.lower()]
            query["risk_score"] = {"$gte": lo, "$lte": hi}
        elif filter_category:
            query["category"] = filter_category

        total = scans.count_documents(query)
        docs = list(
            scans.find(
                query,
                {"_id": 0, "domain": 1, "risk_score": 1, "category": 1,
                 "status": 1, "scan_date": 1, "is_suspicious": 1}
            ).sort("scan_date", DESCENDING).skip((page - 1) * limit).limit(limit)
        )
        domains = []
        for d in docs:
            if isinstance(d.get("scan_date"), datetime):
                d["scan_date"] = d["scan_date"].isoformat()
            d.setdefault("category", "Suspicious")
            d.setdefault("status", "Active")
            domains.append(d)

        return {"domains": domains, "total": total}
    except Exception as exc:
        logger.error("Suspicious domains query failed: %s", exc)
        raise
