"""
db_helper.py
============
Lightweight MongoDB connector for the HoneyShield Intelligence Dashboard.
Reads credentials from the project .env file and exposes clean data-fetching
functions for the Streamlit dashboard app.
"""

import os
import sys
from pathlib import Path
from datetime import datetime, timezone

from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

# ── Path bootstrap: load .env from parent HoneyShield project root ──────────
_DASHBOARD_DIR = Path(__file__).resolve().parent          # intelligence_dashboard/
_PROJECT_ROOT  = _DASHBOARD_DIR.parent                     # HoneyShield/
load_dotenv(_PROJECT_ROOT / ".env")

MONGODB_URI     = os.getenv("MONGODB_URI", "")
DB_NAME         = os.getenv("DB_NAME", "threat_intel")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "honey_credentials")

# ── Status ordering for funnel display ──────────────────────────────────────
STATUS_ORDER = [
    "LURE_CAPTURED",
    "APK_DOWNLOADED",
    "STATIC_ANALYSIS_COMPLETED",
    "DYNAMIC_ANALYSIS_COMPLETED",
    "C2_DOMAINS_ISOLATED",
    "TRAP_READY",
    "TRAP_TRIGGERED",
    "PIPELINE_FAILED",
]

# Flat, minimal, professional palette — mirrors the dashboard's light theme
STATUS_COLORS = {
    "LURE_CAPTURED":               "#1e88e5",
    "APK_DOWNLOADED":              "#0d9488",
    "STATIC_ANALYSIS_COMPLETED":   "#2e7d32",
    "DYNAMIC_ANALYSIS_COMPLETED":  "#ef6c00",
    "C2_DOMAINS_ISOLATED":         "#8e24aa",
    "TRAP_READY":                  "#00838f",
    "TRAP_TRIGGERED":              "#c62828",
    "PIPELINE_FAILED":             "#607d8b",
}


# ── Database client (cached singleton) ──────────────────────────────────────
_client: MongoClient | None = None

import certifi

def get_collection():
    """Return a live MongoCollection, creating the client if necessary."""
    global _client
    try:
        if _client is None:
            _client = MongoClient(
                MONGODB_URI, 
                serverSelectionTimeoutMS=5000, 
                tlsCAFile=certifi.where()
            )
        _client.admin.command("ping")          # lightweight heartbeat
        return _client[DB_NAME][COLLECTION_NAME]
    except (ConnectionFailure, ServerSelectionTimeoutError) as e:
        _client = None
        raise ConnectionError(f"MongoDB connection failed: {e}") from e


def fetch_all_incidents() -> list[dict]:
    """
    Fetch all incident documents sorted newest-first.
    Returns a list of plain Python dicts with ObjectId converted to string.
    """
    col = get_collection()
    docs = list(col.find({}).sort("createdAt", -1))
    for doc in docs:
        doc["_id"] = str(doc["_id"])
        # Normalise datetime fields to UTC-aware strings
        for field in ("createdAt",):
            if isinstance(doc.get(field), datetime):
                doc[field] = doc[field].replace(tzinfo=timezone.utc).isoformat()
        fi = doc.get("forensic_intercept", {})
        if isinstance(fi.get("triggeredAt"), datetime):
            fi["triggeredAt"] = fi["triggeredAt"].replace(tzinfo=timezone.utc).isoformat()
    return docs


def fetch_summary_metrics(docs: list[dict]) -> dict:
    """
    Derive high-level KPI metrics from a list of already-fetched incident docs.
    """
    total = len(docs)
    active_probes  = sum(1 for d in docs if d.get("incident_status") == "TRAP_READY")
    captures       = sum(1 for d in docs if d.get("incident_status") == "TRAP_TRIGGERED")
    failures       = sum(1 for d in docs if d.get("incident_status") == "PIPELINE_FAILED")
    completed_runs = total - failures
    success_rate   = round((completed_runs / total * 100), 1) if total else 0.0

    status_counts = {s: 0 for s in STATUS_ORDER}
    for doc in docs:
        s = doc.get("incident_status", "PIPELINE_FAILED")
        status_counts[s] = status_counts.get(s, 0) + 1

    return {
        "total":        total,
        "active_probes": active_probes,
        "captures":     captures,
        "success_rate": success_rate,
        "status_counts": status_counts,
    }