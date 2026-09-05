import os
import certifi
from pymongo import MongoClient
from datetime import datetime


# ── Connect to MongoDB ───────────────────────────────────
def get_db():
    uri    = os.getenv("MONGO_URI")
    client = MongoClient(uri, tlsCAFile=certifi.where())
    db     = client["threatlens"]
    return db


# ── Save a full analysis session ────────────────────────
def save_analysis(filename, alerts, summary):
    """
    Saves an uploaded log analysis to MongoDB.
    Creates one document per analysis session containing
    the filename, timestamp, summary, and all alerts.
    """
    db = get_db()

    document = {
        "filename":    filename,
        "uploaded_at": datetime.utcnow(),
        "summary":     summary,
        "alerts":      alerts,
        "total":       summary.get("total", 0)
    }

    result = db["analyses"].insert_one(document)
    return str(result.inserted_id)


# ── Get all past analyses ────────────────────────────────
def get_all_analyses():
    """
    Returns all past analysis sessions, newest first.
    """
    db       = get_db()
    analyses = db["analyses"].find(
        {},
        {"filename": 1, "uploaded_at": 1, "summary": 1, "total": 1}
    ).sort("uploaded_at", -1)
    return list(analyses)


# ── Get one specific analysis by ID ─────────────────────
def get_analysis_by_id(analysis_id):
    """
    Returns a single analysis document by its MongoDB ID.
    """
    from bson import ObjectId
    db       = get_db()
    analysis = db["analyses"].find_one({"_id": ObjectId(analysis_id)})
    return analysis


# ── Delete an analysis ───────────────────────────────────
def delete_analysis(analysis_id):
    """
    Deletes an analysis document by its MongoDB ID.
    """
    from bson import ObjectId
    db = get_db()
    db["analyses"].delete_one({"_id": ObjectId(analysis_id)})
