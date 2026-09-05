import os
import bcrypt
import certifi
from pymongo import MongoClient


# ── Connect to MongoDB ───────────────────────────────────
def get_db():
    uri = os.getenv("MONGO_URI")
    client = MongoClient(uri, tlsCAFile=certifi.where())
    db = client["threatlens"]
    return db


# ── Register a new user ──────────────────────────────────
def register_user(username, password):
    """
    Creates a new user in the database.
    Password is hashed with bcrypt before storing.
    Returns True if successful, False if username already exists.
    """
    db = get_db()

    # Check if username already taken
    existing = db["users"].find_one({"username": username})
    if existing:
        return False, "Username already exists."

    # Hash the password
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    db["users"].insert_one({
        "username": username,
        "password": hashed,
    })
    return True, "Account created successfully."


# ── Verify login credentials ─────────────────────────────
def verify_user(username, password):
    """
    Checks username and password against the database.
    Returns user dict if valid, None if invalid.
    """
    db   = get_db()
    user = db["users"].find_one({"username": username})

    if not user:
        return None

    # Compare hashed password
    if bcrypt.checkpw(password.encode("utf-8"), user["password"]):
        return user

    return None


