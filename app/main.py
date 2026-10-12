import hashlib
import os
import secrets
import sqlite3
from functools import wraps
from contextlib import contextmanager
from pathlib import Path

from flask import Flask, jsonify, request, session, render_template
from werkzeug.security import check_password_hash, generate_password_hash

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "platform.db"

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


@contextmanager
def connect_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def initialize_db():
    with connect_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                key_hash TEXT UNIQUE NOT NULL,
                prefix TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                key_id INTEGER NOT NULL,
                endpoint TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
        """)


def error(message, status=400):
    return jsonify({"error": message}), status


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return error("Please log in first.", 401)
        return fn(*args, **kwargs)
    return wrapper


def authenticate_api_key():
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None

    digest = hashlib.sha256(token.encode()).hexdigest()
    with connect_db() as db:
        return db.execute("""
            SELECT id, user_id FROM api_keys
            WHERE key_hash = ? AND revoked = 0
        """, (digest,)).fetchone()


@app.get("/")
def dashboard():
    return render_template("dashboard.html")


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "Declan AI"})


@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")

    if not isinstance(password, str) or len(password) < 10:
        return error("Password must contain at least 10 characters.")
    if len(email) > 254 or "@" not in email:
        return error("Enter a valid email address.")

    try:
        with connect_db() as db:
            db.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                (email, generate_password_hash(password)),
            )
    except sqlite3.IntegrityError:
        return error("An account with that email already exists.", 409)

    return jsonify({
        "message": "Account created. Please log in.",
    }), 201


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")

    with connect_db() as db:
        user = db.execute(
            "SELECT id, password_hash FROM users WHERE email = ?",
            (email,),
        ).fetchone()

    if not user or not isinstance(password, str) or not check_password_hash(
        user["password_hash"], password
    ):
        return error("Invalid email or password.", 401)

    session.clear()
    session["user_id"] = user["id"]
    return jsonify({"message": "Logged in successfully."})


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"message": "Logged out."})


@app.post("/api/keys")
@login_required
def create_key():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "My API key")).strip()[:80]
    token = "myai_" + secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    prefix = token[:12]

    with connect_db() as db:
        cur = db.execute("""
            INSERT INTO api_keys (user_id, name, key_hash, prefix)
            VALUES (?, ?, ?, ?)
        """, (session["user_id"], name or "My API key", digest, prefix))
        key_id = cur.lastrowid

    # The complete key is shown only once.
    return jsonify({
        "id": key_id,
        "name": name or "My API key",
        "api_key": token,
        "warning": "Copy this key now. It cannot be displayed again.",
    }), 201


@app.get("/api/keys")
@login_required
def list_keys():
    with connect_db() as db:
        rows = db.execute("""
            SELECT id, name, prefix, revoked, created_at
            FROM api_keys WHERE user_id = ? ORDER BY id DESC
        """, (session["user_id"],)).fetchall()
    return jsonify({"keys": [dict(row) for row in rows]})


@app.post("/api/keys/<int:key_id>/revoke")
@login_required
def revoke_key(key_id):
    with connect_db() as db:
        cur = db.execute("""
            UPDATE api_keys SET revoked = 1
            WHERE id = ? AND user_id = ?
        """, (key_id, session["user_id"]))
    if cur.rowcount == 0:
        return error("API key not found.", 404)
    return jsonify({"message": "API key revoked."})


@app.post("/v1/chat/completions")
def chat_completions():
    key = authenticate_api_key()
    if not key:
        return error("A valid API key is required.", 401)

    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("messages"), list):
        return error("Send JSON containing a messages array.")

    # The model connection will be added and tested separately.
    with connect_db() as db:
        db.execute("""
            INSERT INTO usage (user_id, key_id, endpoint)
            VALUES (?, ?, ?)
        """, (key["user_id"], key["id"], "/v1/chat/completions"))

    return error(
        "The API key is valid, but no AI model provider is configured yet.",
        503,
    )


initialize_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)
