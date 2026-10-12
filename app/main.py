import hashlib
import json
import os
import urllib.error
import urllib.request
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

    messages = data["messages"]
    if not messages:
        return error("The messages array cannot be empty.")

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return error("No AI model provider is configured.", 503)

    contents = []
    system_parts = []

    for message in messages:
        if not isinstance(message, dict):
            return error("Each message must be an object.")

        role = message.get("role")
        content = message.get("content")

        if role not in ("system", "user", "assistant") or not isinstance(content, str):
            return error("Each message needs a supported role and string content.")

        if role == "system":
            system_parts.append({"text": content})
        else:
            contents.append({
                "role": "model" if role == "assistant" else "user",
                "parts": [{"text": content}],
            })

    if not contents:
        return error("At least one user or assistant message is required.")

    payload = {"contents": contents}
    if system_parts:
        payload["systemInstruction"] = {"parts": system_parts}

    generation_config = {}
    if isinstance(data.get("temperature"), (int, float)):
        generation_config["temperature"] = max(
            0, min(2, data["temperature"])
        )
    if isinstance(data.get("max_tokens"), int):
        generation_config["maxOutputTokens"] = max(
            1, min(8192, data["max_tokens"])
        )
    if generation_config:
        payload["generationConfig"] = generation_config

    url = (
        "https://generativelanguage.googleapis.com/v1beta/"
        "models/gemini-2.5-flash:generateContent"
    )
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": api_key,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        provider_status = ""
        provider_message = ""
        try:
            body = json.loads(exc.read().decode("utf-8"))
            details = body.get("error", {}) if isinstance(body, dict) else {}
            if isinstance(details, dict):
                provider_status = str(details.get("status", ""))[:80]
                provider_message = str(details.get("message", ""))[:500]
        except (ValueError, UnicodeDecodeError):
            pass

        app.logger.warning(
            "Gemini HTTP error: code=%s status=%s message=%s",
            exc.code, provider_status, provider_message,
        )

        if exc.code in (401, 403):
            return error("The AI provider rejected its configured credentials.", 502)
        if exc.code == 429:
            return error("The AI provider rate limit or quota was reached.", 429)
        return error("The AI provider returned an error.", 502)
    except (urllib.error.URLError, TimeoutError):
        return error("The AI provider could not be reached. Please retry.", 502)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return error("The AI provider returned an invalid response.", 502)

    candidates = result.get("candidates", [])
    if not candidates:
        return error("The AI provider returned no answer.", 502)

    parts = candidates[0].get("content", {}).get("parts", [])
    answer = "".join(
        part.get("text", "") for part in parts if isinstance(part, dict)
    )
    if not answer:
        return error("The AI provider returned no text answer.", 502)

    with connect_db() as db:
        db.execute("""
            INSERT INTO usage (user_id, key_id, endpoint)
            VALUES (?, ?, ?)
        """, (key["user_id"], key["id"], "/v1/chat/completions"))

    usage = result.get("usageMetadata", {})
    return jsonify({
        "id": "declan-" + secrets.token_hex(12),
        "object": "chat.completion",
        "created": int(__import__("time").time()),
        "model": data.get("model", "gemini-2.5-flash"),
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": answer},
            "finish_reason": "stop",
        }],
        "usage": {
            "prompt_tokens": usage.get("promptTokenCount", 0),
            "completion_tokens": usage.get("candidatesTokenCount", 0),
            "total_tokens": usage.get("totalTokenCount", 0),
        },
    })


initialize_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)
