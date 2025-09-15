import os
import requests
import logging
import sqlite3
import uuid
from flask import Flask, request, jsonify, render_template, render_template_string
from dotenv import load_dotenv
from datetime import datetime, timedelta
import hmac
import hashlib
import json

# ---------------------- [ إعداد Flask ] ----------------------
load_dotenv()
app = Flask(__name__, static_folder="static", template_folder="templates")

# ---------------------- [ Logging ] ----------------------
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(os.path.join(LOG_DIR, "app.log")),
              logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# ---------------------- [ المتغيرات ] ----------------------
CLIENT_ID = os.getenv("SALLA_CLIENT_ID")
CLIENT_SECRET = os.getenv("SALLA_CLIENT_SECRET")
WEBHOOK_SECRET = os.getenv("SALLA_WEBHOOK_SECRET")

# ---------------------- [ قاعدة البيانات ] ----------------------
DB_PATH = os.path.join("/tmp", "df.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS oauth_state (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        value TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        access_token TEXT,
        refresh_token TEXT,
        scope TEXT,
        expires_in INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS webhooks_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event TEXT,
        body TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.commit()
    conn.close()

init_db()

# ---------------------- [ دوال مساعدة ] ----------------------
def save_state(value: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT INTO oauth_state (value) VALUES (?)", (value,))
    conn.commit()
    conn.close()

def get_last_state():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT value FROM oauth_state ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

def save_token(token_data: dict):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO tokens (access_token, refresh_token, scope, expires_in)
        VALUES (?, ?, ?, ?)
    """, (
        token_data.get("access_token"),
        token_data.get("refresh_token"),
        token_data.get("scope"),
        token_data.get("expires_in")
    ))
    conn.commit()
    conn.close()

def get_latest_token():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
      SELECT access_token, refresh_token, scope, expires_in, created_at
      FROM tokens ORDER BY id DESC LIMIT 1
    """)
    row = cur.fetchone()
    conn.close()
    if row:
        return {"access_token": row[0], "refresh_token": row[1],
                "scope": row[2], "expires_in": row[3], "created_at": row[4]}
    return None

def refresh_access_token():
    tk = get_latest_token()
    if not tk or not tk.get("refresh_token"):
        return None
    data = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": tk["refresh_token"]
    }
    r = requests.post("https://accounts.salla.sa/oauth2/token", data=data)
    if r.status_code == 200:
        new_t = r.json()
        save_token(new_t)
        logger.info("🔄 تم تحديث التوكن")
        return new_t
    logger.error("فشل تحديث التوكن: %s", r.text)
    return None

def is_token_expired(token):
    if not token: return True
    created_at = datetime.strptime(token["created_at"], "%Y-%m-%d %H:%M:%S")
    expiry_time = created_at + timedelta(seconds=token["expires_in"])
    return datetime.now() >= expiry_time

def get_valid_token():
    tk = get_latest_token()
    if not tk or is_token_expired(tk):
        return refresh_access_token()
    return tk

def get_redirect_uri():
    if request.headers.get("X-Forwarded-Host"):
        proto = request.headers.get("X-Forwarded-Proto", "https")
        host = request.headers.get("X-Forwarded-Host")
        return f"{proto}://{host}/callback"
    return os.getenv("REDIRECT_URI", "http://localhost:8000/callback")

# ---------------------- [ صفحات الواجهة ] ----------------------
@app.route("/")
def dashboard():
    """لوحة التحكم الرئيسية"""
    return render_template("dashboard.html")

# رابط تسجيل الدخول
@app.route("/login-link")
def login_link():
    redirect_uri = get_redirect_uri()
    state = str(uuid.uuid4())
    save_state(state)
    url = (
        "https://accounts.salla.sa/oauth2/auth"
        f"?response_type=code&client_id={CLIENT_ID}"
        f"&redirect_uri={redirect_uri}"
        f"&scope=offline_access products.read products.read_write"
        f"&state={state}"
    )
    return jsonify({"auth_url": url})

# بعد التفويض
@app.route("/callback")
def callback():
    code = request.args.get("code")
    received_state = request.args.get("state")
    saved_state = get_last_state()
    logger.info("↩️ Callback: code=%s state=%s", code, received_state)

    if not received_state or received_state != saved_state:
        return "Error: Invalid or missing state"
    if not code:
        return "Error: No code received"

    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": get_redirect_uri(),
        "code": code
    }
    r = requests.post("https://accounts.salla.sa/oauth2/token", data=data)
    if r.status_code == 200:
        save_token(r.json())
        return render_template_string(
            "<h2>✅ تم الربط بنجاح</h2><a href='/'>الرجوع للوحة التحكم</a>"
        )
    return f"Error: {r.text}"

# ---------------------- [ API للواجهة ] ----------------------
@app.route("/api/status")
def api_status():
    tk = get_latest_token()
    return jsonify({
        "client_id_exists": bool(CLIENT_ID),
        "client_secret_exists": bool(CLIENT_SECRET),
        "redirect_uri": get_redirect_uri(),
        "token_exists": bool(tk),
        "token_expired": is_token_expired(tk) if tk else True,
        "token_created_at": tk["created_at"] if tk else None,
        "scope": tk["scope"] if tk else None
    })

@app.route("/api/products", methods=["GET", "POST"])
def api_products():
    tk = get_valid_token()
    if not tk:
        return jsonify({"error": "no_valid_token"}), 401

    headers = {"Authorization": f"Bearer {tk['access_token']}"}

    if request.method == "GET":
        r = requests.get("https://api.salla.dev/admin/v2/products", headers=headers)
        return (jsonify(r.json()), r.status_code)

    # POST: إضافة منتج
    body = request.json or {}
    payload = {
        "name": body.get("name"),
        "price": float(body.get("price", 0)),
        "image": {"url": body.get("image")},
        "product_type": "physical",
        "status": int(body.get("status", 1)),
        "categories": [body.get("category_id")] if body.get("category_id") else []
    }
    r = requests.post("https://api.salla.dev/admin/v2/products", headers=headers, json=payload)
    return (jsonify(r.json()), r.status_code)

@app.route("/api/products/<pid>", methods=["PUT", "DELETE"])
def api_products_item(pid):
    tk = get_valid_token()
    if not tk:
        return jsonify({"error": "no_valid_token"}), 401

    headers = {"Authorization": f"Bearer {tk['access_token']}"}
    url = f"https://api.salla.dev/admin/v2/products/{pid}"

    if request.method == "PUT":
        body = request.json or {}
        payload = {}
        if "price" in body: payload["price"] = float(body["price"])
        if "name" in body: payload["name"] = body["name"]
        r = requests.put(url, headers=headers, json=payload)
        return (jsonify(r.json()), r.status_code)

    # DELETE
    r = requests.delete(url, headers=headers)
    return (jsonify(r.json() if r.text else {"status": "deleted"}), r.status_code)

# ---------------------- [ Webhook ] ----------------------
@app.route("/webhook", methods=["POST"])
def webhook():
    try:
        raw = request.get_data()
        sig = request.headers.get("X-Salla-Signature")
        if not sig:
            return jsonify({"error": "missing_signature"}), 400

        expected = hmac.new(WEBHOOK_SECRET.encode("utf-8"), raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return jsonify({"error": "invalid_signature"}), 403

        payload = request.json or {}
        event = payload.get("event", "unknown")

        # نسجل الحدث في DB
        conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
        cur.execute("INSERT INTO webhooks_log (event, body) VALUES (?, ?)",
                    (event, json.dumps(payload, ensure_ascii=False)))
        conn.commit(); conn.close()

        logger.info("📩 Webhook: %s", event)
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        logger.exception("webhook error")
        return jsonify({"error": "internal_error"}), 500

@app.route("/api/webhooks-log")
def api_webhooks_log():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, event, body, created_at FROM webhooks_log ORDER BY id DESC LIMIT 50")
    rows = cur.fetchall()
    conn.close()
    items = [{"id": r[0], "event": r[1], "body": json.loads(r[2]), "created_at": r[3]} for r in rows]
    return jsonify(items)

# ---------------------- [ تشغيل ] ----------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), debug=False)
