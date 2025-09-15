import os
import requests
import logging
import sqlite3
import uuid
from flask import Flask, request, jsonify, redirect, render_template_string
from dotenv import load_dotenv
from datetime import datetime, timedelta
import hmac
import hashlib
import json

# ---------------------- [ إعداد Flask ] ----------------------
load_dotenv()
app = Flask(__name__)

# ---------------------- [ Logging ] ----------------------
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "app.log")),
        logging.StreamHandler()
    ]
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
    conn.commit()
    conn.close()

init_db()

# ---------------------- [ دوال مساعدة ] ----------------------
def save_state(state_value: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT INTO oauth_state (value) VALUES (?)", (state_value,))
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
    cur.execute("SELECT access_token, refresh_token, scope, expires_in, created_at FROM tokens ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    conn.close()
    if row:
        return {
            "access_token": row[0],
            "refresh_token": row[1],
            "scope": row[2],
            "expires_in": row[3],
            "created_at": row[4]
        }
    return None

def refresh_access_token():
    token_data = get_latest_token()
    if not token_data or not token_data.get("refresh_token"):
        return None
    refresh_token = token_data["refresh_token"]
    data = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": refresh_token
    }
    response = requests.post("https://accounts.salla.sa/oauth2/token", data=data)
    if response.status_code == 200:
        new_tokens = response.json()
        save_token(new_tokens)
        logger.info("🔄 Token refreshed بنجاح")
        return new_tokens
    logger.error("⚠️ فشل تحديث التوكن: %s", response.text)
    return None

def is_token_expired(token_data):
    if not token_data:
        return True
    created_at = datetime.strptime(token_data["created_at"], "%Y-%m-%d %H:%M:%S")
    expires_in = token_data["expires_in"]
    expiry_time = created_at + timedelta(seconds=expires_in)
    return datetime.now() >= expiry_time

def get_valid_token():
    token_data = get_latest_token()
    if not token_data or is_token_expired(token_data):
        return refresh_access_token()
    return token_data

def get_redirect_uri():
    if request.headers.get("X-Forwarded-Host"):
        protocol = request.headers.get("X-Forwarded-Proto", "https")
        host = request.headers.get("X-Forwarded-Host")
        return f"{protocol}://{host}/callback"
    return os.getenv("REDIRECT_URI", "http://localhost:8000/callback")

# ---------------------- [ Routes ] ----------------------
@app.route("/")
def home():
    redirect_uri = get_redirect_uri()
    state = str(uuid.uuid4())
    save_state(state)
    auth_url = (
        f"https://accounts.salla.sa/oauth2/auth"
        f"?response_type=code"
        f"&client_id={CLIENT_ID}"
        f"&redirect_uri={redirect_uri}"
        f"&scope=offline_access products.read products.read_write"
        f"&state={state}"
    )
    logger.info("🏠 Home page opened. Redirect URI: %s", redirect_uri)
    return f"""
    <h1>Salla Dashboard</h1>
    <a href="{auth_url}">Login with Salla</a><br>
    <a href="/products">إدارة المنتجات</a><br>
    <a href="/token">عرض التوكن</a><br>
    <a href="/debug">Debug Info</a><br>
    <a href="/webhook-test">Webhook Test</a>
    """

@app.route("/callback")
def callback():
    code = request.args.get("code")
    received_state = request.args.get("state")
    saved_state = get_last_state()
    logger.info("↩️ Callback received. code=%s state=%s", code, received_state)

    if not received_state or received_state != saved_state:
        logger.error("❌ Invalid or missing state")
        return "Error: Invalid or missing state"
    if not code:
        logger.error("❌ No code received")
        return "Error: No code received"

    redirect_uri = get_redirect_uri()
    token_url = "https://accounts.salla.sa/oauth2/token"
    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": redirect_uri,
        "code": code
    }
    response = requests.post(token_url, data=data)
    if response.status_code == 200:
        token_data = response.json()
        save_token(token_data)
        logger.info("✅ Access token saved بنجاح")
        return "<h2>Success!</h2><a href='/products'>اذهب للمنتجات</a>"
    logger.error("⚠️ Error fetching token: %s", response.text)
    return f"Error: {response.text}"

@app.route("/token")
def token():
    token_data = get_valid_token()
    logger.info("🔑 Token checked: %s", "Available" if token_data else "Not available")
    return jsonify(token_data if token_data else {"error": "No token"})

@app.route("/products")
def products():
    logger.info("📦 طلب صفحة المنتجات")
    token_data = get_valid_token()
    if not token_data:
        logger.error("❌ No valid token موجود")
        return "<h2>Error: No valid token available</h2>"

    access_token = token_data["access_token"]
    url = "https://api.salla.dev/admin/v2/products"
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        logger.error("⚠️ Error fetching products: %s", response.text)
        return f"<h2>Error fetching products:</h2><pre>{response.text}</pre>"

    products = response.json().get("data", [])
    logger.info("✅ عدد المنتجات: %d", len(products))

    html = "<h1>🛒 المنتجات</h1><ul>"
    for p in products:
        html += f"<li>{p.get('name', 'بدون اسم')} - {p.get('price', {}).get('amount', 0)} ريال</li>"
    html += "</ul>"
    return render_template_string(html)

@app.route("/webhook", methods=["POST"])
def webhook():
    try:
        raw_body = request.get_data()
        signature = request.headers.get("X-Salla-Signature")

        if not signature:
            logger.warning("❌ Webhook بدون توقيع")
            return jsonify({"error": "Missing signature"}), 400

        expected_signature = hmac.new(
            WEBHOOK_SECRET.encode("utf-8"),
            raw_body,
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected_signature, signature):
            logger.warning("⚠️ توقيع غير صالح للويب هوك")
            return jsonify({"error": "Invalid signature"}), 403

        payload = request.json
        event_type = payload.get("event", "unknown")

        logger.info(f"📩 Webhook مستلم: {event_type}")
        logger.debug(f"Payload: {json.dumps(payload, ensure_ascii=False)}")

        return jsonify({"status": "success"}), 200

    except Exception as e:
        logger.error(f"❌ خطأ في معالجة Webhook: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500

@app.route("/debug")
def debug():
    token_data = get_latest_token()
    redirect_uri = get_redirect_uri()
    logger.info("🔍 Debug endpoint checked")
    return jsonify({
        "client_id": CLIENT_ID,
        "client_secret_exists": bool(CLIENT_SECRET),
        "redirect_uri": redirect_uri,
        "latest_token": token_data if token_data else "No token stored"
    })

@app.route("/webhook-test")
def webhook_test():
    return "<h2>🚀 Webhook Test Route جاهز</h2>"

# ----------------------
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        debug=False
    )
