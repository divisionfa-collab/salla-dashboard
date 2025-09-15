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
import time

# ---------------------- [ إعداد Flask ] ----------------------
load_dotenv()
app = Flask(__name__, static_folder="static", template_folder="templates")

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
DB_PATH = os.path.join("/tmp", "salla_store.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

def init_db():
    """إنشاء جداول قاعدة البيانات"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # جدول OAuth State
    cur.execute("""
    CREATE TABLE IF NOT EXISTS oauth_state (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        value TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    
    # جدول التوكنات
    cur.execute("""
    CREATE TABLE IF NOT EXISTS tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        access_token TEXT,
        refresh_token TEXT,
        scope TEXT,
        expires_in INTEGER,
        store_id TEXT,
        store_name TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        refresh_count INTEGER DEFAULT 0
    )""")
    
    # جدول سجل الأخطاء
    cur.execute("""
    CREATE TABLE IF NOT EXISTS error_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        error_type TEXT,
        error_message TEXT,
        endpoint TEXT,
        method TEXT,
        ip_address TEXT,
        response_code INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    
    # جدول سجل API
    cur.execute("""
    CREATE TABLE IF NOT EXISTS api_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        endpoint TEXT,
        method TEXT,
        response_code INTEGER,
        response_time_ms REAL,
        ip_address TEXT,
        success BOOLEAN,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    
    # جدول Webhooks
    cur.execute("""
    CREATE TABLE IF NOT EXISTS webhooks_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event TEXT,
        body TEXT,
        signature_valid BOOLEAN DEFAULT 0,
        ip_address TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    
    # جدول مقاييس الأداء
    cur.execute("""
    CREATE TABLE IF NOT EXISTS performance_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        endpoint TEXT,
        method TEXT,
        response_time_ms REAL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    
    # جدول أحداث الأمان
    cur.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT,
        ip_address TEXT,
        details TEXT,
        severity TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    
    conn.commit()
    conn.close()
    logger.info("✅ تم تهيئة قاعدة البيانات")

init_db()

# ---------------------- [ دوال مساعدة ] ----------------------
def log_error(error_type, error_message, endpoint=None):
    """تسجيل الأخطاء في قاعدة البيانات"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO error_logs (error_type, error_message, endpoint, method, ip_address)
            VALUES (?, ?, ?, ?, ?)
        """, (
            error_type,
            str(error_message),
            endpoint or request.endpoint if request else None,
            request.method if request else None,
            request.remote_addr if request else None
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to log error: {e}")

def log_api_call(endpoint, method, response_code, response_time, success):
    """تسجيل استدعاءات API"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO api_logs (endpoint, method, response_code, response_time_ms, ip_address, success)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            endpoint,
            method,
            response_code,
            response_time,
            request.remote_addr if request else None,
            success
        ))
        
        # إضافة إلى performance_metrics
        cur.execute("""
            INSERT INTO performance_metrics (endpoint, method, response_time_ms)
            VALUES (?, ?, ?)
        """, (endpoint, method, response_time))
        
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to log API call: {e}")

def save_state(value: str):
    """حفظ OAuth state"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO oauth_state (value, ip_address, user_agent)
        VALUES (?, ?, ?)
    """, (
        value,
        request.remote_addr if request else None,
        request.user_agent.string if request else None
    ))
    conn.commit()
    conn.close()

def get_last_state():
    """الحصول على آخر state"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT value FROM oauth_state ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

def save_token(token_data: dict):
    """حفظ التوكن"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO tokens (access_token, refresh_token, scope, expires_in, store_id, store_name)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        token_data.get("access_token"),
        token_data.get("refresh_token"),
        token_data.get("scope"),
        token_data.get("expires_in"),
        token_data.get("store_id"),
        token_data.get("store_name")
    ))
    conn.commit()
    conn.close()
    logger.info("💾 Token saved")

def get_latest_token():
    """الحصول على آخر توكن"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        SELECT access_token, refresh_token, scope, expires_in, created_at, refresh_count, store_id, store_name
        FROM tokens ORDER BY id DESC LIMIT 1
    """)
    row = cur.fetchone()
    conn.close()
    
    if row:
        return {
            "access_token": row[0],
            "refresh_token": row[1],
            "scope": row[2],
            "expires_in": row[3],
            "created_at": row[4],
            "refresh_count": row[5],
            "store_id": row[6],
            "store_name": row[7]
        }
    return None

def refresh_access_token():
    """تحديث التوكن"""
    tk = get_latest_token()
    if not tk or not tk.get("refresh_token"):
        return None
    
    try:
        data = {
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "refresh_token": tk["refresh_token"]
        }
        
        r = requests.post("https://accounts.salla.sa/oauth2/token", data=data, timeout=10)
        
        if r.status_code == 200:
            new_token = r.json()
            new_token["store_id"] = tk.get("store_id")
            new_token["store_name"] = tk.get("store_name")
            save_token(new_token)
            
            # تحديث عداد التحديثات
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("UPDATE tokens SET refresh_count = refresh_count + 1 WHERE id = (SELECT MAX(id) FROM tokens)")
            conn.commit()
            conn.close()
            
            logger.info("🔄 Token refreshed")
            return new_token
        else:
            logger.error(f"Token refresh failed: {r.status_code}")
            return None
            
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        return None

def is_token_expired(token):
    """التحقق من انتهاء صلاحية التوكن"""
    if not token:
        return True
    
    try:
        created_at = datetime.strptime(token["created_at"], "%Y-%m-%d %H:%M:%S")
        expiry_time = created_at + timedelta(seconds=token["expires_in"])
        return datetime.now() >= expiry_time
    except:
        return True

def get_valid_token():
    """الحصول على توكن صالح"""
    tk = get_latest_token()
    if not tk:
        return None
    
    if not is_token_expired(tk):
        return tk
    
    return refresh_access_token()

def get_redirect_uri():
    """الحصول على redirect URI"""
    if request and request.headers.get("X-Forwarded-Host"):
        proto = request.headers.get("X-Forwarded-Proto", "https")
        host = request.headers.get("X-Forwarded-Host")
        return f"{proto}://{host}/callback"
    return os.getenv("REDIRECT_URI", "http://localhost:8000/callback")

# ---------------------- [ Routes ] ----------------------
@app.route("/")
def dashboard():
    """لوحة التحكم الرئيسية"""
    template_path = os.path.join(app.template_folder, "dashboard_enhanced.html")
    if os.path.exists(template_path):
        return render_template("dashboard_enhanced.html")
    return render_template("dashboard.html")

@app.route("/login-link")
def login_link():
    """إنشاء رابط تسجيل الدخول"""
    start_time = time.time()
    
    try:
        redirect_uri = get_redirect_uri()
        state = str(uuid.uuid4())
        save_state(state)
        
        # جميع الصلاحيات المتاحة
        url = (
            "https://accounts.salla.sa/oauth2/auth"
            f"?response_type=code&client_id={CLIENT_ID}"
            f"&redirect_uri={redirect_uri}"
            f"&scope=offline_access"
            f"&state={state}"
        )
        
        response_time = (time.time() - start_time) * 1000
        log_api_call("/login-link", "GET", 200, response_time, True)
        
        return jsonify({"auth_url": url})
        
    except Exception as e:
        logger.error(f"Login link error: {e}")
        log_error("login_link_error", str(e))
        response_time = (time.time() - start_time) * 1000
        log_api_call("/login-link", "GET", 500, response_time, False)
        return jsonify({"error": str(e)}), 500

@app.route("/callback")
def callback():
    """OAuth callback"""
    code = request.args.get("code")
    received_state = request.args.get("state")
    error = request.args.get("error")
    error_desc = request.args.get("error_description")
    saved_state = get_last_state()
    
    logger.info(f"Callback: code={code}, state={received_state}, error={error}")
    
    if error:
        log_error("oauth_error", f"{error}: {error_desc}")
        return render_template_string("""
            <html dir="rtl">
            <head>
                <title>خطأ في المصادقة</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            </head>
            <body class="bg-light">
                <div class="container mt-5">
                    <div class="alert alert-warning">
                        <h4>⚠️ خطأ في المصادقة</h4>
                        <p>{{error_desc}}</p>
                    </div>
                    <a href="/" class="btn btn-primary">العودة للوحة التحكم</a>
                </div>
            </body>
            </html>
        """, error_desc=error_desc)
    
    if not received_state or received_state != saved_state:
        return "Error: Invalid state", 403
    
    if not code:
        return "Error: No code received", 400
    
    try:
        data = {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "redirect_uri": get_redirect_uri(),
            "code": code
        }
        
        r = requests.post("https://accounts.salla.sa/oauth2/token", data=data, timeout=15)
        
        if r.status_code == 200:
            token_data = r.json()
            
            # الحصول على معلومات المتجر
            try:
                headers = {"Authorization": f"Bearer {token_data['access_token']}"}
                store_r = requests.get("https://api.salla.dev/admin/v2/oauth2/user", headers=headers, timeout=10)
                if store_r.status_code == 200:
                    store_info = store_r.json().get("data", {})
                    token_data["store_id"] = store_info.get("id")
                    token_data["store_name"] = store_info.get("name")
                    logger.info(f"✅ متصل بمتجر: {token_data['store_name']}")
            except Exception as e:
                logger.error(f"Failed to get store info: {e}")
            
            save_token(token_data)
            
            return render_template_string("""
                <html dir="rtl">
                <head>
                    <title>تم الربط بنجاح</title>
                    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                </head>
                <body class="bg-light">
                    <div class="container mt-5">
                        <div class="alert alert-success">
                            <h2>✅ تم الربط بنجاح</h2>
                            <p>تم ربط متجرك: <strong>{{store_name}}</strong></p>
                        </div>
                        <a href="/" class="btn btn-primary">الذهاب للوحة التحكم</a>
                    </div>
                </body>
                </html>
            """, store_name=token_data.get('store_name', 'المتجر'))
        else:
            logger.error(f"Token exchange failed: {r.text}")
            return f"Error: {r.text}", 400
            
    except Exception as e:
        logger.error(f"Callback error: {e}")
        return f"Error: {str(e)}", 500

@app.route("/api/status")
def api_status():
    """حالة النظام"""
    start_time = time.time()
    
    try:
        tk = get_latest_token()
        
        # Get statistics
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        # Errors today
        cur.execute("""
            SELECT COUNT(*) FROM error_logs 
            WHERE date(created_at) = date('now')
        """)
        errors_today = cur.fetchone()[0]
        
        # API calls today
        cur.execute("""
            SELECT COUNT(*) FROM api_logs 
            WHERE date(created_at) = date('now')
        """)
        api_calls_today = cur.fetchone()[0]
        
        # Average response time
        cur.execute("""
            SELECT AVG(response_time_ms) FROM api_logs 
            WHERE date(created_at) = date('now') AND success = 1
        """)
        avg_response = cur.fetchone()[0] or 0
        
        # Security events
        cur.execute("""
            SELECT COUNT(*) FROM security_events 
            WHERE date(created_at) = date('now')
        """)
        security_events = cur.fetchone()[0]
        
        conn.close()
        
        response_time = (time.time() - start_time) * 1000
        log_api_call("/api/status", "GET", 200, response_time, True)
        
        return jsonify({
            "status": "operational",
            "client_id_exists": bool(CLIENT_ID),
            "client_secret_exists": bool(CLIENT_SECRET),
            "webhook_secret_exists": bool(WEBHOOK_SECRET),
            "redirect_uri": get_redirect_uri(),
            "token_exists": bool(tk),
            "token_expired": is_token_expired(tk) if tk else True,
            "token_created_at": tk["created_at"] if tk else None,
            "token_refresh_count": tk["refresh_count"] if tk else 0,
            "scope": tk["scope"] if tk else None,
            "store_id": tk["store_id"] if tk else None,
            "store_name": tk["store_name"] if tk else None,
            "statistics": {
                "errors_today": errors_today,
                "api_calls_today": api_calls_today,
                "avg_response_time_ms": round(avg_response, 2),
                "security_events_today": security_events
            }
        })
        
    except Exception as e:
        logger.error(f"Status error: {e}")
        log_error("status_error", str(e))
        response_time = (time.time() - start_time) * 1000
        log_api_call("/api/status", "GET", 500, response_time, False)
        return jsonify({"error": str(e)}), 500

@app.route("/api/products", methods=["GET", "POST"])
def api_products():
    """إدارة المنتجات - بيانات حقيقية من المتجر"""
    start_time = time.time()
    
    tk = get_valid_token()
    if not tk:
        response_time = (time.time() - start_time) * 1000
        log_api_call("/api/products", request.method, 401, response_time, False)
        return jsonify({"error": "no_valid_token", "message": "يرجى الربط مع المتجر أولاً"}), 401
    
    headers = {"Authorization": f"Bearer {tk['access_token']}"}
    
    try:
        if request.method == "GET":
            # معاملات البحث والفلترة
            params = {
                "page": request.args.get("page", 1),
                "per_page": request.args.get("per_page", 20)
            }
            
            # إضافة فلاتر إضافية إن وجدت
            if request.args.get("status"):
                params["status"] = request.args.get("status")
            if request.args.get("sort"):
                params["sort"] = request.args.get("sort")
            
            r = requests.get(
                "https://api.salla.dev/admin/v2/products",
                headers=headers,
                params=params,
                timeout=15
            )
            
            response_time = (time.time() - start_time) * 1000
            log_api_call("/api/products", "GET", r.status_code, response_time, r.status_code == 200)
            
            if r.status_code == 200:
                logger.info(f"✅ تم جلب المنتجات من المتجر")
                return jsonify(r.json()), 200
            else:
                logger.error(f"❌ فشل جلب المنتجات: {r.status_code}")
                return jsonify({"error": "api_error", "details": r.text}), r.status_code
        
        else:  # POST - إضافة منتج جديد
            body = request.json or {}
            
            # بناء payload للمنتج الجديد
            payload = {
                "name": body.get("name"),
                "price": float(body.get("price", 0)),
                "product_type": body.get("product_type", "product"),
                "status": body.get("status", "sale"),
                "quantity": body.get("quantity", "unlimited"),
                "sku": body.get("sku"),
                "description": body.get("description", "")
            }
            
            # إضافة الصور إن وجدت
            if body.get("image"):
                payload["images"] = [{"original": body["image"]}]
            
            r = requests.post(
                "https://api.salla.dev/admin/v2/products",
                headers=headers,
                json=payload,
                timeout=15
            )
            
            response_time = (time.time() - start_time) * 1000
            log_api_call("/api/products", "POST", r.status_code, response_time, r.status_code in [200, 201])
            
            if r.status_code in [200, 201]:
                logger.info(f"✅ تم إضافة منتج جديد: {body.get('name')}")
                return jsonify(r.json()), r.status_code
            else:
                logger.error(f"❌ فشل إضافة المنتج: {r.status_code} - {r.text}")
                return jsonify({"error": "api_error", "details": r.text}), r.status_code
            
    except Exception as e:
        logger.error(f"Products error: {e}")
        log_error("products_error", str(e))
        response_time = (time.time() - start_time) * 1000
        log_api_call("/api/products", request.method, 500, response_time, False)
        return jsonify({"error": str(e)}), 500

@app.route("/api/products/<pid>", methods=["GET", "PUT", "DELETE"])
def api_products_item(pid):
    """إدارة منتج محدد"""
    start_time = time.time()
    
    tk = get_valid_token()
    if not tk:
        response_time = (time.time() - start_time) * 1000
        log_api_call(f"/api/products/{pid}", request.method, 401, response_time, False)
        return jsonify({"error": "no_valid_token"}), 401
    
    headers = {"Authorization": f"Bearer {tk['access_token']}"}
    url = f"https://api.salla.dev/admin/v2/products/{pid}"
    
    try:
        if request.method == "GET":
            r = requests.get(url, headers=headers, timeout=10)
            
            response_time = (time.time() - start_time) * 1000
            log_api_call(f"/api/products/{pid}", "GET", r.status_code, response_time, r.status_code == 200)
            
            return jsonify(r.json()), r.status_code
            
        elif request.method == "PUT":
            body = request.json or {}
            payload = {}
            
            # حقول قابلة للتحديث
            if "price" in body:
                payload["price"] = float(body["price"])
            if "name" in body:
                payload["name"] = body["name"]
            if "quantity" in body:
                payload["quantity"] = body["quantity"]
            if "description" in body:
                payload["description"] = body["description"]
            if "status" in body:
                payload["status"] = body["status"]
            
            r = requests.put(url, headers=headers, json=payload, timeout=10)
            
            response_time = (time.time() - start_time) * 1000
            log_api_call(f"/api/products/{pid}", "PUT", r.status_code, response_time, r.status_code == 200)
            
            if r.status_code == 200:
                logger.info(f"✅ تم تحديث المنتج: {pid}")
                return jsonify(r.json()), 200
            else:
                logger.error(f"❌ فشل تحديث المنتج: {r.status_code}")
                return jsonify({"error": "update_failed", "details": r.text}), r.status_code
        
        else:  # DELETE
            r = requests.delete(url, headers=headers, timeout=10)
            
            response_time = (time.time() - start_time) * 1000
            log_api_call(f"/api/products/{pid}", "DELETE", r.status_code, response_time, r.status_code in [200, 204])
            
            if r.status_code in [200, 204]:
                logger.info(f"✅ تم حذف المنتج: {pid}")
                return jsonify({"status": "deleted", "product_id": pid}), 200
            else:
                logger.error(f"❌ فشل حذف المنتج: {r.status_code}")
                return jsonify({"error": "delete_failed", "details": r.text}), r.status_code
            
    except Exception as e:
        logger.error(f"Product {pid} error: {e}")
        log_error(f"product_{pid}_error", str(e))
        response_time = (time.time() - start_time) * 1000
        log_api_call(f"/api/products/{pid}", request.method, 500, response_time, False)
        return jsonify({"error": str(e)}), 500

@app.route("/api/orders")
def api_orders():
    """جلب الطلبات من المتجر"""
    start_time = time.time()
    
    tk = get_valid_token()
    if not tk:
        response_time = (time.time() - start_time) * 1000
        log_api_call("/api/orders", "GET", 401, response_time, False)
        return jsonify({"error": "no_valid_token"}), 401
    
    headers = {"Authorization": f"Bearer {tk['access_token']}"}
    
    try:
        params = {
            "page": request.args.get("page", 1),
            "per_page": request.args.get("per_page", 20)
        }
        
        r = requests.get(
            "https://api.salla.dev/admin/v2/orders",
            headers=headers,
            params=params,
            timeout=15
        )
        
        response_time = (time.time() - start_time) * 1000
        log_api_call("/api/orders", "GET", r.status_code, response_time, r.status_code == 200)
        
        return jsonify(r.json()), r.status_code
        
    except Exception as e:
        logger.error(f"Orders error: {e}")
        response_time = (time.time() - start_time) * 1000
        log_api_call("/api/orders", "GET", 500, response_time, False)
        return jsonify({"error": str(e)}), 500

@app.route("/api/customers")
def api_customers():
    """جلب العملاء من المتجر"""
    start_time = time.time()
    
    tk = get_valid_token()
    if not tk:
        response_time = (time.time() - start_time) * 1000
        log_api_call("/api/customers", "GET", 401, response_time, False)
        return jsonify({"error": "no_valid_token"}), 401
    
    headers = {"Authorization": f"Bearer {tk['access_token']}"}
    
    try:
        params = {
            "page": request.args.get("page", 1),
            "per_page": request.args.get("per_page", 20)
        }
        
        r = requests.get(
            "https://api.salla.dev/admin/v2/customers",
            headers=headers,
            params=params,
            timeout=15
        )
        
        response_time = (time.time() - start_time) * 1000
        log_api_call("/api/customers", "GET", r.status_code, response_time, r.status_code == 200)
        
        return jsonify(r.json()), r.status_code
        
    except Exception as e:
        logger.error(f"Customers error: {e}")
        response_time = (time.time() - start_time) * 1000
        log_api_call("/api/customers", "GET", 500, response_time, False)
        return jsonify({"error": str(e)}), 500

@app.route("/api/errors")
def api_errors():
    """جلب سجل الأخطاء"""
    try:
        limit = request.args.get("limit", 100, type=int)
        
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        cur.execute("""
            SELECT id, error_type, error_message, endpoint, method, ip_address, response_code, created_at
            FROM error_logs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        
        rows = cur.fetchall()
        conn.close()
        
        errors = []
        for row in rows:
            errors.append({
                "id": row[0],
                "type": row[1],
                "message": row[2],
                "endpoint": row[3],
                "method": row[4],
                "ip": row[5],
                "response_code": row[6],
                "timestamp": row[7]
            })
        
        return jsonify({"count": len(errors), "errors": errors})
        
    except Exception as e:
        logger.error(f"Errors fetch error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/metrics")
def api_metrics():
    """جلب مقاييس الأداء"""
    try:
        period = request.args.get("period", "24h")
        
        # Calculate time filter
        if period == "1h":
            time_filter = "datetime('now', '-1 hour')"
        elif period == "7d":
            time_filter = "datetime('now', '-7 days')"
        else:
            time_filter = "datetime('now', '-1 day')"
        
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        # Performance metrics
        cur.execute(f"""
            SELECT endpoint, COUNT(*) as count, AVG(response_time_ms) as avg_time,
                   MIN(response_time_ms) as min_time, MAX(response_time_ms) as max_time
            FROM performance_metrics
            WHERE created_at >= {time_filter}
            GROUP BY endpoint
            ORDER BY count DESC
        """)
        
        performance = []
        for row in cur.fetchall():
            performance.append({
                "endpoint": row[0],
                "count": row[1],
                "avg_time": round(row[2], 2) if row[2] else 0,
                "min_time": round(row[3], 2) if row[3] else 0,
                "max_time": round(row[4], 2) if row[4] else 0
            })
        
        # Success rate
        cur.execute(f"""
            SELECT COUNT(CASE WHEN success = 1 THEN 1 END) * 100.0 / COUNT(*) as success_rate,
                   COUNT(*) as total_calls
            FROM api_logs
            WHERE created_at >= {time_filter}
        """)
        
        row = cur.fetchone()
        success_rate = round(row[0], 2) if row[0] else 100
        total_calls = row[1] or 0
        
        conn.close()
        
        return jsonify({
            "period": period,
            "performance": performance,
            "success_rate": success_rate,
            "total_calls": total_calls
        })
        
    except Exception as e:
        logger.error(f"Metrics error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/webhooks-log")
def api_webhooks_log():
    """جلب سجل Webhooks"""
    try:
        limit = request.args.get("limit", 50, type=int)
        
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        cur.execute("""
            SELECT id, event, body, signature_valid, ip_address, created_at
            FROM webhooks_log
            ORDER BY id DESC LIMIT ?
        """, (limit,))
        
        rows = cur.fetchall()
        conn.close()
        
        items = []
        for row in rows:
            try:
                body = json.loads(row[2]) if row[2] else {}
            except:
                body = {"raw": row[2]}
            
            items.append({
                "id": row[0],
                "event": row[1],
                "body": body,
                "signature_valid": bool(row[3]),
                "ip": row[4],
                "created_at": row[5]
            })
        
        return jsonify(items)
        
    except Exception as e:
        logger.error(f"Webhooks log error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/webhook", methods=["POST"])
def webhook():
    """معالج Webhook"""
    try:
        raw = request.get_data()
        sig = request.headers.get("X-Salla-Signature")
        
        if not sig:
            logger.warning("Webhook without signature")
            return jsonify({"error": "missing_signature"}), 400
        
        if not WEBHOOK_SECRET:
            logger.warning("WEBHOOK_SECRET not configured")
            # حفظ الـ webhook بدون التحقق من التوقيع للاختبار
            payload = request.json or {}
            event = payload.get("event", "unknown")
            
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO webhooks_log (event, body, signature_valid, ip_address)
                VALUES (?, ?, ?, ?)
            """, (
                event,
                json.dumps(payload, ensure_ascii=False),
                False,
                request.remote_addr
            ))
            conn.commit()
            conn.close()
            
            logger.info(f"📩 Webhook received (no verification): {event}")
            return jsonify({"status": "ok", "warning": "no_webhook_secret"}), 200
        
        expected = hmac.new(
            WEBHOOK_SECRET.encode("utf-8"),
            raw,
            hashlib.sha256
        ).hexdigest()
        
        signature_valid = hmac.compare_digest(expected, sig)
        
        if not signature_valid:
            logger.error("Invalid webhook signature")
            return jsonify({"error": "invalid_signature"}), 403
        
        payload = request.json or {}
        event = payload.get("event", "unknown")
        
        # Save to database
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO webhooks_log (event, body, signature_valid, ip_address)
            VALUES (?, ?, ?, ?)
        """, (
            event,
            json.dumps(payload, ensure_ascii=False),
            signature_valid,
            request.remote_addr
        ))
        conn.commit()
        conn.close()
        
        logger.info(f"📩 Webhook received: {event}")
        
        # معالجة أحداث محددة
        if event == "order.created":
            logger.info(f"🛒 طلب جديد: {payload.get('data', {}).get('id')}")
        elif event == "product.created":
            logger.info(f"📦 منتج جديد: {payload.get('data', {}).get('name')}")
        elif event == "customer.created":
            logger.info(f"👤 عميل جديد: {payload.get('data', {}).get('email')}")
        
        return jsonify({"status": "ok"}), 200
        
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return jsonify({"error": "internal_error"}), 500

@app.route("/health")
def health():
    """فحص صحة النظام"""
    try:
        # Test database
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT 1")
        conn.close()
        
        # Check token
        tk = get_latest_token()
        
        return jsonify({
            "status": "healthy",
            "database": "connected",
            "token_status": "active" if tk and not is_token_expired(tk) else "expired",
            "store_connected": tk.get("store_name") if tk else None
        }), 200
        
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e)
        }), 503

# ---------------------- [ Error Handlers ] ----------------------
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "not_found"}), 404

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal error: {e}")
    return jsonify({"error": "internal_server_error"}), 500

# ---------------------- [ تشغيل ] ----------------------
if __name__ == "__main__":
    logger.info("🚀 Starting Salla Store Integration")
    logger.info("📦 Real Store Mode - No Demo Data")
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        debug=False
    )