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
import traceback
from functools import wraps
import time
from enum import Enum

# ---------------------- [ إعداد Flask ] ----------------------
load_dotenv()
app = Flask(__name__, static_folder="static", template_folder="templates")

# ---------------------- [ نظام Logging متقدم ] ----------------------
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

# إعداد loggers متعددة
def setup_logging():
    # Logger عام
    general_logger = logging.getLogger("general")
    general_logger.setLevel(logging.DEBUG)
    
    # Logger للأخطاء
    error_logger = logging.getLogger("errors")
    error_logger.setLevel(logging.ERROR)
    
    # Logger للأداء
    performance_logger = logging.getLogger("performance")
    performance_logger.setLevel(logging.INFO)
    
    # Logger للأمان
    security_logger = logging.getLogger("security")
    security_logger.setLevel(logging.WARNING)
    
    # Logger لـ API
    api_logger = logging.getLogger("api")
    api_logger.setLevel(logging.INFO)
    
    # Format مفصل
    detailed_formatter = logging.Formatter(
        '%(asctime)s | %(name)s | %(levelname)s | %(funcName)s:%(lineno)d | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Handlers
    handlers = [
        ("app.log", general_logger),
        ("errors.log", error_logger),
        ("performance.log", performance_logger),
        ("security.log", security_logger),
        ("api.log", api_logger)
    ]
    
    for filename, logger in handlers:
        fh = logging.FileHandler(os.path.join(LOG_DIR, filename))
        fh.setFormatter(detailed_formatter)
        logger.addHandler(fh)
        
        # Console handler للأخطاء الحرجة
        if logger == error_logger:
            ch = logging.StreamHandler()
            ch.setFormatter(detailed_formatter)
            logger.addHandler(ch)
    
    return general_logger, error_logger, performance_logger, security_logger, api_logger

logger, error_logger, perf_logger, sec_logger, api_logger = setup_logging()

# ---------------------- [ المتغيرات ] ----------------------
CLIENT_ID = os.getenv("SALLA_CLIENT_ID")
CLIENT_SECRET = os.getenv("SALLA_CLIENT_SECRET")
WEBHOOK_SECRET = os.getenv("SALLA_WEBHOOK_SECRET")
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
DEBUG_MODE = os.getenv("DEBUG_MODE", "false").lower() == "true"

# ---------------------- [ قاعدة البيانات المحسنة ] ----------------------
DB_PATH = os.path.join("/tmp", "df_enhanced.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

def init_db():
    """إنشاء جداول قاعدة البيانات المحسنة"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # جدول OAuth
    cur.execute("""
    CREATE TABLE IF NOT EXISTS oauth_state (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        value TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP
    )""")
    
    # جدول التوكنات المحسن
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
        last_used TIMESTAMP,
        refresh_count INTEGER DEFAULT 0,
        is_active BOOLEAN DEFAULT 1
    )""")
    
    # جدول سجل الأخطاء
    cur.execute("""
    CREATE TABLE IF NOT EXISTS error_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        error_type TEXT,
        error_message TEXT,
        error_trace TEXT,
        endpoint TEXT,
        method TEXT,
        ip_address TEXT,
        user_agent TEXT,
        request_data TEXT,
        response_code INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    
    # جدول سجل API
    cur.execute("""
    CREATE TABLE IF NOT EXISTS api_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        endpoint TEXT,
        method TEXT,
        request_headers TEXT,
        request_body TEXT,
        response_code INTEGER,
        response_body TEXT,
        response_time_ms REAL,
        ip_address TEXT,
        user_agent TEXT,
        success BOOLEAN,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    
    # جدول مراقبة الأداء
    cur.execute("""
    CREATE TABLE IF NOT EXISTS performance_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        endpoint TEXT,
        method TEXT,
        response_time_ms REAL,
        memory_usage_mb REAL,
        cpu_percent REAL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    
    # جدول Webhooks المحسن
    cur.execute("""
    CREATE TABLE IF NOT EXISTS webhooks_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event TEXT,
        body TEXT,
        signature TEXT,
        signature_valid BOOLEAN,
        processing_time_ms REAL,
        ip_address TEXT,
        headers TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    
    # جدول إحصائيات النظام
    cur.execute("""
    CREATE TABLE IF NOT EXISTS system_stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stat_type TEXT,
        stat_value TEXT,
        metadata TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    
    # جدول محاولات الوصول المشبوهة
    cur.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT,
        ip_address TEXT,
        user_agent TEXT,
        details TEXT,
        severity TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    
    conn.commit()
    conn.close()
    logger.info("✅ تم إنشاء قاعدة البيانات المحسنة")

init_db()

# ---------------------- [ Decorators للمراقبة ] ----------------------
def monitor_performance(func):
    """Decorator لمراقبة أداء الدوال"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        
        try:
            result = func(*args, **kwargs)
            execution_time = (time.time() - start_time) * 1000
            
            # تسجيل الأداء
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO performance_metrics (endpoint, method, response_time_ms)
                VALUES (?, ?, ?)
            """, (request.endpoint, request.method, execution_time))
            conn.commit()
            conn.close()
            
            if execution_time > 1000:  # تحذير إذا تجاوز 1 ثانية
                perf_logger.warning(f"⚠️ Slow endpoint: {request.endpoint} took {execution_time:.2f}ms")
            
            return result
            
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            error_logger.error(f"❌ Error in {func.__name__}: {str(e)}")
            log_error(e, func.__name__)
            raise
            
    return wrapper

def track_api_call(func):
    """Decorator لتتبع استدعاءات API"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        
        # جمع معلومات الطلب
        request_data = {
            "headers": dict(request.headers),
            "body": request.get_json() if request.is_json else request.get_data(as_text=True),
            "args": dict(request.args),
            "ip": request.remote_addr,
            "user_agent": request.user_agent.string
        }
        
        try:
            response = func(*args, **kwargs)
            response_time = (time.time() - start_time) * 1000
            
            # تسجيل في قاعدة البيانات
            log_api_call(
                endpoint=request.endpoint,
                method=request.method,
                request_data=request_data,
                response_code=response[1] if isinstance(response, tuple) else 200,
                response_body=str(response[0].get_data(as_text=True)) if hasattr(response[0], 'get_data') else str(response),
                response_time=response_time,
                success=True
            )
            
            api_logger.info(f"✅ API Call: {request.method} {request.path} - {response_time:.2f}ms")
            return response
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            
            log_api_call(
                endpoint=request.endpoint,
                method=request.method,
                request_data=request_data,
                response_code=500,
                response_body=str(e),
                response_time=response_time,
                success=False
            )
            
            error_logger.error(f"❌ API Error: {request.method} {request.path} - {str(e)}")
            raise
            
    return wrapper

def require_auth(func):
    """Decorator للتحقق من المصادقة"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = get_valid_token()
        if not token:
            sec_logger.warning(f"⚠️ Unauthorized access attempt: {request.remote_addr}")
            log_security_event("unauthorized_access", request.remote_addr, "No valid token")
            return jsonify({"error": "unauthorized", "message": "No valid token"}), 401
        return func(*args, **kwargs)
    return wrapper

# ---------------------- [ دوال مساعدة محسنة ] ----------------------
def log_error(exception, context=""):
    """تسجيل الأخطاء بتفاصيل كاملة"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    error_data = {
        "type": type(exception).__name__,
        "message": str(exception),
        "trace": traceback.format_exc(),
        "context": context,
        "endpoint": request.endpoint if request else None,
        "method": request.method if request else None,
        "ip": request.remote_addr if request else None,
        "user_agent": request.user_agent.string if request else None,
        "request_data": request.get_json() if request and request.is_json else None
    }
    
    cur.execute("""
        INSERT INTO error_logs 
        (error_type, error_message, error_trace, endpoint, method, ip_address, user_agent, request_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        error_data["type"],
        error_data["message"],
        error_data["trace"],
        error_data["endpoint"],
        error_data["method"],
        error_data["ip"],
        error_data["user_agent"],
        json.dumps(error_data["request_data"]) if error_data["request_data"] else None
    ))
    
    conn.commit()
    conn.close()

def log_api_call(endpoint, method, request_data, response_code, response_body, response_time, success):
    """تسجيل استدعاءات API"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    cur.execute("""
        INSERT INTO api_logs 
        (endpoint, method, request_headers, request_body, response_code, response_body, 
         response_time_ms, ip_address, user_agent, success)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        endpoint,
        method,
        json.dumps(request_data.get("headers", {})),
        json.dumps(request_data.get("body", {})),
        response_code,
        response_body[:1000] if len(response_body) > 1000 else response_body,  # حد أقصى 1000 حرف
        response_time,
        request_data.get("ip"),
        request_data.get("user_agent"),
        success
    ))
    
    conn.commit()
    conn.close()

def log_security_event(event_type, ip_address, details, severity="MEDIUM"):
    """تسجيل أحداث الأمان"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    cur.execute("""
        INSERT INTO security_events (event_type, ip_address, user_agent, details, severity)
        VALUES (?, ?, ?, ?, ?)
    """, (
        event_type,
        ip_address,
        request.user_agent.string if request else None,
        details,
        severity
    ))
    
    conn.commit()
    conn.close()
    
    sec_logger.warning(f"🔒 Security Event: {event_type} from {ip_address} - {details}")

def save_state(value: str):
    """حفظ state مع معلومات إضافية"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    expires_at = datetime.now() + timedelta(minutes=10)  # صلاحية 10 دقائق
    
    cur.execute("""
        INSERT INTO oauth_state (value, ip_address, user_agent, expires_at)
        VALUES (?, ?, ?, ?)
    """, (
        value,
        request.remote_addr,
        request.user_agent.string,
        expires_at
    ))
    
    conn.commit()
    conn.close()
    logger.info(f"📝 Saved OAuth state: {value[:8]}...")

def validate_state(received_state):
    """التحقق من صحة state"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    cur.execute("""
        SELECT value, expires_at, ip_address 
        FROM oauth_state 
        WHERE value = ? 
        ORDER BY id DESC LIMIT 1
    """, (received_state,))
    
    row = cur.fetchone()
    conn.close()
    
    if not row:
        sec_logger.warning(f"⚠️ Invalid state attempted: {received_state[:8]}...")
        return False
    
    # التحقق من الصلاحية
    expires_at = datetime.strptime(row[1], "%Y-%m-%d %H:%M:%S")
    if datetime.now() > expires_at:
        sec_logger.warning(f"⚠️ Expired state attempted: {received_state[:8]}...")
        return False
    
    # التحقق من IP (اختياري)
    if row[2] != request.remote_addr:
        sec_logger.info(f"ℹ️ State used from different IP: original={row[2]}, current={request.remote_addr}")
    
    return True

def save_token(token_data: dict):
    """حفظ التوكن مع معلومات إضافية"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # إلغاء تفعيل التوكنات القديمة
    cur.execute("UPDATE tokens SET is_active = 0 WHERE is_active = 1")
    
    # حفظ التوكن الجديد
    cur.execute("""
        INSERT INTO tokens 
        (access_token, refresh_token, scope, expires_in, store_id, store_name, is_active)
        VALUES (?, ?, ?, ?, ?, ?, 1)
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
    logger.info("💾 Token saved successfully")

def get_latest_token():
    """الحصول على آخر توكن نشط"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    cur.execute("""
        SELECT access_token, refresh_token, scope, expires_in, created_at, 
               refresh_count, store_id, store_name
        FROM tokens 
        WHERE is_active = 1
        ORDER BY id DESC LIMIT 1
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
    """تحديث التوكن مع تتبع المحاولات"""
    tk = get_latest_token()
    if not tk or not tk.get("refresh_token"):
        error_logger.error("❌ No refresh token available")
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
            cur.execute("UPDATE tokens SET refresh_count = refresh_count + 1 WHERE is_active = 1")
            conn.commit()
            conn.close()
            
            logger.info("🔄 Token refreshed successfully")
            return new_token
        else:
            error_logger.error(f"❌ Token refresh failed: {r.status_code} - {r.text}")
            log_security_event("token_refresh_failed", request.remote_addr if request else "system", r.text)
            return None
            
    except Exception as e:
        error_logger.error(f"❌ Token refresh exception: {str(e)}")
        log_error(e, "refresh_access_token")
        return None

def is_token_expired(token):
    """التحقق من انتهاء صلاحية التوكن"""
    if not token:
        return True
    
    try:
        created_at = datetime.strptime(token["created_at"], "%Y-%m-%d %H:%M:%S")
        expiry_time = created_at + timedelta(seconds=token["expires_in"])
        is_expired = datetime.now() >= expiry_time
        
        if is_expired:
            logger.info(f"⏰ Token expired at {expiry_time}")
        
        return is_expired
    except Exception as e:
        error_logger.error(f"❌ Error checking token expiry: {str(e)}")
        return True

def get_valid_token():
    """الحصول على توكن صالح مع إعادة المحاولة"""
    max_retries = 3
    retry_count = 0
    
    while retry_count < max_retries:
        tk = get_latest_token()
        
        if not tk:
            logger.warning("⚠️ No token found")
            return None
        
        if not is_token_expired(tk):
            # تحديث وقت آخر استخدام
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("UPDATE tokens SET last_used = CURRENT_TIMESTAMP WHERE is_active = 1")
            conn.commit()
            conn.close()
            
            return tk
        
        logger.info(f"🔄 Token expired, attempting refresh (attempt {retry_count + 1}/{max_retries})")
        new_token = refresh_access_token()
        
        if new_token:
            return new_token
        
        retry_count += 1
        time.sleep(1)  # انتظار ثانية قبل المحاولة التالية
    
    error_logger.error(f"❌ Failed to get valid token after {max_retries} attempts")
    return None

def get_redirect_uri():
    """الحصول على redirect URI"""
    if request.headers.get("X-Forwarded-Host"):
        proto = request.headers.get("X-Forwarded-Proto", "https")
        host = request.headers.get("X-Forwarded-Host")
        return f"{proto}://{host}/callback"
    return os.getenv("REDIRECT_URI", "http://localhost:8000/callback")

# ---------------------- [ صفحات الواجهة ] ----------------------
@app.route("/")
@monitor_performance
def dashboard():
    """لوحة التحكم الرئيسية المحسنة"""
    return render_template("dashboard_enhanced.html")

@app.route("/monitoring")
@monitor_performance
def monitoring():
    """صفحة المراقبة المتقدمة"""
    return render_template("monitoring.html")

# ---------------------- [ OAuth Endpoints ] ----------------------
@app.route("/login-link")
@track_api_call
@monitor_performance
def login_link():
    """إنشاء رابط تسجيل الدخول"""
    try:
        redirect_uri = get_redirect_uri()
        state = str(uuid.uuid4())
        save_state(state)
        
        url = (
            "https://accounts.salla.sa/oauth2/auth"
            f"?response_type=code&client_id={CLIENT_ID}"
            f"&redirect_uri={redirect_uri}"
            f"&scope=offline_access products.read products.write orders.read customers.read"
            f"&state={state}"
        )
        
        logger.info(f"🔗 Generated login URL for {request.remote_addr}")
        return jsonify({"auth_url": url, "state": state[:8] + "..."})
        
    except Exception as e:
        error_logger.error(f"❌ Failed to generate login link: {str(e)}")
        log_error(e, "login_link")
        return jsonify({"error": "failed_to_generate_link", "message": str(e)}), 500

@app.route("/callback")
@monitor_performance
def callback():
    """معالج callback OAuth"""
    code = request.args.get("code")
    received_state = request.args.get("state")
    error = request.args.get("error")
    
    logger.info(f"↩️ OAuth callback: code={code[:8] if code else 'None'}... state={received_state[:8] if received_state else 'None'}...")
    
    # التحقق من الأخطاء
    if error:
        error_msg = request.args.get("error_description", "Unknown error")
        error_logger.error(f"❌ OAuth error: {error} - {error_msg}")
        log_security_event("oauth_error", request.remote_addr, f"{error}: {error_msg}")
        return render_template_string(
            "<h2>❌ خطأ في المصادقة</h2><p>{{error}}: {{desc}}</p><a href='/'>العودة</a>",
            error=error, desc=error_msg
        )
    
    # التحقق من State
    if not received_state or not validate_state(received_state):
        sec_logger.error(f"🔒 Invalid state in callback from {request.remote_addr}")
        log_security_event("invalid_state", request.remote_addr, f"State: {received_state[:8] if received_state else 'None'}...", "HIGH")
        return render_template_string(
            "<h2>❌ خطأ أمني</h2><p>State غير صحيح</p><a href='/'>العودة</a>"
        ), 403
    
    # التحقق من Code
    if not code:
        error_logger.error("❌ No authorization code received")
        return render_template_string(
            "<h2>❌ خطأ</h2><p>لم يتم استلام كود المصادقة</p><a href='/'>العودة</a>"
        ), 400
    
    try:
        # طلب التوكن
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
            
            # محاولة الحصول على معلومات المتجر
            try:
                headers = {"Authorization": f"Bearer {token_data['access_token']}"}
                store_r = requests.get("https://api.salla.dev/admin/v2/oauth2/user", headers=headers, timeout=10)
                if store_r.status_code == 200:
                    store_info = store_r.json().get("data", {})
                    token_data["store_id"] = store_info.get("id")
                    token_data["store_name"] = store_info.get("name")
            except:
                pass
            
            save_token(token_data)
            logger.info(f"✅ OAuth completed successfully for store: {token_data.get('store_name', 'Unknown')}")
            
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
                            <p>تم ربط حسابك بنجاح مع متجر: <strong>{{store_name}}</strong></p>
                        </div>
                        <a href="/" class="btn btn-primary">الذهاب للوحة التحكم</a>
                    </div>
                </body>
                </html>
            """, store_name=token_data.get('store_name', 'غير محدد'))
            
        else:
            error_logger.error(f"❌ Token exchange failed: {r.status_code} - {r.text}")
            log_security_event("token_exchange_failed", request.remote_addr, r.text)
            return render_template_string(
                "<h2>❌ فشل تبادل التوكن</h2><p>{{error}}</p><a href='/'>العودة</a>",
                error=r.text
            ), 400
            
    except Exception as e:
        error_logger.error(f"❌ Callback exception: {str(e)}")
        log_error(e, "callback")
        return render_template_string(
            "<h2>❌ خطأ في النظام</h2><p>{{error}}</p><a href='/'>العودة</a>",
            error=str(e)
        ), 500

# ---------------------- [ API Endpoints ] ----------------------
@app.route("/api/status")
@track_api_call
@monitor_performance
def api_status():
    """حالة النظام الشاملة"""
    try:
        tk = get_latest_token()
        
        # إحصائيات من قاعدة البيانات
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        # عدد الأخطاء اليوم
        cur.execute("""
            SELECT COUNT(*) FROM error_logs 
            WHERE date(created_at) = date('now')
        """)
        errors_today = cur.fetchone()[0]
        
        # عدد استدعاءات API اليوم
        cur.execute("""
            SELECT COUNT(*) FROM api_logs 
            WHERE date(created_at) = date('now')
        """)
        api_calls_today = cur.fetchone()[0]
        
        # متوسط وقت الاستجابة
        cur.execute("""
            SELECT AVG(response_time_ms) FROM api_logs 
            WHERE date(created_at) = date('now') AND success = 1
        """)
        avg_response = cur.fetchone()[0] or 0
        
        # أحداث الأمان
        cur.execute("""
            SELECT COUNT(*) FROM security_events 
            WHERE date(created_at) = date('now')
        """)
        security_events = cur.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            "status": "operational",
            "environment": ENVIRONMENT,
            "debug_mode": DEBUG_MODE,
            "credentials": {
                "client_id_exists": bool(CLIENT_ID),
                "client_secret_exists": bool(CLIENT_SECRET),
                "webhook_secret_exists": bool(WEBHOOK_SECRET)
            },
            "oauth": {
                "redirect_uri": get_redirect_uri(),
                "token_exists": bool(tk),
                "token_expired": is_token_expired(tk) if tk else True,
                "token_created_at": tk["created_at"] if tk else None,
                "token_refresh_count": tk["refresh_count"] if tk else 0,
                "scope": tk["scope"] if tk else None,
                "store_id": tk["store_id"] if tk else None,
                "store_name": tk["store_name"] if tk else None
            },
            "statistics": {
                "errors_today": errors_today,
                "api_calls_today": api_calls_today,
                "avg_response_time_ms": round(avg_response, 2),
                "security_events_today": security_events
            },
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        error_logger.error(f"❌ Status endpoint error: {str(e)}")
        log_error(e, "api_status")
        return jsonify({"error": "internal_error", "message": str(e)}), 500

@app.route("/api/products", methods=["GET", "POST"])
@track_api_call
@monitor_performance
@require_auth
def api_products():
    """إدارة المنتجات مع تتبع محسن"""
    tk = get_valid_token()
    headers = {"Authorization": f"Bearer {tk['access_token']}"}
    
    try:
        if request.method == "GET":
            # جلب المنتجات مع معاملات البحث
            params = {
                "page": request.args.get("page", 1),
                "per_page": request.args.get("per_page", 20),
                "status": request.args.get("status"),
                "sort": request.args.get("sort", "created_at"),
                "direction": request.args.get("direction", "desc")
            }
            
            # إزالة المعاملات الفارغة
            params = {k: v for k, v in params.items() if v is not None}
            
            r = requests.get(
                "https://api.salla.dev/admin/v2/products",
                headers=headers,
                params=params,
                timeout=15
            )
            
            if r.status_code == 200:
                api_logger.info(f"✅ Retrieved products: page={params.get('page')}")
                return jsonify(r.json()), 200
            else:
                error_logger.error(f"❌ Failed to get products: {r.status_code}")
                return jsonify({"error": "api_error", "details": r.text}), r.status_code
        
        else:  # POST
            body = request.json or {}
            
            # التحقق من البيانات المطلوبة
            if not body.get("name"):
                return jsonify({"error": "validation_error", "message": "Product name is required"}), 400
            
            payload = {
                "name": body.get("name"),
                "price": float(body.get("price", 0)),
                "product_type": body.get("product_type", "physical"),
                "status": body.get("status", "available"),
                "description": body.get("description", ""),
                "sku": body.get("sku"),
                "quantity": body.get("quantity", 0),
                "categories": body.get("categories", [])
            }
            
            # إضافة الصورة إذا وجدت
            if body.get("image"):
                payload["images"] = [{"original": body["image"]}]
            
            r = requests.post(
                "https://api.salla.dev/admin/v2/products",
                headers=headers,
                json=payload,
                timeout=15
            )
            
            if r.status_code in [200, 201]:
                api_logger.info(f"✅ Product created: {body.get('name')}")
                return jsonify(r.json()), r.status_code
            else:
                error_logger.error(f"❌ Failed to create product: {r.status_code} - {r.text}")
                return jsonify({"error": "api_error", "details": r.text}), r.status_code
                
    except Exception as e:
        error_logger.error(f"❌ Products endpoint error: {str(e)}")
        log_error(e, "api_products")
        return jsonify({"error": "internal_error", "message": str(e)}), 500

@app.route("/api/products/<pid>", methods=["GET", "PUT", "DELETE"])
@track_api_call
@monitor_performance
@require_auth
def api_products_item(pid):
    """إدارة منتج محدد"""
    tk = get_valid_token()
    headers = {"Authorization": f"Bearer {tk['access_token']}"}
    url = f"https://api.salla.dev/admin/v2/products/{pid}"
    
    try:
        if request.method == "GET":
            r = requests.get(url, headers=headers, timeout=10)
            
            if r.status_code == 200:
                api_logger.info(f"✅ Retrieved product: {pid}")
                return jsonify(r.json()), 200
            else:
                error_logger.error(f"❌ Failed to get product {pid}: {r.status_code}")
                return jsonify({"error": "not_found"}), 404
        
        elif request.method == "PUT":
            body = request.json or {}
            
            # بناء payload للتحديث
            payload = {}
            updateable_fields = ["name", "price", "description", "sku", "quantity", "status"]
            
            for field in updateable_fields:
                if field in body:
                    payload[field] = body[field]
            
            if not payload:
                return jsonify({"error": "no_fields_to_update"}), 400
            
            r = requests.put(url, headers=headers, json=payload, timeout=10)
            
            if r.status_code == 200:
                api_logger.info(f"✅ Updated product {pid}: {list(payload.keys())}")
                return jsonify(r.json()), 200
            else:
                error_logger.error(f"❌ Failed to update product {pid}: {r.status_code}")
                return jsonify({"error": "update_failed", "details": r.text}), r.status_code
        
        else:  # DELETE
            r = requests.delete(url, headers=headers, timeout=10)
            
            if r.status_code in [200, 204]:
                api_logger.info(f"✅ Deleted product: {pid}")
                return jsonify({"status": "deleted", "product_id": pid}), 200
            else:
                error_logger.error(f"❌ Failed to delete product {pid}: {r.status_code}")
                return jsonify({"error": "delete_failed", "details": r.text}), r.status_code
                
    except Exception as e:
        error_logger.error(f"❌ Product {pid} operation error: {str(e)}")
        log_error(e, f"api_products_item_{request.method}")
        return jsonify({"error": "internal_error", "message": str(e)}), 500

# ---------------------- [ Monitoring Endpoints ] ----------------------
@app.route("/api/errors")
@track_api_call
@monitor_performance
def api_errors():
    """جلب سجل الأخطاء"""
    try:
        limit = request.args.get("limit", 100, type=int)
        severity = request.args.get("severity")
        
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        query = """
            SELECT id, error_type, error_message, endpoint, method, 
                   ip_address, response_code, created_at
            FROM error_logs
            ORDER BY id DESC
            LIMIT ?
        """
        
        cur.execute(query, (limit,))
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
        
        return jsonify({
            "count": len(errors),
            "errors": errors
        })
        
    except Exception as e:
        error_logger.error(f"❌ Error fetching error logs: {str(e)}")
        return jsonify({"error": "internal_error"}), 500

@app.route("/api/metrics")
@track_api_call
@monitor_performance
def api_metrics():
    """جلب مقاييس الأداء"""
    try:
        period = request.args.get("period", "1h")  # 1h, 24h, 7d
        
        # حساب الفترة الزمنية
        if period == "1h":
            time_filter = "datetime('now', '-1 hour')"
        elif period == "24h":
            time_filter = "datetime('now', '-1 day')"
        elif period == "7d":
            time_filter = "datetime('now', '-7 days')"
        else:
            time_filter = "datetime('now', '-1 hour')"
        
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        # مقاييس الأداء
        cur.execute(f"""
            SELECT 
                endpoint,
                COUNT(*) as count,
                AVG(response_time_ms) as avg_time,
                MIN(response_time_ms) as min_time,
                MAX(response_time_ms) as max_time
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
        
        # نسبة النجاح
        cur.execute(f"""
            SELECT 
                COUNT(CASE WHEN success = 1 THEN 1 END) * 100.0 / COUNT(*) as success_rate,
                COUNT(*) as total_calls
            FROM api_logs
            WHERE created_at >= {time_filter}
        """)
        
        row = cur.fetchone()
        success_rate = round(row[0], 2) if row[0] else 0
        total_calls = row[1] or 0
        
        conn.close()
        
        return jsonify({
            "period": period,
            "performance": performance,
            "success_rate": success_rate,
            "total_calls": total_calls,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        error_logger.error(f"❌ Error fetching metrics: {str(e)}")
        return jsonify({"error": "internal_error"}), 500

@app.route("/api/security-events")
@track_api_call
@monitor_performance
def api_security_events():
    """جلب أحداث الأمان"""
    try:
        limit = request.args.get("limit", 50, type=int)
        severity = request.args.get("severity")
        
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        if severity:
            cur.execute("""
                SELECT * FROM security_events 
                WHERE severity = ?
                ORDER BY id DESC LIMIT ?
            """, (severity, limit))
        else:
            cur.execute("""
                SELECT * FROM security_events 
                ORDER BY id DESC LIMIT ?
            """, (limit,))
        
        rows = cur.fetchall()
        conn.close()
        
        events = []
        for row in rows:
            events.append({
                "id": row[0],
                "type": row[1],
                "ip": row[2],
                "user_agent": row[3],
                "details": row[4],
                "severity": row[5],
                "timestamp": row[6]
            })
        
        return jsonify({
            "count": len(events),
            "events": events
        })
        
    except Exception as e:
        error_logger.error(f"❌ Error fetching security events: {str(e)}")
        return jsonify({"error": "internal_error"}), 500

# ---------------------- [ Webhook ] ----------------------
@app.route("/webhook", methods=["POST"])
@monitor_performance
def webhook():
    """معالج Webhook محسن"""
    start_time = time.time()
    
    try:
        raw = request.get_data()
        sig = request.headers.get("X-Salla-Signature")
        
        if not sig:
            sec_logger.warning(f"⚠️ Webhook without signature from {request.remote_addr}")
            log_security_event("webhook_no_signature", request.remote_addr, "Missing signature", "HIGH")
            return jsonify({"error": "missing_signature"}), 400
        
        # التحقق من التوقيع
        expected = hmac.new(
            WEBHOOK_SECRET.encode("utf-8"),
            raw,
            hashlib.sha256
        ).hexdigest()
        
        signature_valid = hmac.compare_digest(expected, sig)
        
        if not signature_valid:
            sec_logger.error(f"🔒 Invalid webhook signature from {request.remote_addr}")
            log_security_event("webhook_invalid_signature", request.remote_addr, f"Signature: {sig[:10]}...", "CRITICAL")
            return jsonify({"error": "invalid_signature"}), 403
        
        payload = request.json or {}
        event = payload.get("event", "unknown")
        
        # تسجيل الحدث
        processing_time = (time.time() - start_time) * 1000
        
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO webhooks_log 
            (event, body, signature, signature_valid, processing_time_ms, ip_address, headers)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            event,
            json.dumps(payload, ensure_ascii=False),
            sig[:20] + "...",  # حفظ جزء من التوقيع فقط
            signature_valid,
            processing_time,
            request.remote_addr,
            json.dumps(dict(request.headers))
        ))
        conn.commit()
        conn.close()
        
        api_logger.info(f"📩 Webhook received: {event} - {processing_time:.2f}ms")
        
        # معالجة الأحداث المختلفة
        if event == "order.created":
            logger.info(f"🛒 New order: {payload.get('data', {}).get('id')}")
        elif event == "product.updated":
            logger.info(f"📦 Product updated: {payload.get('data', {}).get('id')}")
        
        return jsonify({"status": "ok", "event": event}), 200
        
    except Exception as e:
        error_logger.error(f"❌ Webhook error: {str(e)}")
        log_error(e, "webhook")
        return jsonify({"error": "internal_error"}), 500

@app.route("/api/webhooks-log")
@track_api_call
@monitor_performance
def api_webhooks_log():
    """جلب سجل Webhooks"""
    try:
        limit = request.args.get("limit", 50, type=int)
        event_type = request.args.get("event")
        
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        if event_type:
            cur.execute("""
                SELECT id, event, body, signature_valid, processing_time_ms, 
                       ip_address, created_at
                FROM webhooks_log
                WHERE event = ?
                ORDER BY id DESC LIMIT ?
            """, (event_type, limit))
        else:
            cur.execute("""
                SELECT id, event, body, signature_valid, processing_time_ms, 
                       ip_address, created_at
                FROM webhooks_log
                ORDER BY id DESC LIMIT ?
            """, (limit,))
        
        rows = cur.fetchall()
        conn.close()
        
        items = []
        for row in rows:
            items.append({
                "id": row[0],
                "event": row[1],
                "body": json.loads(row[2]),
                "signature_valid": bool(row[3]),
                "processing_time_ms": row[4],
                "ip": row[5],
                "timestamp": row[6]
            })
        
        return jsonify({
            "count": len(items),
            "webhooks": items
        })
        
    except Exception as e:
        error_logger.error(f"❌ Error fetching webhooks: {str(e)}")
        return jsonify({"error": "internal_error"}), 500

# ---------------------- [ Health Check ] ----------------------
@app.route("/health")
def health_check():
    """فحص صحة النظام"""
    try:
        # فحص قاعدة البيانات
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT 1")
        conn.close()
        
        # فحص التوكن
        token_status = "healthy" if get_latest_token() else "warning"
        
        return jsonify({
            "status": "healthy",
            "database": "connected",
            "token": token_status,
            "timestamp": datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        error_logger.error(f"❌ Health check failed: {str(e)}")
        return jsonify({
            "status": "unhealthy",
            "error": str(e)
        }), 503

# ---------------------- [ Error Handlers ] ----------------------
@app.errorhandler(404)
def not_found(e):
    """معالج 404"""
    logger.warning(f"⚠️ 404: {request.path}")
    return jsonify({"error": "not_found", "path": request.path}), 404

@app.errorhandler(500)
def internal_error(e):
    """معالج 500"""
    error_logger.error(f"❌ 500 Internal Error: {str(e)}")
    log_error(e, "internal_error")
    return jsonify({"error": "internal_server_error"}), 500

# ---------------------- [ تشغيل ] ----------------------
if __name__ == "__main__":
    logger.info("🚀 Starting Enhanced Salla Integration App")
    logger.info(f"📊 Environment: {ENVIRONMENT}")
    logger.info(f"🐛 Debug Mode: {DEBUG_MODE}")
    
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        debug=DEBUG_MODE
    )