import os
import requests
import logging
import sqlite3
import uuid
from flask import Flask, request, jsonify, redirect, render_template_string
from dotenv import load_dotenv
import hmac
import hashlib
import json
from datetime import datetime, timedelta

# ---------------------- [ إعداد Flask ] ----------------------
load_dotenv()
app = Flask(__name__)

# ---------------------- [ Logging ] ----------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ---------------------- [ المتغيرات ] ----------------------
CLIENT_ID = os.getenv("SALLA_CLIENT_ID")
CLIENT_SECRET = os.getenv("SALLA_CLIENT_SECRET")
WEBHOOK_SECRET = os.getenv("SALLA_WEBHOOK_SECRET")

# ---------------------- [ قاعدة البيانات ] ----------------------
# ✅ تعديل: نخزن قاعدة البيانات في /tmp عشان تشتغل على Render
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
        return new_tokens
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
    return f"""
    <h1>Salla Dashboard</h1>
    <a href="{auth_url}">Login with Salla</a><br>
    <a href="/products">إدارة المنتجات</a><br>
    <a href="/token">عرض التوكن</a>
    """


@app.route("/callback")
def callback():
    code = request.args.get("code")
    received_state = request.args.get("state")
    saved_state = get_last_state()
    if not received_state or received_state != saved_state:
        return "Error: Invalid or missing state"
    if not code:
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
        return "<h2>Success!</h2><a href='/products'>اذهب للمنتجات</a>"
    return f"Error: {response.text}"


@app.route("/token")
def token():
    token_data = get_valid_token()
    return jsonify(token_data if token_data else {"error": "No token"})

# ---------------------- [ إدارة المنتجات ] ----------------------


@app.route("/products")
def products():
    token_data = get_valid_token()
    if not token_data:
        return "<h2>Error: No valid token available</h2>"
    access_token = token_data["access_token"]
    url = "https://api.salla.dev/admin/v2/products"
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return f"<h2>Error fetching products:</h2><pre>{response.text}</pre>"
    products = response.json().get("data", [])

    html = """
    <!DOCTYPE html><html lang="ar"><head>
    <meta charset="UTF-8"><title>المنتجات</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head><body class="bg-light">
    <div class="container py-4">
        <h1 class="mb-4 text-center">🛒 إدارة المنتجات</h1>
        <div class="text-end mb-3">
            <a href="/products/add" class="btn btn-success">➕ إضافة منتج جديد</a>
        </div>
        <div class="row">
    """
    for p in products:
        product_id = p.get("id")
        image = p.get("image", {}).get("url", "https://via.placeholder.com/150")
        name = p.get("name", "بدون اسم")
        price = p.get("price", {}).get("amount", 0)
        html += f"""
        <div class="col-md-3 mb-4">
            <div class="card shadow-sm h-100">
                <img src="{image}" class="card-img-top" alt="{name}">
                <div class="card-body text-center">
                    <h5 class="card-title">{name}</h5>
                    <p class="text-success fw-bold">{price} ريال</p>
                    <form action="/products/edit/{product_id}" method="post" class="d-flex mb-2">
                        <input type="number" step="0.01" name="price" class="form-control me-2" placeholder="سعر جديد" required>
                        <button type="submit" class="btn btn-primary btn-sm">💾 تعديل</button>
                    </form>
                    <form action="/products/delete/{product_id}" method="post">
                        <button type="submit" class="btn btn-danger btn-sm">🗑️ حذف</button>
                    </form>
                </div>
            </div>
        </div>"""
    html += "</div></div></body></html>"
    return render_template_string(html)


@app.route("/products/edit/<product_id>", methods=["POST"])
def edit_product(product_id):
    new_price = request.form.get("price")

    try:
        new_price = float(new_price)  # ✅ تحويل السعر إلى رقم
    except:
        return "Error: Price must be a number"

    token_data = get_valid_token()
    if not token_data:
        return "Error: No valid token"

    access_token = token_data["access_token"]
    url = f"https://api.salla.dev/admin/v2/products/{product_id}"
    headers = {"Authorization": f"Bearer {access_token}"}
    payload = {"price": new_price}  # ✅ API يتطلب رقم مباشر

    response = requests.put(url, headers=headers, json=payload)
    if response.status_code in [200, 201]:
        return redirect("/products")
    return f"Error updating product: {response.text}"


@app.route("/products/delete/<product_id>", methods=["POST"])
def delete_product(product_id):
    token_data = get_valid_token()
    if not token_data:
        return "Error: No valid token"
    access_token = token_data["access_token"]
    url = f"https://api.salla.dev/admin/v2/products/{product_id}"
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.delete(url, headers=headers)
    if response.status_code == 200:
        return redirect("/products")
    return f"Error deleting product: {response.text}"


@app.route("/products/add", methods=["GET", "POST"])
def add_product():
    token_data = get_valid_token()
    if not token_data:
        return "Error: No valid token"
    access_token = token_data["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}

    categories_url = "https://api.salla.dev/admin/v2/categories"
    cat_res = requests.get(categories_url, headers=headers)
    categories = cat_res.json().get("data", []) if cat_res.status_code == 200 else []

    if request.method == "POST":
        name = request.form.get("name")
        price = request.form.get("price")
        image = request.form.get("image")
        category_id = request.form.get("category_id")
        status = int(request.form.get("status", 1))

        try:
            price = float(price)
        except:
            return "Error: Price must be a number"

        url = "https://api.salla.dev/admin/v2/products"
        payload = {
            "name": name,
            "price": price,  # ✅ رقم مباشر
            "image": {"url": image},
            "product_type": "physical",
            "status": status,
            "categories": [category_id]
        }
        response = requests.post(url, headers=headers, json=payload)
        if response.status_code in [200, 201]:
            return redirect("/products")
        return f"Error adding product: {response.text}"

    category_options = "".join([f'<option value="{c["id"]}">{c["name"]}</option>' for c in categories])
    return f"""
    <form action="" method="post" class="container mt-5" style="max-width:500px">
        <h2>➕ إضافة منتج جديد</h2>
        <input class="form-control mb-2" type="text" name="name" placeholder="اسم المنتج" required>
        <input class="form-control mb-2" type="number" step="0.01" name="price" placeholder="السعر" required>
        <input class="form-control mb-2" type="text" name="image" placeholder="رابط الصورة">
        <select class="form-control mb-2" name="category_id" required>
            <option value="">اختر القسم</option>{category_options}
        </select>
        <select class="form-control mb-2" name="status" required>
            <option value="1">نشط</option>
            <option value="0">غير نشط</option>
        </select>
        <button class="btn btn-success">إضافة</button>
    </form>
    """

# ----------------------

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        debug=False
    )
