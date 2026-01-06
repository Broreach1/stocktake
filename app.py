import os
import sqlite3
import pandas as pd
import requests
from functools import wraps
from datetime import timedelta, datetime
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, g, flash, jsonify, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect

# ==========================
# Flask setup
# ==========================
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "super_secret_key")
csrf = CSRFProtect(app)

# ==========================
# DATABASE (Render + Local safe)
# ==========================
DATABASE = os.environ.get("DATABASE_PATH")

# If Render disk not mounted → fallback to local file
if not DATABASE:
    DATABASE = os.path.join(os.getcwd(), "pos.db")

# Try to create directory ONLY if allowed
db_dir = os.path.dirname(DATABASE)
if db_dir and not os.path.exists(db_dir):
    try:
        os.makedirs(db_dir, exist_ok=True)
    except PermissionError:
        pass  # Render handles /var/data automatically

# ==========================
# Upload config
# ==========================
UPLOAD_FOLDER = os.path.join("static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"xlsx"}

# ==========================
# Session config
# ==========================
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False

# ==========================
# Telegram config
# ==========================
TELEGRAM_BOT_TOKEN = os.environ.get(
    "TELEGRAM_BOT_TOKEN",
    "7951793613:AAFkOBGmBURAVVusTmMCW2SCkGRsCWMY1Ug"
)
TELEGRAM_CHAT_ID = os.environ.get(
    "TELEGRAM_CHAT_ID",
    "-1003244053484"
)

# ==========================
# Database helpers
# ==========================
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(
            DATABASE,
            timeout=30,
            check_same_thread=False
        )
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_database", None)
    if db:
        db.close()


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rows = cur.fetchall()
    cur.close()
    return (rows[0] if rows else None) if one else rows


def execute_db(query, args=()):
    db = get_db()
    cur = db.execute(query, args)
    db.commit()
    cur.close()


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ==========================
# Telegram sender
# ==========================
def send_telegram(text):
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            data={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": text,
                "parse_mode": "Markdown",
            },
            timeout=8,
        )
    except Exception as e:
        print("Telegram error:", e)


# ==========================
# Initialize database (FLASK 3 SAFE)
# ==========================
def init_db():
    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user'
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            sku TEXT,
            name TEXT NOT NULL,
            price REAL,
            cost REAL,
            qty INTEGER,
            min_qty INTEGER,
            barcode TEXT
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS stock_movements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            product_id INTEGER,
            change_qty INTEGER,
            reason TEXT,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        )
    """)

    db.execute("""
        INSERT OR IGNORE INTO users (username, password, role)
        VALUES (?, ?, ?)
    """, ("admin", generate_password_hash("admin123"), "admin"))

    db.commit()


# 🔥 IMPORTANT: INIT DB AT STARTUP (NO before_first_request)
with app.app_context():
    init_db()


# ==========================
# Auth helpers
# ==========================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


# ==========================
# Auth routes
# ==========================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = query_db(
            "SELECT * FROM users WHERE username=?",
            (username,),
            one=True
        )

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session.permanent = True
            return redirect(url_for("stock_page"))

        flash("❌ Invalid username or password")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


# ==========================
# Pages
# ==========================
@app.route("/")
@login_required
def stock_page():
    products = query_db("SELECT * FROM products")
    return render_template("stock.html", products=products)


# ==========================
# API: Add product
# ==========================
@app.route("/api/product/add", methods=["POST"])
@csrf.exempt
@login_required
def add_product():
    data = request.json or {}

    execute_db("""
        INSERT INTO products (user_id, name, qty, barcode)
        VALUES (?, ?, ?, ?)
    """, (
        session["user_id"],
        data.get("name"),
        int(data.get("qty") or 0),
        data.get("barcode", "")
    ))

    return jsonify(success=True)


# ==========================
# API: Remove stock
# ==========================
@app.route("/api/stock/remove", methods=["POST"])
@csrf.exempt
@login_required
def remove_stock():
    data = request.json or {}
    product_id = data.get("product_id")
    remove_qty = int(data.get("amount") or 0)
    staff = data.get("staff_name", "")

    product = query_db(
        "SELECT * FROM products WHERE id=?",
        (product_id,),
        one=True
    )

    if not product:
        return jsonify(error="Product not found"), 404

    current_qty = int(product["qty"] or 0)
    if remove_qty > current_qty:
        return jsonify(error="Not enough stock"), 400

    new_qty = current_qty - remove_qty

    execute_db(
        "UPDATE products SET qty=? WHERE id=?",
        (new_qty, product_id)
    )

    execute_db("""
        INSERT INTO stock_movements (user_id, product_id, change_qty, reason)
        VALUES (?, ?, ?, ?)
    """, (
        session["user_id"],
        product_id,
        -remove_qty,
        f"by {staff}"
    ))

    send_telegram(
        f"📦 *បានដកស្តុកចេញ*\n"
        f"🔹 *{product['name']}*\n"
        f"➖ ដកចេញ៖ {remove_qty}\n"
        f"📉 មុន៖ {current_qty} ➜ បន្ទាប់៖ {new_qty}\n"
        f"👤 អ្នកដក៖ {staff}"
    )

    return jsonify(success=True, new_qty=new_qty)


# ==========================
# Run locally only
# ==========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5009, debug=True)
