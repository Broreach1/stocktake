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

# --------------------------
# Flask setup
# --------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "super_secret_key")
csrf = CSRFProtect(app)

# ==========================
# ✅ RENDER PERSISTENT DATABASE
# ==========================
DATABASE = os.environ.get("DATABASE_PATH", "/var/data/pos.db")
os.makedirs(os.path.dirname(DATABASE), exist_ok=True)

UPLOAD_FOLDER = os.path.join("static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"xlsx"}

# --- Remember me (30 days) ---
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False

# Telegram Config (unchanged)
TELEGRAM_BOT_TOKEN = os.environ.get(
    "TELEGRAM_BOT_TOKEN",
    "7951793613:AAFkOBGmBURAVVusTmMCW2SCkGRsCWMY1Ug"
)
TELEGRAM_CHAT_ID = os.environ.get(
    "TELEGRAM_CHAT_ID",
    "-1003244053484"
)

# --------------------------
# DB helpers
# --------------------------
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
def close_connection(exception):
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


# --------------------------
# Initialize DB
# --------------------------
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
        CREATE TABLE IF NOT EXISTS stocktake_drafts (
            user_id INTEGER,
            product_id INTEGER,
            qty INTEGER,
            PRIMARY KEY (user_id, product_id)
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


# ==========================
# ✅ AUTO INIT DB ON RENDER
# ==========================
@app.before_first_request
def auto_init_db():
    init_db()


# --------------------------
# Auth helpers
# --------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


# --------------------------
# Auth routes
# --------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = query_db("SELECT * FROM users WHERE username=?", (username,), one=True)

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session.permanent = True
            return redirect(url_for("stock_remove_page"))

        flash("Invalid login")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------
# Pages
# --------------------------
@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/stock/remove")
@login_required
def stock_remove_page():
    if session.get("role") == "admin":
        products = query_db("SELECT id,name,barcode,qty FROM products")
    else:
        products = query_db(
            "SELECT id,name,barcode,qty FROM products WHERE user_id=?",
            (session["user_id"],)
        )
    return render_template("stock_remove.html", products=products)


# --------------------------
# API: remove stock
# --------------------------
@app.route("/api/stock/remove", methods=["POST"])
@csrf.exempt
@login_required
def api_stock_remove():
    data = request.json
    product_id = data.get("product_id")
    remove_qty = int(data.get("amount") or 0)
    staff_name = data.get("staff_name", "")

    product = query_db("SELECT * FROM products WHERE id=?", (product_id,), one=True)
    if not product:
        return jsonify(success=False, error="Product not found"), 404

    current_qty = int(product["qty"] or 0)
    if remove_qty > current_qty:
        return jsonify(success=False, error="Not enough stock"), 400

    new_qty = current_qty - remove_qty
    execute_db("UPDATE products SET qty=? WHERE id=?", (new_qty, product_id))

    execute_db("""
        INSERT INTO stock_movements (user_id, product_id, change_qty, reason)
        VALUES (?,?,?,?)
    """, (session["user_id"], product_id, -remove_qty, f"by {staff_name}"))

    send_telegram(
        f"📦 *បានដកស្តុកចេញ*\n"
        f"🔹 *{product['name']}*\n"
        f"➖ ដកចេញ៖ {remove_qty}\n"
        f"📉 មុន៖ {current_qty} ➜ បន្ទាប់៖ {new_qty}\n"
        f"👤 អ្នកដក៖ {staff_name}"
    )

    return jsonify(success=True, new_qty=new_qty)


# --------------------------
# Run app
# --------------------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5009)
