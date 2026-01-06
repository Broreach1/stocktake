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

# ✅ FIX: Render-safe DB
DATABASE = os.environ.get("DATABASE_PATH", "pos.db")

UPLOAD_FOLDER = os.path.join("static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"xlsx"}

# --- Remember me (30 days) ---
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False

# Telegram Config
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "your_bot_token_here")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "your_chat_id_here")

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
# Initialize DB (FIXED)
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


# ✅ FIX: init DB at startup (Flask 3 safe)
with app.app_context():
    init_db()

# --------------------------
# Auth helpers
# --------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("⚠️ Please log in first")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

# --------------------------
# Auth routes
# --------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            flash("⚠️ Username and password required")
            return redirect(url_for("register"))

        try:
            execute_db(
                "INSERT INTO users (username, password, role) VALUES (?,?,?)",
                (username, generate_password_hash(password), "user"),
            )
        except sqlite3.IntegrityError:
            flash("⚠️ Username already exists")
            return redirect(url_for("register"))

        flash("✅ Registration successful! Please log in.")
        return redirect(url_for("login"))

    return render_template("register.html")


# ✅ FIX: CSRF exempt login
@app.route("/login", methods=["GET", "POST"])
@csrf.exempt
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
            return redirect(url_for("stock_remove_page"))

        flash("❌ Invalid username or password")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("✅ Logged out successfully")
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
    products = query_db(
        "SELECT id, name, barcode, qty FROM products WHERE user_id=? OR ?='admin'",
        (session["user_id"], session["role"])
    )
    products = [dict(p) for p in products]
    for p in products:
        p["qty"] = p["qty"] or 0
    return render_template("stock_remove.html", products=products)

# --------------------------
# Run app (local only)
# --------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5009, debug=True)
