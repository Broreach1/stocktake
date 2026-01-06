# app.py  (Render-ready: PostgreSQL on Render, SQLite locally)
import os
import sqlite3
import pandas as pd
import requests
from functools import wraps
from datetime import timedelta

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, g, flash, jsonify, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect

# ✅ Postgres (Render) - psycopg v3
import psycopg
from psycopg.rows import dict_row


# --------------------------
# Flask setup
# --------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "super_secret_key")
csrf = CSRFProtect(app)

# If DATABASE_URL exists -> PostgreSQL (Render). Else -> SQLite local.
DATABASE = os.environ.get("SQLITE_PATH", "pos.db")
DATABASE_URL = os.environ.get("DATABASE_URL")

UPLOAD_FOLDER = os.path.join("static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"xlsx"}

# --- Remember me (30 days) ---
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False  # set True if HTTPS

# Telegram Config
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "7951793613:AAFkOBGmBURAVVusTmMCW2SCkGRsCWMY1Ug")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "-1003244053484")


# --------------------------
# DB helpers (SQLite + PostgreSQL)
# --------------------------
def is_postgres() -> bool:
    return bool(DATABASE_URL)


def _pg_url():
    url = DATABASE_URL
    # Render sometimes provides postgres://
    if url and url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    return url


def _adapt_sql(sql: str) -> str:
    """
    Your code uses SQLite placeholders '?' everywhere.
    psycopg uses %s. This converts ? -> %s for PostgreSQL.
    """
    if not is_postgres():
        return sql
    return sql.replace("?", "%s")


def get_db():
    db = getattr(g, "_database", None)
    if db is not None:
        return db

    if is_postgres():
        db = g._database = psycopg.connect(
            _pg_url(),
            row_factory=dict_row,
            autocommit=False,
        )
    else:
        db = g._database = sqlite3.connect(DATABASE, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row  # dict-like rows

    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db:
        try:
            db.close()
        except Exception:
            pass


def _row_to_dict(r):
    if r is None:
        return None
    if isinstance(r, sqlite3.Row):
        return dict(r)
    return r


def query_db(query, args=(), one=False):
    db = get_db()
    q = _adapt_sql(query)

    if is_postgres():
        with db.cursor() as cur:
            cur.execute(q, args)
            rows = cur.fetchall()
            if one:
                return rows[0] if rows else None
            return rows
    else:
        cur = db.execute(q, args)
        rows = cur.fetchall()
        cur.close()
        if one:
            return rows[0] if rows else None
        return rows


def execute_db(query, args=()):
    db = get_db()
    q = _adapt_sql(query)

    if is_postgres():
        with db.cursor() as cur:
            cur.execute(q, args)
        db.commit()
    else:
        cur = db.execute(q, args)
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
        print(f"Telegram error: {e}")


# --------------------------
# Initialize DB (works on SQLite + Postgres)
# --------------------------
def init_db():
    with app.app_context():
        db = get_db()

        if is_postgres():
            execute_db("""
                CREATE TABLE IF NOT EXISTS users (
                    id BIGSERIAL PRIMARY KEY,
                    username TEXT UNIQUE,
                    password TEXT,
                    role TEXT DEFAULT 'user'
                )
            """)

            execute_db("""
                CREATE TABLE IF NOT EXISTS products (
                    id BIGSERIAL PRIMARY KEY,
                    user_id BIGINT,
                    sku TEXT,
                    name TEXT NOT NULL,
                    price DOUBLE PRECISION,
                    cost DOUBLE PRECISION,
                    qty INTEGER,
                    min_qty INTEGER,
                    barcode TEXT
                )
            """)

            execute_db("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'uq_products_user_sku'
                    ) THEN
                        ALTER TABLE products
                        ADD CONSTRAINT uq_products_user_sku UNIQUE (user_id, sku);
                    END IF;
                END
                $$;
            """)

            execute_db("""
                CREATE TABLE IF NOT EXISTS stocktake_drafts (
                    user_id BIGINT,
                    product_id BIGINT,
                    qty INTEGER,
                    PRIMARY KEY (user_id, product_id)
                )
            """)

            execute_db("""
                CREATE TABLE IF NOT EXISTS stock_movements (
                    id BIGSERIAL PRIMARY KEY,
                    user_id BIGINT,
                    product_id BIGINT,
                    change_qty INTEGER,
                    reason TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            execute_db("""
                INSERT INTO users (username, password, role)
                VALUES (?, ?, ?)
                ON CONFLICT (username) DO NOTHING
            """, ("admin", generate_password_hash("admin123"), "admin"))

            execute_db("CREATE INDEX IF NOT EXISTS idx_products_barcode ON products(barcode)")
            execute_db("CREATE INDEX IF NOT EXISTS idx_products_user ON products(user_id)")
            execute_db("CREATE INDEX IF NOT EXISTS idx_movements_created ON stock_movements(created_at)")
            execute_db("CREATE INDEX IF NOT EXISTS idx_movements_product ON stock_movements(product_id)")

        else:
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

            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_products_user_sku ON products(user_id, sku)")

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

            db.execute("CREATE INDEX IF NOT EXISTS idx_products_barcode ON products(barcode)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_products_user ON products(user_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_movements_created ON stock_movements(created_at)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_movements_product ON stock_movements(product_id)")
            db.commit()


# --------------------------
# ✅ IMPORTANT FIX: init DB for Gunicorn/Render
# --------------------------
_db_initialized = False

@app.before_request
def ensure_db_initialized():
    global _db_initialized
    if _db_initialized:
        return
    try:
        print("DATABASE_URL exists?", bool(DATABASE_URL))
        init_db()
        _db_initialized = True
        print("✅ DB initialized OK")
    except Exception as e:
        print("❌ DB init failed:", e)


# --------------------------
# Auth helpers
# --------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            # API calls should return JSON instead of redirect
            if request.path.startswith("/api/"):
                return jsonify(success=False, error="Not logged in"), 401
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

        hashed_pw = generate_password_hash(password)

        try:
            execute_db(
                "INSERT INTO users (username, password, role) VALUES (?,?,?)",
                (username, hashed_pw, "user"),
            )
        except Exception:
            flash("⚠️ Username already exists")
            return redirect(url_for("register"))

        flash("✅ Registration successful! Please log in.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = query_db("SELECT * FROM users WHERE username=?", (username,), one=True)
        user = _row_to_dict(user)

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user.get("role", "user")

            remember = request.form.get("remember") == "on"
            session.permanent = bool(remember)

            return redirect(url_for("stock_remove_page"))

        flash("❌ Invalid username or password")
        return redirect(url_for("login"))

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


@app.route("/products")
@login_required
def products_page():
    if session.get("role") == "admin":
        products = query_db("SELECT * FROM products")
    else:
        products = query_db("SELECT * FROM products WHERE user_id=?", (session["user_id"],))

    products = [_row_to_dict(p) for p in products]
    for p in products:
        p["qty"] = p.get("qty") or 0
        p["min_qty"] = p.get("min_qty") or 0

    return render_template("products.html", products=products)


# --------------------------
# ✅ FIXED: Barcode search (SAFE)
# --------------------------
def _find_product_by_barcode(barcode: str):
    barcode = (barcode or "").strip()
    if not barcode:
        return None

    like_pattern = f"%{barcode}%"

    if session.get("role") == "admin":
        p = query_db(
            "SELECT id, name, qty, barcode, user_id FROM products WHERE barcode=? ORDER BY id DESC LIMIT 1",
            (barcode,),
            one=True
        )
        p = _row_to_dict(p)
        if not p:
            p = query_db(
                "SELECT id, name, qty, barcode, user_id FROM products WHERE barcode LIKE ? ORDER BY id DESC LIMIT 1",
                (like_pattern,),
                one=True
            )
            p = _row_to_dict(p)
        return p

    # normal user
    p = query_db(
        "SELECT id, name, qty, barcode FROM products WHERE user_id=? AND barcode=? ORDER BY id DESC LIMIT 1",
        (session["user_id"], barcode),
        one=True
    )
    p = _row_to_dict(p)
    if not p:
        p = query_db(
            "SELECT id, name, qty, barcode FROM products WHERE user_id=? AND barcode LIKE ? ORDER BY id DESC LIMIT 1",
            (session["user_id"], like_pattern),
            one=True
        )
        p = _row_to_dict(p)
    return p


# ✅ new safe endpoint: /api/product/barcode?q=123
@app.route("/api/product/barcode", methods=["GET"])
@csrf.exempt
@login_required
def api_get_product_by_barcode_q():
    barcode = (request.args.get("q") or "").strip()
    p = _find_product_by_barcode(barcode)
    if not p:
        return jsonify(success=False, error="Product not found"), 404

    return jsonify(success=True, product={
        "id": p["id"],
        "name": p["name"],
        "barcode": p.get("barcode", ""),
        "qty": int(p.get("qty") or 0),
    })


# ✅ keep old style working too: /api/product/barcode/<barcode>
@app.route("/api/product/barcode/<path:barcode>", methods=["GET"])
@csrf.exempt
@login_required
def api_get_product_by_barcode_path(barcode):
    p = _find_product_by_barcode(barcode)
    if not p:
        return jsonify(success=False, error="Product not found"), 404

    return jsonify(success=True, product={
        "id": p["id"],
        "name": p["name"],
        "barcode": p.get("barcode", ""),
        "qty": int(p.get("qty") or 0),
    })


# --------------------------
# Remove Stock page (UI)
# --------------------------
@app.route("/stock/remove")
@login_required
def stock_remove_page():
    if session.get("role") == "admin":
        products = query_db("""
            SELECT id, name, barcode, qty
            FROM products
            ORDER BY name ASC
        """)
    else:
        products = query_db("""
            SELECT id, name, barcode, qty
            FROM products
            WHERE user_id=?
            ORDER BY name ASC
        """, (session["user_id"],))

    products = [_row_to_dict(p) for p in products]
    for p in products:
        p["qty"] = p.get("qty") or 0

    return render_template("stock_remove.html", products=products)


# --------------------------
# Staff page
# --------------------------
@app.route("/staff")
@login_required
def staff_page():
    staff = [
        {"name": "Srey Neath"},
        {"name": "Lin"},
        {"name": "Pich"},
        {"name": "Sopha"},
        {"name": "Oudom"},
        {"name": "Sary"},
        {"name": "Srey Ka"},
        {"name": "Srey Na"},
        {"name": "SOVANNARY"},
        {"name": "Puthea"},
        {"name": "Sok Na"},
    ]
    return render_template("staff.html", staff=staff)


# --------------------------
# Run app (Render uses PORT)
# --------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5009))
    app.run(host="0.0.0.0", port=port)
