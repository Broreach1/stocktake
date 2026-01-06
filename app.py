import os
import sqlite3
import requests
from functools import wraps
from datetime import timedelta
from flask import (
    Flask, request, redirect, url_for,
    session, g, flash, jsonify, render_template_string
)
from werkzeug.security import generate_password_hash, check_password_hash
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
if not DATABASE:
    DATABASE = os.path.join(os.getcwd(), "pos.db")

db_dir = os.path.dirname(DATABASE)
if db_dir and not os.path.exists(db_dir):
    try:
        os.makedirs(db_dir, exist_ok=True)
    except PermissionError:
        pass

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
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

# ==========================
# DB helpers
# ==========================
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(
            DATABASE,
            timeout=30,
            check_same_thread=False
        )
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_db", None)
    if db:
        db.close()


def query_db(sql, args=(), one=False):
    cur = get_db().execute(sql, args)
    rows = cur.fetchall()
    cur.close()
    return rows[0] if one and rows else rows


def execute_db(sql, args=()):
    db = get_db()
    cur = db.execute(sql, args)
    db.commit()
    cur.close()


# ==========================
# Telegram sender (safe)
# ==========================
def send_telegram(text):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": text,
            },
            timeout=10,
        )
    except Exception as e:
        print("Telegram error:", e)


# ==========================
# DB init (Flask 3 SAFE)
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
            name TEXT NOT NULL,
            qty INTEGER DEFAULT 0
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS stock_movements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER,
            change_qty INTEGER,
            reason TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    db.execute("""
        INSERT OR IGNORE INTO users (username, password, role)
        VALUES (?, ?, ?)
    """, ("admin", generate_password_hash("admin123"), "admin"))

    db.commit()


# ✅ INIT DATABASE AT STARTUP (NO decorators)
with app.app_context():
    init_db()


# ==========================
# Auth helper
# ==========================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


# ==========================
# Routes
# ==========================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        user = query_db(
            "SELECT * FROM users WHERE username=?",
            (username,),
            one=True
        )

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session.permanent = True
            return redirect(url_for("index"))

        flash("Invalid login")

    # SAFE inline template (NO TemplateNotFound)
    return render_template_string("""
        <h2>Login</h2>
        <form method="post">
            <input name="username" placeholder="username"><br>
            <input name="password" type="password" placeholder="password"><br>
            <button type="submit">Login</button>
        </form>
    """)


@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    products = query_db("SELECT * FROM products")
    return render_template_string("""
        <h2>Stock</h2>
        <ul>
        {% for p in products %}
            <li>{{p.name}} - {{p.qty}}</li>
        {% endfor %}
        </ul>
    """, products=products)


# ==========================
# API: remove stock (safe)
# ==========================
@app.route("/api/stock/remove", methods=["POST"])
@csrf.exempt
@login_required
def remove_stock():
    data = request.get_json(silent=True) or {}

    product_id = data.get("product_id")
    amount = int(data.get("amount") or 0)

    if not product_id or amount <= 0:
        return jsonify(error="Invalid data"), 400

    product = query_db(
        "SELECT * FROM products WHERE id=?",
        (product_id,),
        one=True
    )

    if not product:
        return jsonify(error="Product not found"), 404

    if product["qty"] < amount:
        return jsonify(error="Not enough stock"), 400

    new_qty = product["qty"] - amount

    execute_db(
        "UPDATE products SET qty=? WHERE id=?",
        (new_qty, product_id)
    )

    execute_db("""
        INSERT INTO stock_movements (product_id, change_qty, reason)
        VALUES (?, ?, ?)
    """, (product_id, -amount, "remove"))

    send_telegram(
        f"📦 Stock removed\n{product['name']}: -{amount} → {new_qty}"
    )

    return jsonify(success=True, new_qty=new_qty)


# ==========================
# DEBUG ROUTE (VERY IMPORTANT)
# ==========================
@app.route("/_health")
def health():
    return {
        "status": "ok",
        "db": DATABASE,
        "files": os.listdir(".")
    }


# ==========================
# GLOBAL ERROR HANDLER (NO BLIND 500)
# ==========================
@app.errorhandler(Exception)
def handle_exception(e):
    print("ERROR:", repr(e))
    return jsonify(
        error="Internal Server Error",
        detail=str(e)
    ), 500


# ==========================
# Local run only
# ==========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5009, debug=True)
