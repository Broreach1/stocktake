# app.py  (Render-ready: PostgreSQL on Render, SQLite locally)
import os
import sqlite3
import pandas as pd
import requests
from functools import wraps
from datetime import timedelta
from urllib.parse import urlparse

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, g, flash, jsonify, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect

# Postgres (Render)
import psycopg2
import psycopg2.extras


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
    psycopg2 uses %s. This converts ? -> %s for PostgreSQL.
    """
    if not is_postgres():
        return sql
    return sql.replace("?", "%s")


def get_db():
    db = getattr(g, "_database", None)
    if db is not None:
        return db

    if is_postgres():
        db = g._database = psycopg2.connect(
            _pg_url(),
            cursor_factory=psycopg2.extras.RealDictCursor,
        )
        # We will commit manually in execute_db / transactions
        db.autocommit = False
    else:
        # SQLite
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


def query_db(query, args=(), one=False):
    db = get_db()
    q = _adapt_sql(query)

    if is_postgres():
        with db.cursor() as cur:
            cur.execute(q, args)
            rows = cur.fetchall()
            return (rows[0] if rows else None) if one else rows
    else:
        cur = db.execute(q, args)
        rows = cur.fetchall()
        cur.close()
        return (rows[0] if rows else None) if one else rows


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
    """Send alert message to Telegram group/chat."""
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
            # USERS
            execute_db("""
                CREATE TABLE IF NOT EXISTS users (
                    id BIGSERIAL PRIMARY KEY,
                    username TEXT UNIQUE,
                    password TEXT,
                    role TEXT DEFAULT 'user'
                )
            """)

            # PRODUCTS
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

            # Optional uniqueness (helps import "replace")
            # unique by (user_id, sku) to allow upsert import
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

            # STOCKTAKE DRAFTS
            execute_db("""
                CREATE TABLE IF NOT EXISTS stocktake_drafts (
                    user_id BIGINT,
                    product_id BIGINT,
                    qty INTEGER,
                    PRIMARY KEY (user_id, product_id)
                )
            """)

            # MOVEMENTS
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

            # Default admin
            execute_db("""
                INSERT INTO users (username, password, role)
                VALUES (?, ?, ?)
                ON CONFLICT (username) DO NOTHING
            """, ("admin", generate_password_hash("admin123"), "admin"))

            # Indexes
            execute_db("CREATE INDEX IF NOT EXISTS idx_products_barcode ON products(barcode)")
            execute_db("CREATE INDEX IF NOT EXISTS idx_products_user ON products(user_id)")
            execute_db("CREATE INDEX IF NOT EXISTS idx_movements_created ON stock_movements(created_at)")
            execute_db("CREATE INDEX IF NOT EXISTS idx_movements_product ON stock_movements(product_id)")

        else:
            # SQLite schema (your original)
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

            # Helpful unique key for import replace behavior
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

        user = query_db(
            "SELECT * FROM users WHERE username=?",
            (username,),
            one=True
        )

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
        products = query_db(
            "SELECT * FROM products WHERE user_id=?",
            (session["user_id"],)
        )

    products = [dict(p) for p in products]
    for p in products:
        p["qty"] = p.get("qty") or 0
        p["min_qty"] = p.get("min_qty") or 0

    return render_template("products.html", products=products)


@app.route("/products/import", methods=["GET", "POST"])
@login_required
def import_products():
    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            flash("⚠️ No file selected")
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], secure_filename(file.filename))
            file.save(filepath)

            try:
                df = pd.read_excel(filepath)

                required_cols = ["sku", "name", "price", "cost", "qty", "min_qty", "barcode"]
                if not all(col in df.columns for col in required_cols):
                    flash("⚠️ Excel missing required columns")
                    return redirect(request.url)

                for idx, row in df.iterrows():
                    sku = str(row.get("sku") or "").strip()
                    name = str(row.get("name") or "").strip()

                    # ensure sku exists (needed for upsert)
                    if not sku:
                        sku = f"AUTO-{idx+1}"

                    if not name:
                        name = f"NUII-{sku}"

                    qty = int(row.get("qty") or 0)
                    min_qty = int(row.get("min_qty") or 0)
                    barcode = str(row.get("barcode") or "").strip()

                    if is_postgres():
                        execute_db("""
                            INSERT INTO products (user_id, sku, name, price, cost, qty, min_qty, barcode)
                            VALUES (?,?,?,?,?,?,?,?)
                            ON CONFLICT (user_id, sku)
                            DO UPDATE SET
                                name=EXCLUDED.name,
                                price=EXCLUDED.price,
                                cost=EXCLUDED.cost,
                                qty=EXCLUDED.qty,
                                min_qty=EXCLUDED.min_qty,
                                barcode=EXCLUDED.barcode
                        """, (
                            session["user_id"], sku, name,
                            float(row.get("price") or 0),
                            float(row.get("cost") or 0),
                            qty, min_qty, barcode
                        ))
                    else:
                        execute_db("""
                            INSERT INTO products (user_id, sku, name, price, cost, qty, min_qty, barcode)
                            VALUES (?,?,?,?,?,?,?,?)
                            ON CONFLICT(user_id, sku) DO UPDATE SET
                                name=excluded.name,
                                price=excluded.price,
                                cost=excluded.cost,
                                qty=excluded.qty,
                                min_qty=excluded.min_qty,
                                barcode=excluded.barcode
                        """, (
                            session["user_id"], sku, name,
                            row.get("price", 0),
                            row.get("cost", 0),
                            qty, min_qty, barcode
                        ))

                flash("✅ Products imported successfully")
                return redirect(url_for("products_page"))

            except Exception as e:
                flash(f"❌ Error reading Excel: {e}")
                return redirect(request.url)

    return render_template("import_products.html")


@app.route("/products/download-template")
@login_required
def download_template():
    df = pd.DataFrame(columns=["sku", "name", "price", "cost", "qty", "min_qty", "barcode"])
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], "product_template.xlsx")
    df.to_excel(filepath, index=False)
    return send_file(filepath, as_attachment=True)


@app.route("/stocktake")
@login_required
def stocktake_page():
    products = query_db("SELECT * FROM products WHERE user_id=?", (session["user_id"],))
    products = [dict(p) for p in products]
    for p in products:
        p["qty"] = p.get("qty") or 0
        p["min_qty"] = p.get("min_qty") or 0
    return render_template("stocktake.html", products=products)


@app.route("/checkout")
@login_required
def checkout_page():
    products = query_db("SELECT * FROM products WHERE user_id=?", (session["user_id"],))
    return render_template("checkout.html", products=[dict(p) for p in products])


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

    products = [dict(p) for p in products]
    for p in products:
        p["qty"] = p.get("qty") or 0

    return render_template("stock_remove.html", products=products)


# --------------------------
# Stock movement history (admin audit)
# --------------------------
@app.route("/stock/history")
@login_required
def stock_history():
    if session.get("role") != "admin":
        flash("❌ Access denied")
        return redirect(url_for("index"))

    rows = query_db("""
        SELECT sm.id,
               sm.created_at,
               sm.change_qty,
               sm.reason,
               u.username,
               p.name AS product_name,
               p.barcode
        FROM stock_movements sm
        LEFT JOIN users u ON u.id = sm.user_id
        LEFT JOIN products p ON p.id = sm.product_id
        ORDER BY sm.id DESC
        LIMIT 200
    """)

    return render_template("stock_history.html", rows=rows)


# --------------------------
# Admin Pages
# --------------------------
@app.route("/admin")
@login_required
def admin_page():
    if session.get("role") != "admin":
        flash("❌ Access denied")
        return redirect(url_for("index"))

    users = query_db("SELECT id, username, role FROM users")
    products = query_db("SELECT * FROM products")
    products = [dict(p) for p in products]
    for p in products:
        p["price"] = p.get("price") or 0.0
        p["cost"] = p.get("cost") or 0.0
        p["qty"] = p.get("qty") or 0
        p["min_qty"] = p.get("min_qty") or 0

    return render_template("admin.html", users=users, products=products)


@app.route("/admin/delete/user/<int:id>", methods=["POST"])
@login_required
def delete_user(id):
    if session.get("role") != "admin":
        flash("❌ Access denied")
        return redirect(url_for("index"))

    user = query_db("SELECT * FROM users WHERE id=?", (id,), one=True)
    if not user:
        flash("⚠️ User not found")
        return redirect(url_for("admin_page"))

    if user["username"] == "admin":
        flash("⚠️ Cannot delete default admin user")
        return redirect(url_for("admin_page"))

    execute_db("DELETE FROM users WHERE id=?", (id,))
    flash(f"✅ User {user['username']} deleted")
    return redirect(url_for("admin_page"))


@app.route("/admin/export/users")
@login_required
def export_users():
    if session.get("role") != "admin":
        flash("❌ Access denied")
        return redirect(url_for("index"))

    users = query_db("SELECT id, username, role FROM users")
    df = pd.DataFrame(users, columns=["id", "username", "role"])
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], "users_export.xlsx")
    df.to_excel(filepath, index=False)
    return send_file(filepath, as_attachment=True)


@app.route("/admin/export/products")
@login_required
def export_products():
    if session.get("role") != "admin":
        flash("❌ Access denied")
        return redirect(url_for("index"))

    products = query_db("SELECT * FROM products")
    df = pd.DataFrame(
        products,
        columns=["id", "user_id", "sku", "name", "price", "cost", "qty", "min_qty", "barcode"]
    )
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], "products_export.xlsx")
    df.to_excel(filepath, index=False)
    return send_file(filepath, as_attachment=True)


# --------------------------
# API: Get product by ID (for dropdown)
# --------------------------
@app.route("/api/product/<int:pid>")
@login_required
def api_get_product(pid):
    if session.get("role") == "admin":
        product = query_db(
            "SELECT id, name, qty, barcode, user_id FROM products WHERE id=?",
            (pid,),
            one=True
        )
    else:
        product = query_db(
            "SELECT id, name, qty, barcode FROM products WHERE id=? AND user_id=?",
            (pid, session["user_id"]),
            one=True
        )

    if not product:
        return jsonify(success=False, error="Not found"), 404

    return jsonify(success=True, product={
        "id": product["id"],
        "name": product["name"],
        "barcode": product.get("barcode", ""),
        "qty": int(product.get("qty") or 0),
    })


# --------------------------
# API: Get product by BARCODE (supports partial match)
# --------------------------
@app.route("/api/product/barcode/<barcode>")
@login_required
def api_get_product_by_barcode(barcode):
    barcode = (barcode or "").strip()
    like_pattern = f"%{barcode}%"

    if session.get("role") == "admin":
        product = query_db(
            "SELECT id, name, qty, barcode, user_id "
            "FROM products WHERE barcode LIKE ? "
            "ORDER BY id DESC LIMIT 1",
            (like_pattern,),
            one=True
        )
    else:
        product = query_db(
            "SELECT id, name, qty, barcode "
            "FROM products WHERE barcode LIKE ? AND user_id=? "
            "ORDER BY id DESC LIMIT 1",
            (like_pattern, session["user_id"]),
            one=True
        )

    if not product:
        return jsonify(success=False, error="Not found"), 404

    return jsonify(success=True, product={
        "id": product["id"],
        "name": product["name"],
        "barcode": product.get("barcode", ""),
        "qty": int(product.get("qty") or 0),
    })


# --------------------------
# API: Add product
# --------------------------
@app.route("/api/products/add", methods=["POST"])
@csrf.exempt
@login_required
def api_add_product():
    data = request.json or {}
    sku = (data.get("sku") or "").strip()
    name = (data.get("name") or "").strip()

    if not sku:
        # give sku so unique upsert/import works
        sku = f"AUTO-{int(pd.Timestamp.now().timestamp())}"

    if not name:
        name = f"NUII-{sku}"

    qty = int(data.get("qty") or 0)
    min_qty = int(data.get("min_qty") or 0)

    execute_db("""
        INSERT INTO products (user_id, sku, name, price, cost, qty, min_qty, barcode)
        VALUES (?,?,?,?,?,?,?,?)
    """, (
        session["user_id"],
        sku,
        name,
        float(data.get("price") or 0),
        float(data.get("cost") or 0),
        qty,
        min_qty,
        (data.get("barcode") or "").strip(),
    ))
    return jsonify(success=True, product=data)


# --------------------------
# API: Update product
# --------------------------
@app.route("/api/products/update", methods=["POST"])
@csrf.exempt
@login_required
def api_update_product():
    data = request.json or {}
    name = (data.get("name") or "").strip()
    sku = (data.get("sku") or "").strip()

    if not name:
        name = f"NUII-{sku}" if sku else "NUII"

    qty = int(data.get("qty") or 0)
    min_qty = int(data.get("min_qty") or 0)

    if session.get("role") == "admin":
        execute_db("""
            UPDATE products
            SET name=?, price=?, cost=?, qty=?, min_qty=?, barcode=?
            WHERE id=?
        """, (
            name,
            float(data.get("price") or 0),
            float(data.get("cost") or 0),
            qty,
            min_qty,
            (data.get("barcode") or "").strip(),
            data.get("id"),
        ))
    else:
        execute_db("""
            UPDATE products
            SET name=?, price=?, cost=?, qty=?, min_qty=?, barcode=?
            WHERE id=? AND user_id=?
        """, (
            name,
            float(data.get("price") or 0),
            float(data.get("cost") or 0),
            qty,
            min_qty,
            (data.get("barcode") or "").strip(),
            data.get("id"),
            session["user_id"],
        ))
    return jsonify(success=True, product=data)


# --------------------------
# API: Delete product
# --------------------------
@app.route("/api/products/delete/<int:id>", methods=["DELETE"])
@csrf.exempt
@login_required
def api_delete_product(id):
    if session.get("role") == "admin":
        execute_db("DELETE FROM products WHERE id=?", (id,))
    else:
        execute_db("DELETE FROM products WHERE id=? AND user_id=?", (id, session["user_id"]))
    return jsonify(success=True)


# --------------------------
# API: stocktake draft save/load
# --------------------------
@app.route("/api/stocktake/draft", methods=["GET", "POST"])
@csrf.exempt
@login_required
def api_stocktake_draft():
    if request.method == "POST":
        data = request.json or {}
        for upd in data.get("updates", []):
            execute_db("""
                INSERT INTO stocktake_drafts (user_id, product_id, qty)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id, product_id)
                DO UPDATE SET qty=excluded.qty
            """, (
                session["user_id"],
                upd["id"],
                int(upd.get("qty") or 0)
            ))
        return jsonify(success=True)

    drafts = query_db(
        "SELECT product_id, qty FROM stocktake_drafts WHERE user_id=?",
        (session["user_id"],)
    )
    return jsonify(success=True, drafts=[dict(d) for d in drafts])


# --------------------------
# API: stocktake apply final
# --------------------------
@app.route("/api/stocktake/apply", methods=["POST"])
@csrf.exempt
@login_required
def api_stocktake_apply():
    data = request.json or {}
    changes = []

    for upd in data.get("updates", []):
        product = query_db(
            "SELECT name, barcode, qty FROM products WHERE id=?",
            (upd["id"],),
            one=True
        )
        if not product:
            continue

        old_qty = int(product.get("qty") or 0)
        new_qty = int(upd.get("qty") or 0)

        if old_qty != new_qty:
            execute_db(
                "UPDATE products SET qty=? WHERE id=? AND user_id=?",
                (new_qty, upd["id"], session["user_id"])
            )

            execute_db(
                "DELETE FROM stocktake_drafts WHERE user_id=? AND product_id=?",
                (session["user_id"], upd["id"])
            )

            diff = new_qty - old_qty
            execute_db("""
                INSERT INTO stock_movements (user_id, product_id, change_qty, reason)
                VALUES (?, ?, ?, ?)
            """, (session["user_id"], upd["id"], diff, "stocktake adjust"))

            changes.append(f"- {product['name']} (📌 {product.get('barcode','')})  {old_qty} ➝ {new_qty}")

    if changes:
        message = "✏️ *បន្ថែមស្តុក*\n\n" + "\n".join(changes)
        send_telegram(message)

    return jsonify(success=True)


# --------------------------
# API: remove stock (single)
# --------------------------
@app.route("/api/stock/remove", methods=["POST"])
@csrf.exempt
@login_required
def api_stock_remove():
    data = request.json or {}

    product_id = data.get("product_id")
    remove_qty = int(data.get("amount") or 0)

    base_reason = (data.get("reason") or "").strip()
    staff_name = (data.get("staff_name") or "").strip()

    if not staff_name:
        return jsonify(success=False, error="Staff name required"), 400

    reason_full = f"{base_reason} (by {staff_name})" if base_reason else f"(by {staff_name})"

    if not product_id or remove_qty <= 0:
        return jsonify(success=False, error="Invalid product or amount"), 400

    if session.get("role") == "admin":
        product = query_db(
            "SELECT id, name, qty, barcode, user_id FROM products WHERE id=?",
            (product_id,),
            one=True
        )
        target_user_id = product["user_id"] if product else None
    else:
        product = query_db(
            "SELECT id, name, qty, barcode FROM products WHERE id=? AND user_id=?",
            (product_id, session["user_id"]),
            one=True
        )
        target_user_id = session["user_id"] if product else None

    if not product:
        return jsonify(success=False, error="Product not found"), 404

    current_qty = int(product.get("qty") or 0)
    if current_qty - remove_qty < 0:
        return jsonify(success=False, error=f"Not enough stock. Current {current_qty}, trying to remove {remove_qty}"), 400

    new_qty = current_qty - remove_qty

    if session.get("role") == "admin":
        execute_db("UPDATE products SET qty=? WHERE id=?", (new_qty, product["id"]))
    else:
        execute_db("UPDATE products SET qty=? WHERE id=? AND user_id=?", (new_qty, product["id"], session["user_id"]))

    execute_db("""
        INSERT INTO stock_movements (user_id, product_id, change_qty, reason)
        VALUES (?, ?, ?, ?)
    """, (target_user_id, product["id"], -remove_qty, reason_full))

    msg = (
        "📦 *បានដកស្តុកចេញ*\n"
        "━━━━━━━━━━━━━━━\n"
        f"🔹 *{product['name']}*\n"
        f"   📌 បាកូដ៖ {product.get('barcode','')}\n"
        f"   ➖ ដកចេញ៖ {remove_qty}\n"
        f"   📉 មុនដក៖ {current_qty}  ដកហើយសល់៖ {new_qty}\n"
        f"   👤 អ្នកដក៖ {staff_name}"
        + (f"\n   📝 មូលហេតុ៖ {base_reason}" if base_reason else "")
        + "\n━━━━━━━━━━━━━━━"
    )
    send_telegram(msg)

    return jsonify(success=True, product_id=product["id"], old_qty=current_qty, new_qty=new_qty)


# --------------------------
# API: remove stock (BATCH, atomic)
# --------------------------
@app.route("/api/stock/remove/batch", methods=["POST"])
@csrf.exempt
@login_required
def api_stock_remove_batch():
    payload = request.json or {}
    items = payload.get("items", [])
    if not isinstance(items, list) or not items:
        return jsonify(success=False, error="No items"), 400

    conn = get_db()
    results = []
    tele_lines = []

    try:
        # Begin transaction
        if is_postgres():
            conn.autocommit = False
            cur = conn.cursor()
            cur.execute("BEGIN")
        else:
            cur = conn.cursor()
            cur.execute("BEGIN IMMEDIATE")

        for i, it in enumerate(items, start=1):
            product_id = it.get("product_id")
            remove_qty = int(it.get("amount") or 0)
            base_reason = (it.get("reason") or "").strip()
            staff_name = (it.get("staff_name") or "").strip()

            res = {"index": i, "product_id": product_id, "amount": remove_qty, "reason": base_reason, "staff_name": staff_name}

            if not staff_name:
                res["error"] = "Staff name required"
                results.append(res)
                raise ValueError("Staff name required")

            if not product_id or remove_qty <= 0:
                res["error"] = "Invalid product or amount"
                results.append(res)
                raise ValueError("Invalid product or amount")

            # Fetch product (role guard)
            if session.get("role") == "admin":
                product = query_db("SELECT id, name, qty, barcode, user_id FROM products WHERE id=?", (product_id,), one=True)
                target_user_id = product["user_id"] if product else None
            else:
                product = query_db("SELECT id, name, qty, barcode FROM products WHERE id=? AND user_id=?", (product_id, session["user_id"]), one=True)
                target_user_id = session["user_id"] if product else None

            if not product:
                res["error"] = "Product not found"
                results.append(res)
                raise ValueError("Product not found")

            current_qty = int(product.get("qty") or 0)
            new_qty = current_qty - remove_qty
            if new_qty < 0:
                res["error"] = f"Not enough stock (current {current_qty}, remove {remove_qty})"
                results.append(res)
                raise ValueError("Not enough stock")

            reason_full = f"{base_reason} (by {staff_name})" if base_reason else f"(by {staff_name})"

            # Update products
            if session.get("role") == "admin":
                cur.execute(_adapt_sql("UPDATE products SET qty=? WHERE id=?"), (new_qty, product["id"]))
            else:
                cur.execute(_adapt_sql("UPDATE products SET qty=? WHERE id=? AND user_id=?"), (new_qty, product["id"], session["user_id"]))

            # Insert movement
            cur.execute(_adapt_sql("""
                INSERT INTO stock_movements (user_id, product_id, change_qty, reason)
                VALUES (?, ?, ?, ?)
            """), (target_user_id, product["id"], -remove_qty, reason_full))

            res.update({
                "name": product["name"],
                "barcode": product.get("barcode", ""),
                "old_qty": current_qty,
                "new_qty": new_qty,
            })
            results.append(res)

            tele_lines.append(
                f"🔹 *{product['name']}*\n"
                f"   📌 បាកូដ៖ {product.get('barcode','')}\n"
                f"   ➖ ដកចេញ៖ {remove_qty}\n"
                f"   📉 មុន៖ {current_qty} ➜ បន្ទាប់៖ {new_qty}\n"
                f"   👤 អ្នកដក៖ {staff_name}"
                + (f"\n   📝 មូលហេតុ៖ {base_reason}" if base_reason else "")
            )

        conn.commit()
        if is_postgres():
            conn.autocommit = False  # keep manual mode; safe

        if tele_lines:
            message = (
                "📦 *របាយការណ៍ដកស្តុកចេញ (Batch)*\n"
                "━━━━━━━━━━━━━━━\n"
                + "\n\n".join(tele_lines)
                + "\n━━━━━━━━━━━━━━━"
            )
            send_telegram(message)

        return jsonify(success=True, results=results)

    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        return jsonify(success=False, error=str(e), results=results), 400


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
    init_db()
    port = int(os.environ.get("PORT", 5009))
    app.run(host="0.0.0.0", port=port)
