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

# ✅ FIX (Render): use persistent disk path if provided
# Example Render env: DATABASE_PATH=/var/data/pos.db
DATABASE = os.environ.get("DATABASE_PATH", "pos.db")

# ✅ FIX: create db folder only if there is a folder in path
_db_dir = os.path.dirname(DATABASE)
if _db_dir:
    try:
        os.makedirs(_db_dir, exist_ok=True)
    except PermissionError:
        # If disk path isn't mounted yet, don't crash at import.
        pass

UPLOAD_FOLDER = os.path.join("static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"xlsx"}

# --- Remember me (30 days) ---
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"     # consider "Strict" for intranet
app.config["SESSION_COOKIE_SECURE"] = False       # set True when served via HTTPS

# Telegram Config
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "your_bot_token_here")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "your_chat_id_here")


# --------------------------
# DB helpers
# --------------------------
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        # ✅ FIX (Gunicorn): check_same_thread=False + higher timeout
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
    return "." in filename and filename.rsplit(".", 1)[1].lower() in {"xlsx"}


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
# Initialize DB
# --------------------------
def init_db():
    db = get_db()

    # Users
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user'
        )
    """)

    # Products
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

    # Stocktake drafts (staging area before apply)
    db.execute("""
        CREATE TABLE IF NOT EXISTS stocktake_drafts (
            user_id INTEGER,
            product_id INTEGER,
            qty INTEGER,
            PRIMARY KEY (user_id, product_id)
        )
    """)

    # Stock movements (audit log)
    db.execute("""
        CREATE TABLE IF NOT EXISTS stock_movements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            product_id INTEGER,
            change_qty INTEGER,          -- negative for remove, positive for add/adjust
            reason TEXT,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        )
    """)

    # Default admin
    db.execute("""
        INSERT OR IGNORE INTO users (username, password, role)
        VALUES (?, ?, ?)
    """, (
        "admin",
        generate_password_hash("admin123"),
        "admin"
    ))

    # Helpful indexes (idempotent)
    db.execute("CREATE INDEX IF NOT EXISTS idx_products_barcode ON products(barcode)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_products_user ON products(user_id)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_movements_created ON stock_movements(created_at)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_movements_product ON stock_movements(product_id)")

    db.commit()


# ✅ FIX (Render/Gunicorn): make sure tables exist when app loads (Gunicorn doesn't run __main__)
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

# ✅ FIX: if your HTML doesn't include csrf_token, CSRF will 400
@csrf.exempt
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
        except sqlite3.IntegrityError:
            flash("⚠️ Username already exists")
            return redirect(url_for("register"))

        flash("✅ Registration successful! Please log in.")
        return redirect(url_for("login"))

    return render_template("register.html")


# ✅ FIX: CSRF 400 on login form (same reason)
@csrf.exempt
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
        p["qty"] = p["qty"] or 0
        p["min_qty"] = p["min_qty"] or 0

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
            filepath = os.path.join(
                app.config["UPLOAD_FOLDER"],
                secure_filename(file.filename)
            )
            file.save(filepath)

            try:
                df = pd.read_excel(filepath)

                required_cols = [
                    "sku", "name", "price", "cost",
                    "qty", "min_qty", "barcode"
                ]
                if not all(col in df.columns for col in required_cols):
                    flash("⚠️ Excel missing required columns")
                    return redirect(request.url)

                for idx, row in df.iterrows():
                    sku = str(row.get("sku") or "").strip()
                    name = str(row.get("name") or "").strip()

                    if not name:
                        name = f"NUII-{sku}" if sku else f"NUII-{idx+1}"

                    qty = int(row.get("qty") or 0)
                    min_qty = int(row.get("min_qty") or 0)

                    execute_db("""
                        INSERT OR REPLACE INTO products
                        (user_id, sku, name, price, cost, qty, min_qty, barcode)
                        VALUES (?,?,?,?,?,?,?,?)
                    """, (
                        session["user_id"],
                        sku,
                        name,
                        row.get("price", 0),
                        row.get("cost", 0),
                        qty,
                        min_qty,
                        str(row.get("barcode") or "")
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
    df = pd.DataFrame(columns=[
        "sku", "name", "price", "cost",
        "qty", "min_qty", "barcode"
    ])
    filepath = os.path.join(
        app.config["UPLOAD_FOLDER"],
        "product_template.xlsx"
    )
    df.to_excel(filepath, index=False)
    return send_file(filepath, as_attachment=True)


@app.route("/stocktake")
@login_required
def stocktake_page():
    products = query_db(
        "SELECT * FROM products WHERE user_id=?",
        (session["user_id"],)
    )
    products = [dict(p) for p in products]
    for p in products:
        p["qty"] = p["qty"] or 0
        p["min_qty"] = p["min_qty"] or 0

    return render_template("stocktake.html", products=products)


@app.route("/checkout")
@login_required
def checkout_page():
    products = query_db(
        "SELECT * FROM products WHERE user_id=?",
        (session["user_id"],)
    )
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
        p["qty"] = p["qty"] or 0

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
        p["price"] = p["price"] or 0.0
        p["cost"] = p["cost"] or 0.0
        p["qty"] = p["qty"] or 0
        p["min_qty"] = p["min_qty"] or 0

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
    filepath = os.path.join(
        app.config["UPLOAD_FOLDER"],
        "users_export.xlsx"
    )
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
        columns=[
            "id", "user_id", "sku", "name", "price",
            "cost", "qty", "min_qty", "barcode"
        ]
    )
    filepath = os.path.join(
        app.config["UPLOAD_FOLDER"],
        "products_export.xlsx"
    )
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

    return jsonify(
        success=True,
        product={
            "id": product["id"],
            "name": product["name"],
            "barcode": product["barcode"],
            "qty": int(product["qty"] or 0),
        }
    )


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

    return jsonify(
        success=True,
        product={
            "id": product["id"],
            "name": product["name"],
            "barcode": product["barcode"],
            "qty": int(product["qty"] or 0),
        }
    )


# --------------------------
# API: Add product
# --------------------------
@app.route("/api/products/add", methods=["POST"])
@csrf.exempt
@login_required
def api_add_product():
    data = request.json or {}
    sku = data.get("sku", "")
    name = (data.get("name", "") or "").strip()
    if not name:
        name = f"NUII-{sku}" if sku else "NUII"

    qty = int(data.get("qty") or 0)
    min_qty = int(data.get("min_qty") or 0)

    execute_db("""
        INSERT INTO products (user_id, sku, name, price, cost, qty, min_qty, barcode)
        VALUES (?,?,?,?,?,?,?,?)
    """, (
        session["user_id"],
        sku,
        name,
        data.get("price", 0),
        data.get("cost", 0),
        qty,
        min_qty,
        data.get("barcode", ""),
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
    name = (data.get("name", "") or "").strip()
    if not name:
        name = f"NUII-{data.get('sku','')}" or "NUII"

    qty = int(data.get("qty") or 0)
    min_qty = int(data.get("min_qty") or 0)

    if session["role"] == "admin":
        execute_db("""
            UPDATE products
            SET name=?, price=?, cost=?, qty=?, min_qty=?, barcode=?
            WHERE id=?
        """, (
            name,
            data.get("price", 0),
            data.get("cost", 0),
            qty,
            min_qty,
            data.get("barcode", ""),
            data.get("id"),
        ))
    else:
        execute_db("""
            UPDATE products
            SET name=?, price=?, cost=?, qty=?, min_qty=?, barcode=?
            WHERE id=? AND user_id=?
        """, (
            name,
            data.get("price", 0),
            data.get("cost", 0),
            qty,
            min_qty,
            data.get("barcode", ""),
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
    if session["role"] == "admin":
        execute_db("DELETE FROM products WHERE id=?", (id,))
    else:
        execute_db(
            "DELETE FROM products WHERE id=? AND user_id=?",
            (id, session["user_id"])
        )
    return jsonify(success=True)


# --------------------------
# Staff page (simple static list for now)
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
# Run app
# --------------------------
if __name__ == "__main__":
    # local only; Render runs Gunicorn
    init_db()
    app.run(host="0.0.0.0", port=5009, debug=True)
