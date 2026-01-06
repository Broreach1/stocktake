import os
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

import psycopg2
from psycopg2.extras import RealDictCursor


# --------------------------
# Flask setup
# --------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "super_secret_key")
csrf = CSRFProtect(app)

UPLOAD_FOLDER = os.path.join("static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"xlsx"}

# --- Remember me (30 days) ---
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False  # set True when HTTPS

# Telegram Config
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "your_bot_token_here")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "your_chat_id_here")

# Render Postgres provides DATABASE_URL
DATABASE_URL = os.environ.get("DATABASE_URL")  # e.g. postgres://...


# --------------------------
# DB helpers (PostgreSQL)
# --------------------------
def get_db():
    """
    One connection per request (stored in flask.g).
    """
    db = getattr(g, "_db", None)
    if db is None:
        if not DATABASE_URL:
            raise RuntimeError("DATABASE_URL is not set. On Render, add a PostgreSQL and link DATABASE_URL.")
        db = g._db = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        db.autocommit = False
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_db", None)
    if db:
        try:
            db.close()
        except Exception:
            pass


def query_db(query, args=(), one=False):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(query, args)
        rows = cur.fetchall()
    return (rows[0] if rows else None) if one else rows


def execute_db(query, args=()):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(query, args)
    conn.commit()


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in {"xlsx"}


def send_telegram(text):
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            data={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "Markdown"},
            timeout=8,
        )
    except Exception as e:
        print(f"Telegram error: {e}")


# --------------------------
# Initialize DB (Postgres)
# --------------------------
def init_db():
    with app.app_context():
        conn = get_db()
        with conn.cursor() as cur:
            # USERS
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT DEFAULT 'user'
                )
            """)

            # PRODUCTS
            # We enforce unique (user_id, sku) so import can UPSERT safely.
            cur.execute("""
                CREATE TABLE IF NOT EXISTS products (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    sku TEXT NOT NULL,
                    name TEXT NOT NULL,
                    price NUMERIC,
                    cost NUMERIC,
                    qty INTEGER DEFAULT 0,
                    min_qty INTEGER DEFAULT 0,
                    barcode TEXT,
                    UNIQUE (user_id, sku)
                )
            """)

            # STOCKTAKE DRAFTS
            cur.execute("""
                CREATE TABLE IF NOT EXISTS stocktake_drafts (
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
                    qty INTEGER DEFAULT 0,
                    PRIMARY KEY (user_id, product_id)
                )
            """)

            # STOCK MOVEMENTS
            cur.execute("""
                CREATE TABLE IF NOT EXISTS stock_movements (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    product_id INTEGER REFERENCES products(id) ON DELETE SET NULL,
                    change_qty INTEGER NOT NULL,
                    reason TEXT,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)

            # Default admin
            cur.execute("""
                INSERT INTO users (username, password, role)
                VALUES (%s, %s, %s)
                ON CONFLICT (username) DO NOTHING
            """, ("admin", generate_password_hash("admin123"), "admin"))

            # Indexes
            cur.execute("CREATE INDEX IF NOT EXISTS idx_products_barcode ON products(barcode)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_products_user ON products(user_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_movements_created ON stock_movements(created_at)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_movements_product ON stock_movements(product_id)")

        conn.commit()


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
                "INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
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
            "SELECT * FROM users WHERE username=%s",
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
        products = query_db("SELECT * FROM products ORDER BY id DESC")
    else:
        products = query_db(
            "SELECT * FROM products WHERE user_id=%s ORDER BY id DESC",
            (session["user_id"],)
        )

    # ensure ints
    for p in products:
        p["qty"] = int(p.get("qty") or 0)
        p["min_qty"] = int(p.get("min_qty") or 0)

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

                conn = get_db()
                with conn.cursor() as cur:
                    for idx, row in df.iterrows():
                        sku = str(row.get("sku") or "").strip()
                        if not sku:
                            sku = f"AUTO-{idx+1}"  # guarantee unique-ish sku

                        name = str(row.get("name") or "").strip()
                        if not name:
                            name = f"NUII-{sku}"

                        qty = int(row.get("qty") or 0)
                        min_qty = int(row.get("min_qty") or 0)
                        price = row.get("price", 0) or 0
                        cost = row.get("cost", 0) or 0
                        barcode = str(row.get("barcode") or "").strip()

                        # UPSERT by (user_id, sku)
                        cur.execute("""
                            INSERT INTO products (user_id, sku, name, price, cost, qty, min_qty, barcode)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                            ON CONFLICT (user_id, sku)
                            DO UPDATE SET
                                name=EXCLUDED.name,
                                price=EXCLUDED.price,
                                cost=EXCLUDED.cost,
                                qty=EXCLUDED.qty,
                                min_qty=EXCLUDED.min_qty,
                                barcode=EXCLUDED.barcode
                        """, (
                            session["user_id"], sku, name, price, cost, qty, min_qty, barcode
                        ))

                conn.commit()
                flash("✅ Products imported successfully")
                return redirect(url_for("products_page"))

            except Exception as e:
                try:
                    get_db().rollback()
                except Exception:
                    pass
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
    products = query_db(
        "SELECT * FROM products WHERE user_id=%s ORDER BY name ASC",
        (session["user_id"],)
    )
    for p in products:
        p["qty"] = int(p.get("qty") or 0)
        p["min_qty"] = int(p.get("min_qty") or 0)
    return render_template("stocktake.html", products=products)


@app.route("/checkout")
@login_required
def checkout_page():
    products = query_db(
        "SELECT * FROM products WHERE user_id=%s ORDER BY name ASC",
        (session["user_id"],)
    )
    return render_template("checkout.html", products=products)


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
            WHERE user_id=%s
            ORDER BY name ASC
        """, (session["user_id"],))

    for p in products:
        p["qty"] = int(p.get("qty") or 0)

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

    users = query_db("SELECT id, username, role FROM users ORDER BY id ASC")
    products = query_db("SELECT * FROM products ORDER BY id DESC")

    for p in products:
        p["price"] = float(p.get("price") or 0.0)
        p["cost"] = float(p.get("cost") or 0.0)
        p["qty"] = int(p.get("qty") or 0)
        p["min_qty"] = int(p.get("min_qty") or 0)

    return render_template("admin.html", users=users, products=products)


@app.route("/admin/delete/user/<int:id>", methods=["POST"])
@login_required
def delete_user(id):
    if session.get("role") != "admin":
        flash("❌ Access denied")
        return redirect(url_for("index"))

    user = query_db("SELECT * FROM users WHERE id=%s", (id,), one=True)
    if not user:
        flash("⚠️ User not found")
        return redirect(url_for("admin_page"))

    if user["username"] == "admin":
        flash("⚠️ Cannot delete default admin user")
        return redirect(url_for("admin_page"))

    execute_db("DELETE FROM users WHERE id=%s", (id,))
    flash(f"✅ User {user['username']} deleted")
    return redirect(url_for("admin_page"))


@app.route("/admin/export/users")
@login_required
def export_users():
    if session.get("role") != "admin":
        flash("❌ Access denied")
        return redirect(url_for("index"))

    users = query_db("SELECT id, username, role FROM users ORDER BY id ASC")
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

    products = query_db("SELECT * FROM products ORDER BY id ASC")
    df = pd.DataFrame(products)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], "products_export.xlsx")
    df.to_excel(filepath, index=False)
    return send_file(filepath, as_attachment=True)


# --------------------------
# API: Get product by ID
# --------------------------
@app.route("/api/product/<int:pid>")
@login_required
def api_get_product(pid):
    if session.get("role") == "admin":
        product = query_db(
            "SELECT id, name, qty, barcode, user_id FROM products WHERE id=%s",
            (pid,),
            one=True
        )
    else:
        product = query_db(
            "SELECT id, name, qty, barcode FROM products WHERE id=%s AND user_id=%s",
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
            "barcode": product.get("barcode"),
            "qty": int(product.get("qty") or 0),
        }
    )


# --------------------------
# API: Get product by BARCODE (partial match)
# --------------------------
@app.route("/api/product/barcode/<barcode>")
@login_required
def api_get_product_by_barcode(barcode):
    barcode = (barcode or "").strip()
    like_pattern = f"%{barcode}%"

    if session.get("role") == "admin":
        product = query_db(
            "SELECT id, name, qty, barcode, user_id FROM products WHERE barcode ILIKE %s ORDER BY id DESC LIMIT 1",
            (like_pattern,),
            one=True
        )
    else:
        product = query_db(
            "SELECT id, name, qty, barcode FROM products WHERE barcode ILIKE %s AND user_id=%s ORDER BY id DESC LIMIT 1",
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
            "barcode": product.get("barcode"),
            "qty": int(product.get("qty") or 0),
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
    sku = (data.get("sku") or "").strip()
    if not sku:
        sku = "AUTO-NEW"

    name = (data.get("name") or "").strip() or f"NUII-{sku}"
    qty = int(data.get("qty") or 0)
    min_qty = int(data.get("min_qty") or 0)

    # Upsert by (user_id, sku)
    execute_db("""
        INSERT INTO products (user_id, sku, name, price, cost, qty, min_qty, barcode)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (user_id, sku)
        DO UPDATE SET
            name=EXCLUDED.name,
            price=EXCLUDED.price,
            cost=EXCLUDED.cost,
            qty=EXCLUDED.qty,
            min_qty=EXCLUDED.min_qty,
            barcode=EXCLUDED.barcode
    """, (
        session["user_id"],
        sku,
        name,
        data.get("price", 0) or 0,
        data.get("cost", 0) or 0,
        qty,
        min_qty,
        (data.get("barcode") or "").strip(),
    ))

    return jsonify(success=True)


# --------------------------
# API: Update product
# --------------------------
@app.route("/api/products/update", methods=["POST"])
@csrf.exempt
@login_required
def api_update_product():
    data = request.json or {}
    pid = data.get("id")
    if not pid:
        return jsonify(success=False, error="Missing id"), 400

    name = (data.get("name") or "").strip() or "NUII"
    qty = int(data.get("qty") or 0)
    min_qty = int(data.get("min_qty") or 0)

    if session["role"] == "admin":
        execute_db("""
            UPDATE products
            SET name=%s, price=%s, cost=%s, qty=%s, min_qty=%s, barcode=%s
            WHERE id=%s
        """, (
            name,
            data.get("price", 0) or 0,
            data.get("cost", 0) or 0,
            qty,
            min_qty,
            (data.get("barcode") or "").strip(),
            pid,
        ))
    else:
        execute_db("""
            UPDATE products
            SET name=%s, price=%s, cost=%s, qty=%s, min_qty=%s, barcode=%s
            WHERE id=%s AND user_id=%s
        """, (
            name,
            data.get("price", 0) or 0,
            data.get("cost", 0) or 0,
            qty,
            min_qty,
            (data.get("barcode") or "").strip(),
            pid,
            session["user_id"],
        ))
    return jsonify(success=True)


# --------------------------
# API: Delete product
# --------------------------
@app.route("/api/products/delete/<int:id>", methods=["DELETE"])
@csrf.exempt
@login_required
def api_delete_product(id):
    if session["role"] == "admin":
        execute_db("DELETE FROM products WHERE id=%s", (id,))
    else:
        execute_db("DELETE FROM products WHERE id=%s AND user_id=%s", (id, session["user_id"]))
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
        conn = get_db()
        try:
            with conn.cursor() as cur:
                for upd in data.get("updates", []):
                    cur.execute("""
                        INSERT INTO stocktake_drafts (user_id, product_id, qty)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (user_id, product_id)
                        DO UPDATE SET qty=EXCLUDED.qty
                    """, (
                        session["user_id"],
                        upd["id"],
                        int(upd.get("qty") or 0)
                    ))
            conn.commit()
            return jsonify(success=True)
        except Exception as e:
            conn.rollback()
            return jsonify(success=False, error=str(e)), 500

    drafts = query_db(
        "SELECT product_id, qty FROM stocktake_drafts WHERE user_id=%s",
        (session["user_id"],)
    )
    return jsonify(success=True, drafts=drafts)


# --------------------------
# API: stocktake apply final
# --------------------------
@app.route("/api/stocktake/apply", methods=["POST"])
@csrf.exempt
@login_required
def api_stocktake_apply():
    data = request.json or {}
    conn = get_db()
    changes = []

    try:
        with conn.cursor() as cur:
            for upd in data.get("updates", []):
                cur.execute("SELECT id, name, barcode, qty FROM products WHERE id=%s AND user_id=%s",
                            (upd["id"], session["user_id"]))
                product = cur.fetchone()
                if not product:
                    continue

                old_qty = int(product["qty"] or 0)
                new_qty = int(upd.get("qty") or 0)

                if old_qty == new_qty:
                    continue

                diff = new_qty - old_qty

                cur.execute("UPDATE products SET qty=%s WHERE id=%s AND user_id=%s",
                            (new_qty, upd["id"], session["user_id"]))
                cur.execute("DELETE FROM stocktake_drafts WHERE user_id=%s AND product_id=%s",
                            (session["user_id"], upd["id"]))
                cur.execute("""
                    INSERT INTO stock_movements (user_id, product_id, change_qty, reason)
                    VALUES (%s, %s, %s, %s)
                """, (session["user_id"], upd["id"], diff, "stocktake adjust"))

                changes.append(f"- {product['name']} (📌 {product.get('barcode','')})  {old_qty} ➝ {new_qty}")

        conn.commit()

        if changes:
            send_telegram("✏️ *បន្ថែមស្តុក*\n\n" + "\n".join(changes))

        return jsonify(success=True)

    except Exception as e:
        conn.rollback()
        return jsonify(success=False, error=str(e)), 500


# --------------------------
# API: remove stock (single) - safe
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
    if not product_id or remove_qty <= 0:
        return jsonify(success=False, error="Invalid product or amount"), 400

    reason_full = f"{base_reason} (by {staff_name})" if base_reason else f"(by {staff_name})"

    conn = get_db()
    try:
        with conn.cursor() as cur:
            # lock row
            if session.get("role") == "admin":
                cur.execute("""
                    SELECT id, name, qty, barcode, user_id
                    FROM products
                    WHERE id=%s
                    FOR UPDATE
                """, (product_id,))
                product = cur.fetchone()
                target_user_id = product["user_id"] if product else None
            else:
                cur.execute("""
                    SELECT id, name, qty, barcode
                    FROM products
                    WHERE id=%s AND user_id=%s
                    FOR UPDATE
                """, (product_id, session["user_id"]))
                product = cur.fetchone()
                target_user_id = session["user_id"] if product else None

            if not product:
                conn.rollback()
                return jsonify(success=False, error="Product not found"), 404

            current_qty = int(product["qty"] or 0)
            new_qty = current_qty - remove_qty
            if new_qty < 0:
                conn.rollback()
                return jsonify(success=False, error=f"Not enough stock. Current {current_qty}, remove {remove_qty}"), 400

            if session.get("role") == "admin":
                cur.execute("UPDATE products SET qty=%s WHERE id=%s", (new_qty, product["id"]))
            else:
                cur.execute("UPDATE products SET qty=%s WHERE id=%s AND user_id=%s",
                            (new_qty, product["id"], session["user_id"]))

            cur.execute("""
                INSERT INTO stock_movements (user_id, product_id, change_qty, reason)
                VALUES (%s, %s, %s, %s)
            """, (target_user_id, product["id"], -remove_qty, reason_full))

        conn.commit()

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

    except Exception as e:
        conn.rollback()
        return jsonify(success=False, error=str(e)), 500


# --------------------------
# API: remove stock (BATCH) - atomic
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
        with conn.cursor() as cur:
            for i, it in enumerate(items, start=1):
                product_id = it.get("product_id")
                remove_qty = int(it.get("amount") or 0)
                base_reason = (it.get("reason") or "").strip()
                staff_name = (it.get("staff_name") or "").strip()

                if not staff_name:
                    raise ValueError(f"Row {i}: Staff name required")
                if not product_id or remove_qty <= 0:
                    raise ValueError(f"Row {i}: Invalid product or amount")

                reason_full = f"{base_reason} (by {staff_name})" if base_reason else f"(by {staff_name})"

                # lock product row
                if session.get("role") == "admin":
                    cur.execute("""
                        SELECT id, name, qty, barcode, user_id
                        FROM products
                        WHERE id=%s
                        FOR UPDATE
                    """, (product_id,))
                    product = cur.fetchone()
                    target_user_id = product["user_id"] if product else None
                else:
                    cur.execute("""
                        SELECT id, name, qty, barcode
                        FROM products
                        WHERE id=%s AND user_id=%s
                        FOR UPDATE
                    """, (product_id, session["user_id"]))
                    product = cur.fetchone()
                    target_user_id = session["user_id"] if product else None

                if not product:
                    raise ValueError(f"Row {i}: Product not found")

                current_qty = int(product["qty"] or 0)
                new_qty = current_qty - remove_qty
                if new_qty < 0:
                    raise ValueError(f"Row {i}: Not enough stock (current {current_qty}, remove {remove_qty})")

                # update + movement
                if session.get("role") == "admin":
                    cur.execute("UPDATE products SET qty=%s WHERE id=%s", (new_qty, product["id"]))
                else:
                    cur.execute("UPDATE products SET qty=%s WHERE id=%s AND user_id=%s",
                                (new_qty, product["id"], session["user_id"]))

                cur.execute("""
                    INSERT INTO stock_movements (user_id, product_id, change_qty, reason)
                    VALUES (%s, %s, %s, %s)
                """, (target_user_id, product["id"], -remove_qty, reason_full))

                results.append({
                    "index": i,
                    "product_id": product["id"],
                    "name": product["name"],
                    "barcode": product.get("barcode"),
                    "amount": remove_qty,
                    "old_qty": current_qty,
                    "new_qty": new_qty,
                    "staff_name": staff_name,
                    "reason": base_reason,
                })

                tele_lines.append(
                    f"🔹 *{product['name']}*\n"
                    f"   📌 បាកូដ៖ {product.get('barcode','')}\n"
                    f"   ➖ ដកចេញ៖ {remove_qty}\n"
                    f"   📉 មុន៖ {current_qty} ➜ បន្ទាប់៖ {new_qty}\n"
                    f"   👤 អ្នកដក៖ {staff_name}"
                    + (f"\n   📝 មូលហេតុ៖ {base_reason}" if base_reason else "")
                )

        conn.commit()

        if tele_lines:
            send_telegram(
                "📦 *របាយការណ៍ដកស្តុកចេញ (Batch)*\n"
                "━━━━━━━━━━━━━━━\n"
                + "\n\n".join(tele_lines)
                + "\n━━━━━━━━━━━━━━━"
            )

        return jsonify(success=True, results=results)

    except Exception as e:
        conn.rollback()
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
# Run app
# --------------------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5009)), debug=True)
