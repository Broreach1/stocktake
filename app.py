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
from flask_wtf.csrf import CSRFProtect, CSRFError

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
        INSERT OR IGNORE INTO users (username, password, role)
        VALUES (?, ?, ?)
    """, ("admin", generate_password_hash("admin123"), "admin"))

    db.commit()


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
# LOGIN (CSRF EXEMPT ✅)
# ==========================
@app.route("/login", methods=["GET", "POST"])
@csrf.exempt
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
    return "<h2>Login OK ✅</h2>"


# ==========================
# CSRF ERROR HANDLER (NO 500)
# ==========================
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return jsonify(
        error="CSRF validation failed",
        detail=str(e)
    ), 400


# ==========================
# GLOBAL ERROR HANDLER
# ==========================
@app.errorhandler(Exception)
def handle_exception(e):
    print("ERROR:", repr(e))
    return jsonify(
        error="Internal Server Error",
        detail=str(e)
    ), 500


# ==========================
# Local run
# ==========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5009, debug=True)
