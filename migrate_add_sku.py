from flask import Flask, render_template, g
import sqlite3

app = Flask(__name__)
DB_PATH = "pos.db"

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row  # Keep Row objects for fetching
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rows = cur.fetchall()
    cur.close()
    # Convert Row objects to plain dicts
    results = [dict(row) for row in rows]
    return (results[0] if results else None) if one else results

@app.route('/products')
def products_page():
    products = query_db("SELECT * FROM products ORDER BY id ASC")

    # Ensure safe defaults for missing columns
    safe_products = []
    for p in products:
        safe_products.append({
            'id': p.get('id', 0),
            'sku': p.get('sku', ''),
            'name': p.get('name', ''),
            'price': p.get('price', 0.0),
            'cost': p.get('cost', 0.0),
            'qty': p.get('qty', 0),
            'min_qty': p.get('min_qty', 0),
            'barcode': p.get('barcode', '')
        })

    return render_template('products.html', products=safe_products)
