# app.py
import os
import sqlite3
from functools import wraps

from flask import (
    Flask, render_template, jsonify, request, g,
    redirect, url_for, session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "app.db")

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.auto_reload = True

# IMPORTANT: set your own secret key (prefer env var)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")


# ---------- DB ----------
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys = ON;")

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    db.execute("""
    CREATE TABLE IF NOT EXISTS uploads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        orig_name TEXT NOT NULL,
        stored_name TEXT NOT NULL UNIQUE,
        size_bytes INTEGER NOT NULL,
        mime TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
""")

    # ---- migration: add display_name column if missing
    cols = db.execute("PRAGMA table_info(users)").fetchall()
    col_names = {c[1] for c in cols}
    if "display_name" not in col_names:
        db.execute("ALTER TABLE users ADD COLUMN display_name TEXT;")
        db.execute("UPDATE users SET display_name = username WHERE display_name IS NULL;")

    db.commit()
    db.close()


# ---------- Auth helpers ----------
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None

    row = get_db().execute(
        "SELECT id, username, display_name, created_at FROM users WHERE id = ?",
        (uid,)
    ).fetchone()

    return dict(row) if row else None


@app.before_request
def load_user():
    g.user = current_user()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not g.user:
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


@app.context_processor
def inject_user():
    return {"user": g.user}


# ---------- Pages ----------
@app.get("/")
@login_required
def index():
    return render_template("index.html", active_page="index")




@app.get("/profile")
@login_required
def profile():
    return render_template("profile.html", active_page="profile")


@app.get("/profile/edit")
@login_required
def profile_edit():
    return render_template("profile_edit.html", active_page="profile")


@app.post("/profile/edit")
@login_required
def profile_edit_post():
    db = get_db()

    # ---- display name ----
    display_name = (request.form.get("display_name") or "").strip()
    if len(display_name) > 40:
        flash("Имя: максимум 40 символов", "error")
        return redirect(url_for("profile_edit"))

    db.execute(
        "UPDATE users SET display_name = ? WHERE id = ?",
        (display_name if display_name else None, g.user["id"])
    )
    db.commit()

    # ---- username ----
    username = (request.form.get("username") or "").strip()
    if not (3 <= len(username) <= 20):
        flash("Логин: 3–20 символов", "error")
        return redirect(url_for("profile_edit"))

    if username != g.user["username"]:
        try:
            db.execute("UPDATE users SET username = ? WHERE id = ?", (username, g.user["id"]))
            db.commit()
        except sqlite3.IntegrityError:
            flash("Такой логин уже занят", "error")
            return redirect(url_for("profile_edit"))
        
        

    # ---- password change (optional) ----
    current_password = request.form.get("current_password") or ""
    new_password = request.form.get("new_password") or ""
    new_password2 = request.form.get("new_password2") or ""

    wants_password_change = any([current_password, new_password, new_password2])
    if wants_password_change:
        if not (current_password and new_password and new_password2):
            flash("Для смены пароля заполни текущий пароль и два раза новый", "error")
            return redirect(url_for("profile_edit"))

        if new_password != new_password2:
            flash("Новые пароли не совпадают", "error")
            return redirect(url_for("profile_edit"))

        if len(new_password) < 6:
            flash("Новый пароль: минимум 6 символов", "error")
            return redirect(url_for("profile_edit"))

        row = db.execute("SELECT password_hash FROM users WHERE id = ?", (g.user["id"],)).fetchone()
        if not row or not check_password_hash(row["password_hash"], current_password):
            flash("Текущий пароль неверный", "error")
            return redirect(url_for("profile_edit"))

        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), g.user["id"])
        )
        db.commit()

    flash("Профиль обновлён", "ok")
    return redirect(url_for("profile"))

import secrets
from werkzeug.utils import secure_filename
from flask import send_from_directory, abort

UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.get("/cloud")
@login_required
def cloud():
    rows = get_db().execute(
        "SELECT id, orig_name, size_bytes, mime, created_at "
        "FROM uploads WHERE user_id = ? ORDER BY id DESC",
        (g.user["id"],)
    ).fetchall()
    return render_template("cloud.html", active_page="cloud", files=[dict(r) for r in rows])

@app.post("/cloud/upload")
@login_required
def cloud_upload():
    if "files" not in request.files:
        return redirect(url_for("cloud"))

    files = request.files.getlist("files")
    db = get_db()

    for f in files:
        if not f or not f.filename:
            continue

        orig_name = f.filename
        safe_name = secure_filename(orig_name)  # чистим имя файла
        if not safe_name:
            continue

        ext = os.path.splitext(safe_name)[1].lower()
        token = secrets.token_hex(16)
        stored_name = f"{g.user['id']}_{token}{ext}"
        path = os.path.join(UPLOAD_DIR, stored_name)

        f.save(path)

        size_bytes = os.path.getsize(path)
        mime = f.mimetype

        db.execute(
            "INSERT INTO uploads(user_id, orig_name, stored_name, size_bytes, mime) VALUES (?, ?, ?, ?, ?)",
            (g.user["id"], orig_name, stored_name, size_bytes, mime)
        )

    db.commit()
    return redirect(url_for("cloud"))

@app.get("/cloud/download/<int:file_id>")
@login_required
def cloud_download(file_id: int):
    row = get_db().execute(
        "SELECT id, orig_name, stored_name FROM uploads WHERE id = ? AND user_id = ?",
        (file_id, g.user["id"])
    ).fetchone()

    if not row:
        abort(404)

    return send_from_directory(
        UPLOAD_DIR,
        row["stored_name"],
        as_attachment=True,
        download_name=row["orig_name"]
    )

@app.get("/cloud/view/<int:file_id>")
@login_required
def cloud_view(file_id: int):
    row = get_db().execute(
        "SELECT stored_name, mime FROM uploads WHERE id = ? AND user_id = ?",
        (file_id, g.user["id"])
    ).fetchone()

    if not row:
        abort(404)

    return send_from_directory(
        UPLOAD_DIR,
        row["stored_name"],
        mimetype=row["mime"],
        as_attachment=False
    )


@app.post("/cloud/delete/<int:file_id>")
@login_required
def cloud_delete(file_id: int):
    db = get_db()
    row = db.execute(
        "SELECT stored_name FROM uploads WHERE id = ? AND user_id = ?",
        (file_id, g.user["id"])
    ).fetchone()

    if not row:
        abort(404)

    stored = row["stored_name"]
    db.execute("DELETE FROM uploads WHERE id = ? AND user_id = ?", (file_id, g.user["id"]))
    db.commit()

    try:
        os.remove(os.path.join(UPLOAD_DIR, stored))
    except FileNotFoundError:
        pass

    return redirect(url_for("cloud"))

# ---------- Auth ----------
@app.get("/login")
def login():
    if g.user:
        return redirect(url_for("index"))
    return render_template("login.html", active_page="")


@app.post("/login")
def login_post():
    if g.user:
        return redirect(url_for("index"))

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    if not username or not password:
        flash("Введите логин и пароль", "error")
        return redirect(url_for("login"))

    row = get_db().execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if not row or not check_password_hash(row["password_hash"], password):
        flash("Неверный логин или пароль", "error")
        return redirect(url_for("login"))

    session.clear()
    session["user_id"] = row["id"]
    return redirect(url_for("index"))


@app.get("/register")
def register():
    if g.user:
        return redirect(url_for("index"))
    return render_template("register.html", active_page="")


@app.post("/register")
def register_post():
    if g.user:
        return redirect(url_for("index"))

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    password2 = request.form.get("password2") or ""

    if not (3 <= len(username) <= 20):
        flash("Логин: 3–20 символов", "error")
        return redirect(url_for("register"))

    if password != password2:
        flash("Пароли не совпадают", "error")
        return redirect(url_for("register"))

    if len(password) < 6:
        flash("Пароль: минимум 6 символов", "error")
        return redirect(url_for("register"))

    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO users(username, display_name, password_hash) VALUES (?, ?, ?)",
            (username, username, generate_password_hash(password))
        )
        db.commit()
    except sqlite3.IntegrityError:
        flash("Такой логин уже занят", "error")
        return redirect(url_for("register"))

    session.clear()
    session["user_id"] = cur.lastrowid
    return redirect(url_for("index"))


@app.post("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------- Start ----------
if __name__ == "__main__":
    init_db()
if __name__ == "__main__":
    init_db()
    from livereload import Server
    server = Server(app.wsgi_app)
    server.watch("templates/")
    server.watch("static/")
    server.serve(host="0.0.0.0", port=5000, debug=True)
