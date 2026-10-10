# Fixed version of vulnerable_app.py (see REPORT.md for the list of changes)
import json
import os
import re
import secrets
import sqlite3
import subprocess

from flask import Flask, request, session, abort, send_from_directory, render_template_string, jsonify
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]            # set in the environment, never in code
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=True)
DB = "notes.db"
UPLOAD_DIR = os.path.abspath("uploads")
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


def db():
    return sqlite3.connect(DB)


@app.before_request
def csrf_check():
    if request.method == "POST":
        token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
        if not token or token != session.get("csrf"):
            abort(400)


@app.route("/csrf")
def csrf():
    session.setdefault("csrf", secrets.token_hex(16))
    return jsonify(token=session["csrf"])


@app.route("/register", methods=["POST"])
def register():
    user = request.form["username"]
    pw = generate_password_hash(request.form["password"])     # salted, slow hash
    conn = db()
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (user, pw))
    conn.commit()
    return "registered"


@app.route("/login", methods=["POST"])
def login():
    row = db().execute("SELECT id, password FROM users WHERE username=?",
                       (request.form["username"],)).fetchone()
    if row and check_password_hash(row[1], request.form["password"]):
        session.clear()
        session["uid"] = row[0]
        session["csrf"] = secrets.token_hex(16)
        return "ok"
    return "wrong username or password", 401      # same message either way


@app.route("/search")
def search():
    return render_template_string("<h1>Results for {{ q }}</h1>", q=request.args.get("q", ""))


@app.route("/note/<int:note_id>")
def get_note(note_id):
    if "uid" not in session:
        abort(401)
    row = db().execute("SELECT body FROM notes WHERE id=? AND owner_id=?",
                       (note_id, session["uid"])).fetchone()
    if not row:
        abort(404)
    return escape(row[0])


@app.route("/download")
def download():
    return send_from_directory(UPLOAD_DIR, request.args.get("file", ""))   # blocks ../


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not HOST_RE.match(host):
        abort(400)
    out = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5)
    return out.stdout


@app.route("/import", methods=["POST"])
def import_notes():
    data = json.loads(request.data)         # JSON instead of pickle
    if not isinstance(data, list):
        abort(400)
    return str(len(data))


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)
