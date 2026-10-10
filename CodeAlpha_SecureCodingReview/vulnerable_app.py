# Small Flask "notes" app used as the target of the secure code review.
# It is INTENTIONALLY insecure - do not deploy it.
import hashlib
import os
import pickle
import sqlite3
import subprocess

from flask import Flask, request, render_template_string, session

app = Flask(__name__)
app.secret_key = "supersecret123"          # hardcoded secret
DB = "notes.db"


def db():
    return sqlite3.connect(DB)


@app.route("/register", methods=["POST"])
def register():
    user = request.form["username"]
    pw = hashlib.md5(request.form["password"].encode()).hexdigest()   # weak hash
    conn = db()
    conn.execute("INSERT INTO users (username, password) VALUES ('%s', '%s')" % (user, pw))
    conn.commit()
    return "registered"


@app.route("/login", methods=["POST"])
def login():
    user = request.form["username"]
    pw = hashlib.md5(request.form["password"].encode()).hexdigest()
    query = f"SELECT id FROM users WHERE username='{user}' AND password='{pw}'"   # SQL injection
    row = db().execute(query).fetchone()
    if row:
        session["uid"] = row[0]
        return "ok"
    return "wrong username or password for " + user


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # reflected XSS: user input goes straight into the template string
    return render_template_string("<h1>Results for " + q + "</h1>")


@app.route("/note/<int:note_id>")
def get_note(note_id):
    # no check that the note belongs to the logged in user (IDOR)
    row = db().execute("SELECT body FROM notes WHERE id=%d" % note_id).fetchone()
    return row[0] if row else "not found"


@app.route("/download")
def download():
    name = request.args.get("file")
    with open(os.path.join("uploads", name)) as f:      # path traversal
        return f.read()


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)   # command injection


@app.route("/import", methods=["POST"])
def import_notes():
    data = pickle.loads(request.data)       # insecure deserialization
    return str(len(data))


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)     # debug console exposed on all interfaces
