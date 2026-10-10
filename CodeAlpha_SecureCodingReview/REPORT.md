# Secure Code Review Report

**Target:** `vulnerable_app.py` (Python 3 / Flask notes app, ~80 lines)
**Method:** manual review line by line + static analysis (`bandit -r .`, `semgrep --config auto .` if you have them)
**Reference:** OWASP Top 10 (2021)

## Summary

| # | Finding | Severity | OWASP | Line area |
|---|---------|----------|-------|-----------|
| 1 | SQL injection in `/login` and `/register` | Critical | A03 Injection | login(), register() |
| 2 | OS command injection in `/ping` | Critical | A03 Injection | ping() |
| 3 | Insecure deserialization (`pickle.loads`) | Critical | A08 Integrity Failures | import_notes() |
| 4 | Debug mode on and bound to 0.0.0.0 | High | A05 Misconfiguration | `app.run(...)` |
| 5 | Hardcoded secret key | High | A02 Crypto Failures | top of file |
| 6 | Path traversal in `/download` | High | A01 Broken Access Control | download() |
| 7 | Broken object-level access (IDOR) on `/note/<id>` | High | A01 | get_note() |
| 8 | Reflected XSS in `/search` (SSTI too) | High | A03 Injection | search() |
| 9 | Weak password hashing (unsalted MD5) | High | A02 | register(), login() |
| 10 | No CSRF protection, insecure cookie flags | Medium | A01 / A05 | whole app |
| 11 | User enumeration via error message | Low | A07 Auth Failures | login() |
| 12 | SQL built with `%d` string formatting in `/note` | Medium | A03 | get_note() |

## Details and fixes

### 1. SQL injection (Critical)
`"... WHERE username='{user}' ..."` puts user input straight into SQL.
Payload: username `admin' --` logs in as admin with any password.
**Fix:** parameterized queries: `execute("... WHERE username=?", (user,))`.

### 2. Command injection (Critical)
`subprocess.check_output("ping -c 1 " + host, shell=True)` - sending `host=8.8.8.8;cat /etc/passwd` runs extra commands.
**Fix:** no shell, pass a list, validate the host with a regex, add a timeout.

### 3. Insecure deserialization (Critical)
`pickle.loads()` on request data allows remote code execution (an object can run code when unpickled).
**Fix:** use JSON and validate the structure. Never unpickle untrusted data.

### 4. Debug mode (High)
Werkzeug debugger on `0.0.0.0` lets anyone reach an interactive console.
**Fix:** `debug=False`, bind to `127.0.0.1` and put it behind gunicorn + a reverse proxy.

### 5. Hardcoded secret (High)
`secret_key = "supersecret123"` is in the repo, so session cookies can be forged.
**Fix:** read from an environment variable / secrets manager, rotate the old key.

### 6. Path traversal (High)
`file=../../etc/passwd` escapes `uploads/`.
**Fix:** `send_from_directory()` (or resolve the path and check it stays inside the folder).

### 7. IDOR (High)
Any user can read any note by changing the id.
**Fix:** require login and filter by `owner_id = session["uid"]`.

### 8. XSS / template injection (High)
Concatenating `q` into `render_template_string` allows `<script>` and also Jinja expressions like `{{7*7}}`.
**Fix:** pass user data as a template variable (`{{ q }}` is auto-escaped).

### 9. Weak hashing (High)
MD5 without salt is cracked in seconds with rainbow tables.
**Fix:** `generate_password_hash` / `check_password_hash` (or bcrypt/argon2).

### 10. CSRF and cookies (Medium)
State-changing POSTs have no token; cookies lack `HttpOnly`, `Secure`, `SameSite`.
**Fix:** CSRF token per session (or Flask-WTF), set the cookie flags.

### 11. User enumeration (Low)
"wrong username or password for admin" echoes input (also reflection) and can differ between cases.
**Fix:** one generic message, return 401, add rate limiting (Flask-Limiter).

### 12. Formatted SQL in `/note` (Medium)
`%d` with an int-typed route is safe in practice, but it is the same bad habit as #1.
**Fix:** use `?` placeholders everywhere.

## General recommendations
- Validate input on the server, escape on output.
- Least privilege for the DB account and the OS user running the app.
- Keep dependencies updated (`pip-audit`).
- Add `bandit` / `semgrep` to CI so these get caught before merge.
- Log failed logins, never log passwords.

## Re-test
After applying the changes (`secure_app.py`) the injection payloads above return 400/401/404 instead of executing. Run `bandit -r .` again and the High findings for SQLi, shell=True, pickle and debug disappear.
