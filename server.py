#!/usr/bin/env python3
"""Słowo na dziś: serves the app and a small JSON API for accounts, sessions and saved verses.

Run:  py server.py        (then open http://127.0.0.1:8000)
Environment: HOST, PORT, SLOWO_DB (database file), SLOWO_SECURE=1 (cookies only over HTTPS),
TRUST_PROXY=1 (take the client address and scheme from X-Forwarded-* headers).
SLOWO_ADMIN (login that gets the admin panel; without it the very first account does),
SLOWO_HOSTS (comma-separated host names the app answers to; others are refused).
Mail for verification codes: SMTP_HOST, SMTP_PORT (587, or 465 for implicit TLS), SMTP_USER,
SMTP_PASSWORD, SMTP_FROM. Without SMTP_HOST the code is printed to this console instead of being sent.
Needs only the Python standard library.
"""
import base64
import gzip
import hashlib
import hmac
import json
import os
import re
import secrets
import signal
import smtplib
import sqlite3
import ssl
import threading
import time
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

ROOT = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("SLOWO_DB", os.path.join(ROOT, "slowo.db"))
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))
SECURE = os.environ.get("SLOWO_SECURE") == "1"
TRUST_PROXY = os.environ.get("TRUST_PROXY") == "1"
ADMIN_LOGIN = os.environ.get("SLOWO_ADMIN", "").strip().casefold()
ALLOWED_HOSTS = {h.strip().lower() for h in os.environ.get("SLOWO_HOSTS", "").split(",") if h.strip()}
MAX_CONNECTIONS = 128       # connections served at once; further ones are dropped
API_PER_MINUTE = 300        # API requests one address may make in a minute
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "") or SMTP_USER

SESSION_SECONDS = 30 * 24 * 3600
MAX_BODY = 64 * 1024
CODE_SECONDS = 15 * 60      # how long a verification code stays valid
RESEND_SECONDS = 60         # shortest gap between two codes for one registration
MAX_SENDS = 5               # codes sent per registration
MAX_TRIES = 5               # wrong codes allowed per code
LANGS = {"pl", "en", "es", "de", "fr", "it", "sv"}
SOURCES = {"sel", "nt", "ot"}
LOGIN_RE = re.compile(r"^[\w.\-]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s<>\"',;]{1,64}@[^@\s<>\"',;]{1,190}\.[^@\s<>\"',;.]{2,24}$")
FAV_RE = re.compile(r"^[A-Za-z ]{2,40}\|\d{1,3}\|\d{1,3}(\|\d{1,3})?$")
DATA_RE = re.compile(r"^/data/((?:nt|ot)-[a-z]{2}\.js)$")
SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}

now_ms = lambda: int(time.time() * 1000)

# ---------- database ----------
db = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
db.row_factory = sqlite3.Row
db_lock = threading.Lock()
db.executescript("""
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS accounts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  login TEXT NOT NULL,
  login_key TEXT NOT NULL UNIQUE,
  hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  created INTEGER NOT NULL,
  last_login INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pending(
  token_hash TEXT PRIMARY KEY,
  login TEXT NOT NULL,
  email TEXT NOT NULL,
  hash TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  expires INTEGER NOT NULL,
  last_sent INTEGER NOT NULL,
  sends INTEGER NOT NULL DEFAULT 1,
  tries INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY,
  account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS state(
  account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  body TEXT NOT NULL,
  updated INTEGER NOT NULL
);
""")


if "email" not in [r["name"] for r in db.execute("PRAGMA table_info(accounts)")]:   # databases made before e-mail was required
    db.execute("ALTER TABLE accounts ADD COLUMN email TEXT")
db.execute("CREATE UNIQUE INDEX IF NOT EXISTS accounts_email ON accounts(lower(email)) WHERE email IS NOT NULL")


def public(row):
    return {"id": "s%d" % row["id"], "login": row["login"], "email": row["email"], "role": row["role"],
            "created": row["created"], "lastLogin": row["last_login"]}


sha = lambda text: hashlib.sha256(text.encode("utf-8")).hexdigest()
new_code = lambda: "%06d" % secrets.randbelow(10 ** 6)


def mask(email):
    name, _, domain = email.partition("@")
    return name[:1] + "***@" + domain


def send_code(email, code):
    """Sends the verification code. Returns "email", or "console" when no mail server is configured."""
    if not SMTP_HOST:
        print("[mail] SMTP_HOST is not set; verification code for %s: %s" % (email, code), flush=True)
        return "console"
    msg = EmailMessage()
    msg["Subject"] = "Słowo na dziś: kod weryfikacyjny %s" % code
    msg["From"] = SMTP_FROM
    msg["To"] = email
    msg.set_content("Twój kod weryfikacyjny do aplikacji Słowo na dziś: %s\n\n"
                    "Kod jest ważny %d minut. Jeśli to nie ty zakładasz konto, zignoruj tę wiadomość.\n"
                    % (code, CODE_SECONDS // 60))
    context = ssl.create_default_context()
    if SMTP_PORT == 465:
        smtp = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15, context=context)
    else:
        smtp = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15)
    with smtp:
        if SMTP_PORT != 465:
            smtp.starttls(context=context)
        if SMTP_USER:
            smtp.login(SMTP_USER, SMTP_PASSWORD)
        smtp.send_message(msg)
    return "email"


# ---------- passwords ----------
def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, dklen=32, **SCRYPT)
    return "scrypt$%d$%d$%d$%s$%s" % (SCRYPT["n"], SCRYPT["r"], SCRYPT["p"], salt.hex(), digest.hex())


def check_password(password, stored):
    try:
        kind, n, r, p, salt, digest = stored.split("$")
        if kind != "scrypt":
            return False
        got = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(got.hex(), digest)
    except (ValueError, TypeError):
        return False


DUMMY_HASH = hash_password(secrets.token_hex(16))   # checked when the login is unknown, so both cases take the same time

# ---------- rate limiting (in memory) ----------
attempts = {}
attempts_lock = threading.Lock()


def too_many(key, limit, window):
    """True when `key` already has `limit` entries within the last `window` seconds."""
    cutoff = time.time() - window
    with attempts_lock:
        recent = [t for t in attempts.get(key, []) if t > cutoff]
        attempts[key] = recent
        return len(recent) >= limit


def note(key):
    with attempts_lock:
        attempts.setdefault(key, []).append(time.time())
        if len(attempts) > 20000:
            attempts.clear()


# ---------- static files ----------
static_cache = {}
static_lock = threading.Lock()


def static_file(path):
    """Returns (file path, content type, cache header) for the few files the app is made of."""
    if path in ("/", "/index.html"):
        return os.path.join(ROOT, "index.html"), "text/html; charset=utf-8", "no-cache"
    if path == "/vendor/bcrypt.min.js":
        return os.path.join(ROOT, "vendor", "bcrypt.min.js"), "text/javascript; charset=utf-8", "public, max-age=86400"
    m = DATA_RE.match(path)
    if m:
        return os.path.join(ROOT, "data", m.group(1)), "text/javascript; charset=utf-8", "public, max-age=86400"
    return None


INLINE_SCRIPT_RE = re.compile(rb"<script>(.*?)</script>", re.S)
csp_cache = {}


def unix_newlines(data):
    """CRLF and lone CR as LF, the way a browser reads a page before it hashes a script."""
    return data.replace(bytes([13, 10]), bytes([10])).replace(bytes([13]), bytes([10]))


def page_policy(etag, raw):
    """The Content-Security-Policy for the page: only its own inline scripts (named by hash) and its own files run."""
    hit = csp_cache.get("page")
    if hit and hit[0] == etag:
        return hit[1]
    # a browser reads CRLF as LF before it hashes a script, so the hash is taken the same way
    hashes = " ".join("'sha256-%s'" % base64.b64encode(hashlib.sha256(unix_newlines(m)).digest()).decode("ascii")
                      for m in INLINE_SCRIPT_RE.findall(raw))
    policy = ("default-src 'self'; script-src 'self' %s; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
              "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; object-src 'none'; "
              "base-uri 'none'; form-action 'self'; frame-ancestors 'none'" % hashes)
    csp_cache["page"] = (etag, policy)
    return policy


def load_static(file_path):
    """Returns (etag, raw bytes, gzipped bytes), compressed once per file version."""
    st = os.stat(file_path)
    etag = '"%x-%x"' % (st.st_mtime_ns, st.st_size)
    with static_lock:
        hit = static_cache.get(file_path)
        if hit and hit[0] == etag:
            return hit
    with open(file_path, "rb") as f:
        raw = f.read()
    entry = (etag, raw, gzip.compress(raw, 6))
    with static_lock:
        static_cache[file_path] = entry
    return entry


class ApiError(Exception):
    def __init__(self, status, error):
        self.status, self.error = status, error


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Slowo"
    sys_version = ""
    timeout = 20

    # ----- plumbing -----
    def client_ip(self):
        if TRUST_PROXY:
            fwd = self.headers.get("X-Forwarded-For", "")
            if fwd:
                return fwd.split(",")[0].strip()
        return self.client_address[0]

    def is_https(self):
        return SECURE or (TRUST_PROXY and self.headers.get("X-Forwarded-Proto") == "https")

    def send_bytes(self, status, body, ctype, extra=()):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        if self.is_https():
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if not any(k == "Content-Security-Policy" for k, _ in extra):      # everything but the page itself: nothing may load or run
            self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, status, obj, extra=()):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_bytes(status, body, "application/json; charset=utf-8", [("Cache-Control", "no-store")] + list(extra))

    def read_body(self):
        """Always drains the request body, so a refused request cannot corrupt the next one on the connection."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            self.close_connection = True
            raise ApiError(413 if length > 0 else 400, "too_large" if length > 0 else "bad_request")
        return self.rfile.read(length) if length else b""

    def read_json(self):
        if not self.body:
            return {}
        if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
            raise ApiError(415, "unsupported_type")
        try:
            data = json.loads(self.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError):      # RecursionError: absurdly deep nesting
            raise ApiError(400, "bad_request")
        if not isinstance(data, dict):
            raise ApiError(400, "bad_request")
        return data

    def cookie_token(self):
        for part in self.headers.get("Cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == "sid" and value:
                return value
        return None

    def cookie_header(self, token, max_age):
        return ("Set-Cookie", "sid=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict%s"
                % (token, max_age, "; Secure" if self.is_https() else ""))

    def current(self):
        """The signed-in account row, or None."""
        token = self.cookie_token()
        if not token:
            return None
        th = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with db_lock:
            return db.execute(
                "SELECT a.* FROM sessions s JOIN accounts a ON a.id=s.account_id WHERE s.token_hash=? AND s.expires>?",
                (th, now_ms())).fetchone()

    def require(self, admin=False):
        acc = self.current()
        if not acc:
            raise ApiError(401, "unauthorized")
        if admin and acc["role"] != "admin":
            raise ApiError(403, "forbidden")
        return acc

    def start_session(self, account_id):
        token = secrets.token_urlsafe(32)
        th = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with db_lock:
            db.execute("DELETE FROM sessions WHERE expires<?", (now_ms(),))
            db.execute("INSERT INTO sessions(token_hash,account_id,expires) VALUES(?,?,?)",
                       (th, account_id, now_ms() + SESSION_SECONDS * 1000))
        return self.cookie_header(token, SESSION_SECONDS)

    def check_origin(self):
        """Changes are accepted only from the app's own pages: a custom header plus a same-host Origin."""
        if self.headers.get("X-Requested-With") != "slowo":
            raise ApiError(403, "forbidden")
        origin = self.headers.get("Origin")
        if origin and urlsplit(origin).netloc != self.headers.get("Host"):
            raise ApiError(403, "forbidden")

    # ----- routing -----
    def do_GET(self):
        self.route()

    do_HEAD = do_POST = do_PUT = do_DELETE = do_GET

    def route(self):
        path = urlsplit(self.path).path
        try:
            self.body = self.read_body()
            if ALLOWED_HOSTS and self.headers.get("Host", "").split(":")[0].lower() not in ALLOWED_HOSTS:
                raise ApiError(400, "bad_host")
            if path.startswith("/api/"):
                ip = self.client_ip()
                if too_many(("api", ip), API_PER_MINUTE, 60):
                    raise ApiError(429, "too_many")
                note(("api", ip))
                if self.command not in ("GET", "HEAD"):
                    self.check_origin()
                self.api(self.command, path[5:])
            elif self.command in ("GET", "HEAD"):
                self.static(path)
            else:
                raise ApiError(405, "method_not_allowed")
        except ApiError as e:
            self.send_json(e.status, {"ok": False, "error": e.error})
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception:
            self.log_error("unhandled error on %s %s", self.command, path)
            self.send_json(500, {"ok": False, "error": "server"})

    def static(self, path):
        found = static_file(path)
        if not found or not os.path.isfile(found[0]):
            return self.send_bytes(404, b"Not found", "text/plain; charset=utf-8")
        file_path, ctype, cache = found
        etag, raw, packed = load_static(file_path)
        headers = [("ETag", etag), ("Cache-Control", cache), ("Vary", "Accept-Encoding")]
        if self.headers.get("If-None-Match") == etag:
            self.send_response(304)
            for k, v in headers:
                self.send_header(k, v)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if ctype.startswith("text/html"):
            headers.append(("Content-Security-Policy", page_policy(etag, raw)))
        if "gzip" in self.headers.get("Accept-Encoding", ""):
            return self.send_bytes(200, packed, ctype, headers + [("Content-Encoding", "gzip")])
        self.send_bytes(200, raw, ctype, headers)

    def api(self, method, path):
        if method == "GET" and path == "me":
            acc = self.current()
            return self.send_json(200, {"ok": True, "account": public(acc) if acc else None})
        if method == "POST" and path == "register":
            return self.register()
        if method == "POST" and path == "verify":
            return self.verify()
        if method == "POST" and path == "resend":
            return self.resend()
        if method == "POST" and path == "login":
            return self.login()
        if method == "POST" and path == "logout":
            token = self.cookie_token()
            if token:
                with db_lock:
                    db.execute("DELETE FROM sessions WHERE token_hash=?",
                               (hashlib.sha256(token.encode("utf-8")).hexdigest(),))
            return self.send_json(200, {"ok": True}, [self.cookie_header("", 0)])
        if method == "DELETE" and path == "me":
            acc = self.require()
            with db_lock:
                db.execute("DELETE FROM accounts WHERE id=?", (acc["id"],))
            return self.send_json(200, {"ok": True}, [self.cookie_header("", 0)])
        if path == "state":
            acc = self.require()
            if method == "GET":
                with db_lock:
                    row = db.execute("SELECT body FROM state WHERE account_id=?", (acc["id"],)).fetchone()
                return self.send_json(200, {"ok": True, "state": json.loads(row["body"]) if row else None})
            if method == "PUT":
                return self.put_state(acc)
        if method == "GET" and path == "admin/accounts":
            self.require(admin=True)
            with db_lock:
                rows = db.execute("SELECT * FROM accounts ORDER BY created").fetchall()
            return self.send_json(200, {"ok": True, "accounts": [public(r) for r in rows]})
        m = re.match(r"^admin/accounts/s(\d{1,12})$", path)
        if method == "DELETE" and m:
            acc = self.require(admin=True)
            if int(m.group(1)) == acc["id"]:
                raise ApiError(400, "own_account")
            with db_lock:
                db.execute("DELETE FROM accounts WHERE id=?", (int(m.group(1)),))
            return self.send_json(200, {"ok": True})
        raise ApiError(404, "not_found")

    # ----- handlers -----
    def credentials(self):
        data = self.read_json()
        login, password = data.get("login"), data.get("password")
        if not isinstance(login, str) or not isinstance(password, str):
            raise ApiError(400, "bad_request")
        return login.strip(), password

    def register(self):
        """Step one: keeps the registration aside and mails a code. The account is created by verify()."""
        ip = self.client_ip()
        if too_many(("register", ip), 10, 3600):
            raise ApiError(429, "too_many")
        data = self.read_json()
        login, password, email = data.get("login"), data.get("password"), data.get("email")
        if not all(isinstance(x, str) for x in (login, password, email)):
            raise ApiError(400, "bad_request")
        login, email = login.strip(), email.strip()
        if not LOGIN_RE.match(login) or not 8 <= len(password) <= 128:
            raise ApiError(400, "invalid")
        if len(email) > 254 or not EMAIL_RE.match(email):
            raise ApiError(400, "invalid_email")
        note(("register", ip))
        with db_lock:
            if db.execute("SELECT 1 FROM accounts WHERE login_key=?", (login.casefold(),)).fetchone():
                raise ApiError(409, "taken")
            if db.execute("SELECT 1 FROM accounts WHERE lower(email)=lower(?)", (email,)).fetchone():
                raise ApiError(409, "email_taken")
        token, code, t = secrets.token_urlsafe(24), new_code(), now_ms()
        hashed = hash_password(password)
        with db_lock:
            db.execute("DELETE FROM pending WHERE expires<? OR lower(email)=lower(?)", (t, email))
            db.execute("INSERT INTO pending(token_hash,login,email,hash,code_hash,expires,last_sent) VALUES(?,?,?,?,?,?,?)",
                       (sha(token), login, email, hashed, sha(token + code), t + CODE_SECONDS * 1000, t))
        self.deliver(token, email, code)

    def deliver(self, token, email, code):
        try:
            how = send_code(email, code)
        except (OSError, smtplib.SMTPException):
            self.log_error("could not send the verification code")
            raise ApiError(502, "mail_failed")
        self.send_json(200, {"ok": True, "pending": token, "email": mask(email), "delivery": how,
                             "resendAfter": RESEND_SECONDS})

    def pending_row(self):
        data = self.read_json()
        token = data.get("pending")
        if not isinstance(token, str) or not token:
            raise ApiError(400, "bad_request")
        with db_lock:
            row = db.execute("SELECT * FROM pending WHERE token_hash=? AND expires>?", (sha(token), now_ms())).fetchone()
        if not row:
            raise ApiError(410, "expired")
        return data, token, row

    def resend(self):
        _, token, row = self.pending_row()
        t = now_ms()
        if row["sends"] >= MAX_SENDS:
            raise ApiError(429, "too_many")
        if t - row["last_sent"] < RESEND_SECONDS * 1000:
            raise ApiError(429, "wait")
        code = new_code()
        with db_lock:
            db.execute("UPDATE pending SET code_hash=?,expires=?,last_sent=?,sends=sends+1,tries=0 WHERE token_hash=?",
                       (sha(token + code), t + CODE_SECONDS * 1000, t, sha(token)))
        self.deliver(token, row["email"], code)

    def verify(self):
        data, token, row = self.pending_row()
        code = data.get("code")
        if not isinstance(code, str):
            raise ApiError(400, "bad_request")
        if not hmac.compare_digest(sha(token + code.strip()), row["code_hash"]):
            last = row["tries"] + 1 >= MAX_TRIES
            with db_lock:
                if last:
                    db.execute("DELETE FROM pending WHERE token_hash=?", (sha(token),))
                else:
                    db.execute("UPDATE pending SET tries=tries+1 WHERE token_hash=?", (sha(token),))
            raise ApiError(410, "expired") if last else ApiError(400, "wrong_code")
        t = now_ms()
        with db_lock:
            try:
                db.execute("BEGIN IMMEDIATE")
                # The admin panel goes to the login named in SLOWO_ADMIN, or without it to the very first account.
                # A later account never becomes an administrator just because the earlier one is gone.
                if ADMIN_LOGIN:
                    role = "admin" if row["login"].casefold() == ADMIN_LOGIN else "user"
                else:
                    role = "user" if db.execute("SELECT 1 FROM accounts").fetchone() else "admin"
                cur = db.execute(
                    "INSERT INTO accounts(login,login_key,email,hash,role,created,last_login) VALUES(?,?,?,?,?,?,?)",
                    (row["login"], row["login"].casefold(), row["email"], row["hash"], role, t, t))
                db.execute("DELETE FROM pending WHERE token_hash=?", (sha(token),))
                db.execute("COMMIT")
                taken = False
            except sqlite3.IntegrityError:      # someone else confirmed the same login or address first
                db.execute("ROLLBACK")
                db.execute("DELETE FROM pending WHERE token_hash=?", (sha(token),))
                taken = True
            acc = None if taken else db.execute("SELECT * FROM accounts WHERE id=?", (cur.lastrowid,)).fetchone()
        if taken:
            raise ApiError(409, "taken")
        self.send_json(200, {"ok": True, "account": public(acc)}, [self.start_session(acc["id"])])

    def login(self):
        ip = self.client_ip()
        login, password = self.credentials()
        key = login.casefold()
        if too_many(("login-ip", ip), 30, 900) or too_many(("login", key), 10, 900):
            raise ApiError(429, "too_many")
        with db_lock:
            row = db.execute("SELECT * FROM accounts WHERE login_key=?", (key,)).fetchone()
        ok = check_password(password, row["hash"] if row else DUMMY_HASH) and row is not None
        if not ok:
            note(("login-ip", ip))
            note(("login", key))
            raise ApiError(401, "wrong")
        t = now_ms()
        with db_lock:
            db.execute("UPDATE accounts SET last_login=? WHERE id=?", (t, row["id"]))
            row = db.execute("SELECT * FROM accounts WHERE id=?", (row["id"],)).fetchone()
        self.send_json(200, {"ok": True, "account": public(row)}, [self.start_session(row["id"])])

    def put_state(self, acc):
        d = self.read_json()
        extra, favs = d.get("extra"), d.get("favs")
        if (d.get("main") not in LANGS or d.get("src") not in SOURCES
                or not isinstance(extra, list) or any(x not in LANGS for x in extra) or len(extra) > len(LANGS)
                or not isinstance(favs, list) or len(favs) > 2000
                or any(not isinstance(x, str) or not FAV_RE.match(x) for x in favs)):
            raise ApiError(400, "invalid")
        t = now_ms()
        body = json.dumps({"main": d["main"], "extra": extra, "favs": favs, "src": d["src"], "updated": t})
        with db_lock:
            db.execute("INSERT INTO state(account_id,body,updated) VALUES(?,?,?) "
                       "ON CONFLICT(account_id) DO UPDATE SET body=excluded.body,updated=excluded.updated",
                       (acc["id"], body, t))
        self.send_json(200, {"ok": True})


class Server(ThreadingHTTPServer):
    """Serves at most MAX_CONNECTIONS connections at once, so a flood of them cannot use up threads and memory."""
    daemon_threads = True
    request_queue_size = 64
    slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):      # a dropped or timed-out connection is not worth a traceback
        pass


def stop(*_):
    raise KeyboardInterrupt


if __name__ == "__main__":
    server = Server((HOST, PORT), Handler)
    signal.signal(signal.SIGTERM, stop)      # "docker stop" ends the server cleanly
    print("Slowo na dzis: http://%s:%d" % (HOST, PORT), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
