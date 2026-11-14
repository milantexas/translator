import hashlib, os, re, secrets, sqlite3, tempfile, threading, time
from datetime import timedelta
from functools import wraps
from flask import Flask, g, jsonify, redirect, request, send_from_directory, session
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
import mailer

BACKEND = os.getenv("BACKEND", "argos").lower()   # "argos" (offline) or "aws" (Amazon Translate)
LANGS = [c.strip() for c in os.getenv("LANGS", "en,es,fr,de,it,pt").split(",") if c.strip()]
MAX_CHARS = int(os.getenv("MAX_CHARS", "5000"))
WHISPER_MODEL = os.getenv("WHISPER_MODEL", "base")          # tiny | base | small
APP_NAME = os.getenv("APP_NAME", "Translator")
HISTORY_LIMIT = 200
DATA = os.getenv("XDG_DATA_HOME", "/data")
os.makedirs(DATA, exist_ok=True)
DB_PATH = os.getenv("DB_PATH", os.path.join(DATA, "app.db"))
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")

NAMES = {"en": "English", "es": "Spanish", "fr": "French", "de": "German", "it": "Italian",
         "pt": "Portuguese", "nl": "Dutch", "ru": "Russian", "zh": "Chinese", "ja": "Japanese",
         "ko": "Korean", "ar": "Arabic", "hi": "Hindi", "tr": "Turkish", "pl": "Polish",
         "uk": "Ukrainian", "sv": "Swedish", "vi": "Vietnamese", "id": "Indonesian"}


def secret_key():
    if os.getenv("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    path = os.path.join(DATA, "secret_key")           # generated once, persisted in the volume
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
        os.chmod(path, 0o600)
    return open(path).read().strip()


app = Flask(__name__, static_folder="static")
if os.getenv("TRUST_PROXY", "0") == "1":   # behind Cloudflare Tunnel / Tailscale Funnel / a reverse proxy
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)   # real client IPs for the rate limits
app.config.update(
    SECRET_KEY=secret_key(),
    MAX_CONTENT_LENGTH=int(os.getenv("MAX_UPLOAD_MB", "25")) * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1",   # set 1 once you serve over HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
)

# ---------------------------------------------------------------- database (SQLite)
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  pref_source TEXT NOT NULL DEFAULT 'auto',
  pref_target TEXT NOT NULL DEFAULT 'es',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  email TEXT,
  pending_email TEXT,
  email_verified INTEGER NOT NULL DEFAULT 0,
  is_admin INTEGER NOT NULL DEFAULT 0,
  is_active INTEGER NOT NULL DEFAULT 1,
  sv INTEGER NOT NULL DEFAULT 0,
  last_login TEXT
);
CREATE TABLE IF NOT EXISTS history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  source TEXT NOT NULL, target TEXT NOT NULL,
  original TEXT NOT NULL, translation TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_history_user ON history(user_id, id DESC);
CREATE TABLE IF NOT EXISTS tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""
MIGRATIONS = [("email", "TEXT"), ("pending_email", "TEXT"), ("email_verified", "INTEGER NOT NULL DEFAULT 0"),
              ("is_admin", "INTEGER NOT NULL DEFAULT 0"), ("is_active", "INTEGER NOT NULL DEFAULT 1"),
              ("sv", "INTEGER NOT NULL DEFAULT 0"), ("last_login", "TEXT")]


def init_db():
    c = sqlite3.connect(DB_PATH)
    c.execute("PRAGMA journal_mode=WAL")
    c.executescript(SCHEMA)
    have = {r[1] for r in c.execute("PRAGMA table_info(users)")}
    for name, ddl in MIGRATIONS:                      # upgrades a database from the earlier version
        if name not in have:
            c.execute(f"ALTER TABLE users ADD COLUMN {name} {ddl}")
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email COLLATE NOCASE) WHERE email IS NOT NULL")
    if not c.execute("SELECT 1 FROM users WHERE is_admin=1").fetchone():     # existing install: oldest user = admin
        c.execute("UPDATE users SET is_admin=1 WHERE id=(SELECT MIN(id) FROM users)")
    c.commit(); c.close()


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


init_db()


def get_setting(key, default=None):
    r = db().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return r["value"] if r else default


def signups_open():
    v = get_setting("allow_signup")
    return (os.getenv("ALLOW_SIGNUP", "1") == "1") if v is None else v == "1"


# ---------------------------------------------------------------- tokens, links, rate limits
def make_token(uid, kind, hours):
    raw = secrets.token_urlsafe(32)
    db().execute("DELETE FROM tokens WHERE user_id=? AND kind=?", (uid, kind))
    db().execute("INSERT INTO tokens(user_id, kind, token_hash, expires_at) VALUES(?,?,?,?)",
                 (uid, kind, hashlib.sha256(raw.encode()).hexdigest(), time.time() + hours * 3600))
    db().commit()
    return raw


def take_token(raw, kind):
    """Returns the user id for a valid, unexpired token and deletes it (single use)."""
    h = hashlib.sha256((raw or "").encode()).hexdigest()
    r = db().execute("SELECT id, user_id, expires_at FROM tokens WHERE token_hash=? AND kind=?", (h, kind)).fetchone()
    if not r:
        return None
    db().execute("DELETE FROM tokens WHERE id=?", (r["id"],)); db().commit()
    return r["user_id"] if r["expires_at"] > time.time() else None


def base_url():
    return (os.getenv("APP_URL") or request.host_url).rstrip("/")


_hits = {}


def is_limited(bucket, limit, window=300):
    if len(_hits) > 5000:
        _hits.clear()
    n, t = _hits.get((bucket, request.remote_addr), (0, time.time()))
    return time.time() - t <= window and n >= limit


def count_hit(bucket, window=300):
    key = (bucket, request.remote_addr)
    n, t = _hits.get(key, (0, time.time()))
    _hits[key] = (1, time.time()) if time.time() - t > window else (n + 1, t)


# ---------------------------------------------------------------- auth helpers
def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    u = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return u if u and u["is_active"] and session.get("sv") == u["sv"] else None


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        u = current_user()
        if not u:
            return jsonify(error="Please sign in."), 401
        g.user = u
        return fn(*a, **kw)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*a, **kw):
        if not g.user["is_admin"]:
            return jsonify(error="Admins only."), 403
        return fn(*a, **kw)
    return wrapper


def start_session(u):
    session.clear(); session.permanent = True
    session["uid"], session["sv"] = u["id"], u["sv"]
    db().execute("UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?", (u["id"],)); db().commit()


def user_json(u):
    return {"username": u["username"], "email": u["email"], "pending_email": u["pending_email"],
            "is_admin": bool(u["is_admin"]), "source": u["pref_source"], "target": u["pref_target"]}


def send_verify(uid, to):
    link = f"{base_url()}/verify?token={make_token(uid, 'verify', 24)}"
    mailer.send(to, f"Confirm your email for {APP_NAME}",
                f"Confirm your email address for {APP_NAME} by opening this link (valid for 24 hours):\n\n{link}\n\n"
                "If you didn't ask for this, you can ignore this email.")


def send_reset(uid, to):
    link = f"{base_url()}/?reset={make_token(uid, 'reset', 1)}"
    mailer.send(to, f"Reset your {APP_NAME} password",
                f"Choose a new password for {APP_NAME} by opening this link (valid for 1 hour):\n\n{link}\n\n"
                "If you didn't ask for this, you can ignore this email. Your password won't change.")


@app.before_request
def csrf_guard():
    # Browsers can't add custom headers on cross-site form posts, so this blocks CSRF.
    if request.path.startswith("/api/") and request.method in ("POST", "PUT", "DELETE"):
        if request.headers.get("X-Requested-With") != "fetch":
            return jsonify(error="Bad request."), 403


@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "no-referrer"
    r.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
                                            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                                            "frame-ancestors 'none'; base-uri 'none'")
    if request.path.startswith("/api/"):
        r.headers["Cache-Control"] = "no-store"
    return r


# ---------------------------------------------------------------- account routes
@app.get("/api/me")
def me():
    u = current_user()
    return jsonify(user=user_json(u) if u else None)


@app.post("/api/register")
def register():
    d = request.get_json(silent=True) or {}
    name, email, pw = (d.get("username") or "").strip(), (d.get("email") or "").strip().lower(), d.get("password") or ""
    first = not db().execute("SELECT 1 FROM users LIMIT 1").fetchone()
    if not first and not signups_open():
        return jsonify(error="Sign-ups are turned off."), 403
    if is_limited("register", 10, 3600):
        return jsonify(error="Too many sign-ups from this address. Try again later."), 429
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", name):
        return jsonify(error="Username must be 3-32 letters, numbers, dot, dash or underscore."), 400
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        return jsonify(error="Enter a valid email address."), 400
    if len(pw) < 8:
        return jsonify(error="Password must be at least 8 characters."), 400
    count_hit("register", 3600)
    try:  # the very first account becomes the admin and skips email confirmation so you can't lock yourself out
        cur = db().execute("INSERT INTO users(username, email, password_hash, email_verified, is_admin) VALUES(?,?,?,?,?)",
                           (name, email, generate_password_hash(pw), int(first), int(first)))
        db().commit()
    except sqlite3.IntegrityError:
        taken = db().execute("SELECT 1 FROM users WHERE username=?", (name,)).fetchone()
        return jsonify(error="That username is taken." if taken else "That email is already registered."), 409
    if first:
        start_session(db().execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone())
        return jsonify(user=user_json(current_user())), 201
    send_verify(cur.lastrowid, email)
    return jsonify(pending=True, message="Check your email for a link to confirm your account, then sign in."), 201


@app.get("/verify")
def verify():
    uid = take_token(request.args.get("token", ""), "verify")
    u = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone() if uid else None
    if u:
        try:
            db().execute("UPDATE users SET email=?, pending_email=NULL, email_verified=1 WHERE id=?",
                         (u["pending_email"] or u["email"], u["id"]))
            db().commit()
            return redirect("/?verified=1")
        except sqlite3.IntegrityError:
            pass
    return redirect("/?verify_failed=1")


@app.post("/api/resend")
def resend():
    if is_limited("mail", 5):
        return jsonify(error="Too many requests. Try again in a few minutes."), 429
    count_hit("mail")
    email = ((request.get_json(silent=True) or {}).get("email") or "").strip().lower()
    u = db().execute("SELECT * FROM users WHERE (email=? AND email_verified=0) OR pending_email=?", (email, email)).fetchone()
    if u and u["is_active"]:
        send_verify(u["id"], email)
    return jsonify(message="If that address is waiting for confirmation, a new link is on its way.")


@app.post("/api/login")
def login():
    if is_limited("login", 10):
        return jsonify(error="Too many attempts. Try again in a few minutes."), 429
    d = request.get_json(silent=True) or {}
    ident = (d.get("username") or "").strip()
    u = db().execute("SELECT * FROM users WHERE username=? OR email=?", (ident, ident.lower())).fetchone()
    if not u or not check_password_hash(u["password_hash"], d.get("password") or ""):
        count_hit("login")
        return jsonify(error="Wrong username or password."), 401
    if not u["is_active"]:
        return jsonify(error="This account is disabled. Ask the admin."), 403
    if u["email"] and not u["email_verified"]:
        return jsonify(error="Confirm your email first. Open the link we sent you.", unverified=u["email"]), 403
    start_session(u)
    return jsonify(user=user_json(current_user()))


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.post("/api/forgot")
def forgot():
    if is_limited("mail", 5):
        return jsonify(error="Too many requests. Try again in a few minutes."), 429
    count_hit("mail")
    email = ((request.get_json(silent=True) or {}).get("email") or "").strip().lower()
    u = db().execute("SELECT * FROM users WHERE email=? AND email_verified=1 AND is_active=1", (email,)).fetchone()
    if u:
        send_reset(u["id"], email)
    return jsonify(message="If that email has an account, a reset link is on its way. It expires in 1 hour.")


@app.post("/api/reset")
def reset():
    d = request.get_json(silent=True) or {}
    pw = d.get("password") or ""
    if len(pw) < 8:
        return jsonify(error="Password must be at least 8 characters."), 400
    uid = take_token(d.get("token"), "reset")
    if not uid:
        return jsonify(error="This reset link has expired or was already used. Request a new one."), 400
    db().execute("UPDATE users SET password_hash=?, sv=sv+1, email_verified=1 WHERE id=?",   # sv+1 signs out every device
                 (generate_password_hash(pw), uid))
    db().commit()
    return jsonify(message="Password updated. Sign in with your new password.")


@app.post("/api/email")
@login_required
def set_email():
    email = ((request.get_json(silent=True) or {}).get("email") or "").strip().lower()
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        return jsonify(error="Enter a valid email address."), 400
    if db().execute("SELECT 1 FROM users WHERE email=? AND id<>?", (email, g.user["id"])).fetchone():
        return jsonify(error="That email is already registered."), 409
    db().execute("UPDATE users SET pending_email=? WHERE id=?", (email, g.user["id"])); db().commit()
    send_verify(g.user["id"], email)
    return jsonify(message=f"We sent a confirmation link to {email}.")


@app.post("/api/prefs")
@login_required
def prefs():
    d = request.get_json(silent=True) or {}
    s, t = str(d.get("source", "auto"))[:8], str(d.get("target", "es"))[:8]
    db().execute("UPDATE users SET pref_source=?, pref_target=? WHERE id=?", (s, t, g.user["id"]))
    db().commit()
    return jsonify(ok=True)


@app.get("/api/history")
@login_required
def history():
    rows = db().execute("SELECT id, source, target, original, translation FROM history "
                        "WHERE user_id=? ORDER BY id DESC LIMIT 30", (g.user["id"],)).fetchall()
    return jsonify(items=[dict(r) for r in rows])


@app.delete("/api/history")
@login_required
def clear_history():
    db().execute("DELETE FROM history WHERE user_id=?", (g.user["id"],)); db().commit()
    return jsonify(ok=True)


@app.delete("/api/history/<int:hid>")
@login_required
def delete_history(hid):
    db().execute("DELETE FROM history WHERE id=? AND user_id=?", (hid, g.user["id"])); db().commit()
    return jsonify(ok=True)


# ---------------------------------------------------------------- admin routes
@app.get("/admin")
def admin_page():
    return send_from_directory("static", "admin.html")


@app.get("/api/admin/users")
@admin_required
def admin_users():
    rows = db().execute(
        "SELECT u.id, u.username, u.email, u.pending_email, u.email_verified, u.is_admin, u.is_active, "
        "u.created_at, u.last_login, (SELECT COUNT(*) FROM history h WHERE h.user_id=u.id) AS translations "
        "FROM users u ORDER BY u.id").fetchall()
    return jsonify(users=[dict(r) for r in rows], me=g.user["id"],
                   allow_signup=signups_open(), mail_enabled=mailer.configured())


@app.post("/api/admin/users/<int:uid>")
@admin_required
def admin_update(uid):
    d = request.get_json(silent=True) or {}
    if not db().execute("SELECT 1 FROM users WHERE id=?", (uid,)).fetchone():
        return jsonify(error="User not found."), 404
    if uid == g.user["id"] and (d.get("is_admin") is False or d.get("is_active") is False):
        return jsonify(error="You can't remove your own admin access or disable yourself."), 400
    if "is_admin" in d:
        db().execute("UPDATE users SET is_admin=? WHERE id=?", (int(bool(d["is_admin"])), uid))
    if "is_active" in d:
        db().execute("UPDATE users SET is_active=?, sv=sv+1 WHERE id=?", (int(bool(d["is_active"])), uid))
    if d.get("email_verified") is True:
        db().execute("UPDATE users SET email=COALESCE(pending_email, email), pending_email=NULL, email_verified=1 WHERE id=?", (uid,))
    db().commit()
    return jsonify(ok=True)


@app.post("/api/admin/users/<int:uid>/reset")
@admin_required
def admin_reset(uid):
    u = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not u:
        return jsonify(error="User not found."), 404
    if not u["email"]:
        return jsonify(error="This user has no email on file."), 400
    send_reset(uid, u["email"])
    return jsonify(message=f"Reset link sent to {u['email']}." if mailer.configured()
                   else "Email isn't configured, so the reset link was printed in the server log.")


@app.delete("/api/admin/users/<int:uid>")
@admin_required
def admin_delete(uid):
    if uid == g.user["id"]:
        return jsonify(error="You can't delete your own account."), 400
    db().execute("DELETE FROM users WHERE id=?", (uid,)); db().commit()   # history and tokens cascade
    return jsonify(ok=True)


@app.post("/api/admin/settings")
@admin_required
def admin_settings():
    d = request.get_json(silent=True) or {}
    if "allow_signup" in d:
        db().execute("INSERT INTO settings(key, value) VALUES('allow_signup', ?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value", ("1" if d["allow_signup"] else "0",))
        db().commit()
    return jsonify(ok=True, allow_signup=signups_open())


# ---------------------------------------------------------------- translation
if BACKEND == "aws":
    import boto3
    _aws = boto3.client("translate", region_name=os.getenv("AWS_REGION", "us-east-1"))
else:
    from argostranslate import translate as argos


def languages():
    if BACKEND == "aws":
        return [{"code": c, "name": NAMES.get(c, c)} for c in LANGS]
    return sorted(({"code": l.code, "name": l.name} for l in argos.get_installed_languages()),
                  key=lambda l: l["name"])


def do_translate(text, src, tgt):
    if BACKEND == "aws":
        r = _aws.translate_text(Text=text, SourceLanguageCode=src, TargetLanguageCode=tgt)
        return r["TranslatedText"], r["SourceLanguageCode"]
    if src == "auto":
        from langdetect import detect
        src = detect(text).split("-")[0]
    installed = {l["code"] for l in languages()}
    if src not in installed or tgt not in installed:
        raise ValueError(f"Language pair {src}->{tgt} is not installed")
    return argos.translate(text, src, tgt), src


@app.get("/")
def index():
    return send_from_directory("static", "index.html")


@app.get("/manifest.webmanifest")
def manifest():
    return send_from_directory("static", "manifest.webmanifest", mimetype="application/manifest+json")


@app.get("/sw.js")
def service_worker():
    r = send_from_directory("static", "sw.js", mimetype="application/javascript")
    r.headers["Cache-Control"] = "no-cache"
    r.headers["Service-Worker-Allowed"] = "/"
    return r


@app.get("/api/config")
def config():
    return jsonify(backend=BACKEND, languages=languages(), max_chars=MAX_CHARS, signup_open=signups_open(),
                   first_run=not db().execute("SELECT 1 FROM users LIMIT 1").fetchone())


@app.post("/api/translate")
@login_required
def translate():
    d = request.get_json(silent=True) or {}
    text, src, tgt = (d.get("text") or "").strip(), d.get("source", "auto"), d.get("target")
    if not text or not tgt:
        return jsonify(error="Enter some text and choose a target language."), 400
    if len(text) > MAX_CHARS:
        return jsonify(error=f"Text is limited to {MAX_CHARS} characters."), 400
    try:
        out, detected = do_translate(text, src, tgt)
    except ValueError as e:
        return jsonify(error=str(e)), 400
    except Exception:
        app.logger.exception("translate failed")
        return jsonify(error="Translation failed. Check the server logs."), 500
    if d.get("save", True):
        uid = g.user["id"]
        db().execute("DELETE FROM history WHERE user_id=? AND original=? AND target=?", (uid, text, tgt))
        db().execute("INSERT INTO history(user_id, source, target, original, translation) VALUES(?,?,?,?,?)",
                     (uid, detected, tgt, text, out))
        db().execute("DELETE FROM history WHERE user_id=? AND id NOT IN "
                     "(SELECT id FROM history WHERE user_id=? ORDER BY id DESC LIMIT ?)",
                     (uid, uid, HISTORY_LIMIT))
        db().commit()
    return jsonify(translation=out, detected=detected)


# ---------------------------------------------------------------- audio -> text
_whisper, _wlock = None, threading.Lock()


def get_whisper():
    global _whisper
    if _whisper is None:
        from faster_whisper import WhisperModel
        _whisper = WhisperModel(WHISPER_MODEL, device="cpu", compute_type="int8",
                                download_root=os.path.join(DATA, "whisper"))
    return _whisper


@app.post("/api/transcribe")
@login_required
def transcribe():
    f = request.files.get("audio")
    if not f:
        return jsonify(error="Choose an audio file to upload."), 400
    lang = request.form.get("language") or None
    suffix = os.path.splitext(f.filename or "")[1][:8] or ".audio"
    with tempfile.NamedTemporaryFile(suffix=suffix) as tmp:
        f.save(tmp.name)
        try:
            with _wlock:  # one at a time keeps the Pi from running out of RAM
                segments, info = get_whisper().transcribe(tmp.name, language=lang, vad_filter=True)
                text = " ".join(s.text.strip() for s in segments).strip()
        except Exception:
            app.logger.exception("transcribe failed")
            return jsonify(error="Couldn't read that audio file. Try mp3, wav, m4a, ogg or webm."), 400
    if not text:
        return jsonify(error="No speech found in that file."), 400
    return jsonify(text=text, language=info.language)


@app.errorhandler(413)
def too_big(_):
    return jsonify(error="Audio file is too large."), 413


@app.get("/healthz")
def health():
    return "ok"
