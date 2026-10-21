"""
KyroMail - messagerie scolaire pour collège.

Backend Flask + SQLite.

Points de sécurité mis en œuvre dans ce fichier :
  * mots de passe hachés (werkzeug, jamais en clair) ;
  * requêtes SQL 100 % paramétrées ;
  * jeton CSRF obligatoire sur chaque requête POST ;
  * validation systématique des données saisies ;
  * contrôle d'accès par rôle (décorateurs login_required / admin_required) ;
  * secret de session lu dans une variable d'environnement ou un fichier
    local ignoré par git (jamais écrit dans le code public) ;
  * régénération de la session à la connexion, cookies HttpOnly / SameSite.

Les adresses générées automatiquement utilisent un domaine INTERNE de
démonstration (kyromail.local par défaut) : ce ne sont pas de véritables
adresses e-mail Internet. Voir README.md pour brancher un domaine réel.
"""

from __future__ import annotations

import os
import re
import secrets
import sqlite3
import time
import unicodedata
import urllib.parse
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# Référentiel des rôles du collège
# ---------------------------------------------------------------------------

ROLES = {
    "admin": "Administrateur",
    "direction": "Direction",
    "professeur": "Professeur",
    "surveillant": "Surveillant",
    "eleve": "Élève",
}
ROLE_KEYS = list(ROLES.keys())

# Domaine INTERNE de démonstration - configurable via variable d'environnement.
INTERNAL_DOMAIN = os.environ.get("KYROMAIL_DOMAIN", "kyromail.local").strip().lower()

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
PASSWORD_MIN_LENGTH = 8
SUBJECT_MAX = 200
BODY_MAX = 20000
NAME_MAX = 80
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCK_SECONDS = 300

MONTHS_FR = [
    "janv.", "févr.", "mars", "avr.", "mai", "juin",
    "juil.", "août", "sept.", "oct.", "nov.", "déc.",
]

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
DEFAULT_DB = os.path.join(INSTANCE_DIR, "kyromail.sqlite3")
DB_PATH = os.environ.get("KYROMAIL_DATABASE", DEFAULT_DB)

# Base de données : SQLite par défaut (local), PostgreSQL si une URL est fournie
# (cas Render / Railway : KYROMAIL_DATABASE_URL=postgresql://…).
DB_URL = os.environ.get("KYROMAIL_DATABASE_URL", "").strip()
USE_POSTGRES = bool(DB_URL)

try:
    import psycopg
    from psycopg.rows import dict_row

    PSYCOPG_AVAILABLE = True
except ImportError:  # psycopg absent : on reste utilisable en SQLite
    psycopg = None
    dict_row = None
    PSYCOPG_AVAILABLE = False

DB_ERRORS: tuple = (sqlite3.Error,)
if PSYCOPG_AVAILABLE:
    DB_ERRORS = (sqlite3.Error, psycopg.Error)

# Stocke les tentatives de connexion échouées (protection simple anti force brute
# en développement mono-processus ; en production utiliser un limiteur dédié).
_LOGIN_FAILURES: dict[str, tuple[int, float]] = {}


def _load_secret_key() -> bytes:
    """Charge la clé secrète sans jamais l'écrire dans le code source."""
    env_key = os.environ.get("KYROMAIL_SECRET_KEY")
    if env_key:
        return env_key.encode("utf-8")

    os.makedirs(INSTANCE_DIR, exist_ok=True)
    key_file = os.path.join(INSTANCE_DIR, "secret_key")
    if os.path.exists(key_file):
        with open(key_file, "rb") as handle:
            saved = handle.read().strip()
            if saved:
                return saved

    key = secrets.token_hex(32).encode("utf-8")
    try:
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        with open(key_file, "rb") as handle:
            saved = handle.read().strip()
            return saved if saved else key
    with os.fdopen(fd, "wb") as handle:
        handle.write(key)
    return key


app = Flask(__name__)
app.config.update(
    SECRET_KEY=_load_secret_key(),
    DATABASE=DB_PATH,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("KYROMAIL_HTTPS", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,  # limite à 2 Mo par requête
)

# ---------------------------------------------------------------------------
# Schéma de la base de données
# ---------------------------------------------------------------------------

SCHEMA_SQLITE = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name     TEXT    NOT NULL,
    email         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL CHECK (role IN
                    ('admin','direction','professeur','surveillant','eleve')),
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL,
    last_login    TEXT
);

CREATE TABLE IF NOT EXISTS messages (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id            INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subject              TEXT    NOT NULL,
    body                 TEXT    NOT NULL,
    sent_at              TEXT    NOT NULL,
    read_at              TEXT,
    deleted_by_sender    INTEGER NOT NULL DEFAULT 0,
    deleted_by_recipient INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_messages_recipient
    ON messages (recipient_id, deleted_by_recipient, sent_at);
CREATE INDEX IF NOT EXISTS idx_messages_sender
    ON messages (sender_id, deleted_by_sender, sent_at);

CREATE TABLE IF NOT EXISTS access_rules (
    from_role TEXT    NOT NULL,
    to_role   TEXT    NOT NULL,
    allowed   INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (from_role, to_role)
);

CREATE TABLE IF NOT EXISTS admin_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action     TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
"""

# Équivalent PostgreSQL (Render / Railway) : mêmes tables, mêmes colonnes.
SCHEMA_POSTGRES = """
CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    full_name     TEXT    NOT NULL,
    email         TEXT    NOT NULL,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL CHECK (role IN
                    ('admin','direction','professeur','surveillant','eleve')),
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL,
    last_login    TEXT,
    CONSTRAINT users_email_key UNIQUE (email)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower ON users (LOWER(email));

CREATE TABLE IF NOT EXISTS messages (
    id                   SERIAL PRIMARY KEY,
    sender_id            INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subject              TEXT    NOT NULL,
    body                 TEXT    NOT NULL,
    sent_at              TEXT    NOT NULL,
    read_at              TEXT,
    deleted_by_sender    INTEGER NOT NULL DEFAULT 0,
    deleted_by_recipient INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_messages_recipient
    ON messages (recipient_id, deleted_by_recipient, sent_at);
CREATE INDEX IF NOT EXISTS idx_messages_sender
    ON messages (sender_id, deleted_by_sender, sent_at);

CREATE TABLE IF NOT EXISTS access_rules (
    from_role TEXT    NOT NULL,
    to_role   TEXT    NOT NULL,
    allowed   INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (from_role, to_role)
);

CREATE TABLE IF NOT EXISTS admin_log (
    id         SERIAL PRIMARY KEY,
    admin_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action     TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
"""

# ---------------------------------------------------------------------------
# Accès à la base de données (requêtes paramétrées uniquement)
# ---------------------------------------------------------------------------


def _adapt(sql: str) -> str:
    """SQLite utilise « ? » ; PostgreSQL utilise « %s » (SQL identique sinon)."""
    return sql.replace("?", "%s") if USE_POSTGRES else sql


def db_label() -> str:
    """Affiche la base utilisée sans jamais exposer le mot de passe SQL."""
    if USE_POSTGRES:
        try:
            host = urllib.parse.urlsplit(DB_URL).hostname or "PostgreSQL"
        except ValueError:
            host = "PostgreSQL"
        return f"PostgreSQL ({host})"
    return app.config["DATABASE"]


def _pg_connect(**kwargs):
    """Connexion PostgreSQL commune (compatible direct ou pooler Supabase).

    `prepare_threshold=0` évite les requêtes préparées, non compatibles avec
    les poolers en mode transaction (PgBouncer). `connect_timeout` évite de
    bloquer le démarrage si la base est injoignable.
    """
    options = {
        "autocommit": True,
        "application_name": "kyromail",
        "prepare_threshold": 0,
        "connect_timeout": 15,
    }
    options.update(kwargs)
    return psycopg.connect(DB_URL, **options)


def get_db():
    if "db" not in g:
        if USE_POSTGRES:
            if not PSYCOPG_AVAILABLE:
                raise RuntimeError(
                    "KYROMAIL_DATABASE_URL est défini mais psycopg est absent "
                    '(: pip install "psycopg[binary]").'
                )
            g.db = _pg_connect(row_factory=dict_row)
        else:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query(sql: str, args: tuple = (), one: bool = False):
    cur = get_db().execute(_adapt(sql), args)
    rows = cur.fetchall()
    cur.close()
    if one:
        return rows[0] if rows else None
    return rows


def execute(sql: str, args: tuple = (), returning_id: bool = False):
    db = get_db()
    if USE_POSTGRES and returning_id:
        sql = sql.rstrip().rstrip(";") + " RETURNING id"
    cur = db.execute(_adapt(sql), args)
    db.commit()
    row_id = None
    if USE_POSTGRES:
        if cur.description is not None:
            first = cur.fetchone()
            if first is not None and "id" in first:
                row_id = first["id"]
    else:
        row_id = cur.lastrowid
    cur.close()
    return row_id


def db_exists() -> bool:
    return tables_ready()


def init_db(force: bool = False) -> None:
    """Crée la base (et les règles d'accès par défaut) de façon idempotente."""
    if USE_POSTGRES:
        if not PSYCOPG_AVAILABLE:
            raise RuntimeError('psycopg absent : pip install "psycopg[binary]".')
        if force:
            with _pg_connect() as conn:
                conn.execute(
                    "DROP TABLE IF EXISTS admin_log, access_rules, messages, users CASCADE"
                )
        with _pg_connect() as conn:
            for statement in SCHEMA_POSTGRES.split(";"):
                statement = statement.strip()
                if statement:
                    conn.execute(statement)
            for src in ROLE_KEYS:
                for dst in ROLE_KEYS:
                    conn.execute(
                        "INSERT INTO access_rules (from_role, to_role, allowed) "
                        "VALUES (%s, %s, 1) ON CONFLICT DO NOTHING",
                        (src, dst),
                    )
        return

    path = app.config["DATABASE"]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if force and os.path.exists(path):
        os.remove(path)

    db = sqlite3.connect(path)
    try:
        db.executescript(SCHEMA_SQLITE)
        for src in ROLE_KEYS:
            for dst in ROLE_KEYS:
                db.execute(
                    "INSERT OR IGNORE INTO access_rules (from_role, to_role, allowed) "
                    "VALUES (?, ?, 1)",
                    (src, dst),
                )
        db.commit()
    finally:
        db.close()


def tables_ready() -> bool:
    """Vérifie la présence de la table users (sans dépendre du contexte Flask)."""
    if USE_POSTGRES:
        if not PSYCOPG_AVAILABLE:
            return False
        try:
            with _pg_connect() as conn:
                row = conn.execute(
                    "SELECT 1 FROM information_schema.tables "
                    "WHERE table_schema = current_schema() AND table_name = 'users'"
                ).fetchone()
        except psycopg.Error:
            return False
        return row is not None

    if not os.path.exists(app.config["DATABASE"]):
        return False
    try:
        probe = sqlite3.connect(app.config["DATABASE"])
        try:
            row = probe.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'users'"
            ).fetchone()
        finally:
            probe.close()
    except sqlite3.Error:
        return False
    return row is not None


# ---------------------------------------------------------------------------
# Utilitaires de validation et de normalisation
# ---------------------------------------------------------------------------


def now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_email(value: str) -> str:
    return (value or "").strip().lower()


def validate_name(name: str) -> list[str]:
    errors = []
    name = (name or "").strip()
    if len(name) < 2:
        errors.append("Le nom complet doit contenir au moins 2 caractères.")
    elif len(name) > NAME_MAX:
        errors.append(f"Le nom complet ne peut pas dépasser {NAME_MAX} caractères.")
    return errors


def validate_email_format(email: str) -> list[str]:
    errors = []
    if not email:
        errors.append("L'adresse mail est obligatoire.")
    elif not EMAIL_RE.match(email):
        errors.append("L'adresse mail saisie n'est pas valide.")
    elif len(email) > 120:
        errors.append("L'adresse mail est trop longue.")
    return errors


def validate_password(password: str) -> list[str]:
    errors = []
    if password is None or password == "":
        errors.append("Le mot de passe est obligatoire.")
        return errors
    if len(password) < PASSWORD_MIN_LENGTH:
        errors.append(
            f"Le mot de passe doit contenir au moins {PASSWORD_MIN_LENGTH} caractères."
        )
    if not re.search(r"[A-Za-z]", password):
        errors.append("Le mot de passe doit contenir au moins une lettre.")
    if not re.search(r"\d", password):
        errors.append("Le mot de passe doit contenir au moins un chiffre.")
    return errors


def validate_role(role: str) -> list[str]:
    if role not in ROLES:
        return ["Le rôle sélectionné n'existe pas."]
    return []


def form_bool(name: str) -> int:
    """Interprète un champ de formulaire comme un booléen (case à cocher / hidden '0')."""
    value = request.form.get(name)
    if value in (None, "", "0", "false", "off", "no"):
        return 0
    return 1


def email_exists(email: str, exclude_id: int | None = None) -> bool:
    if exclude_id is None:
        row = query("SELECT 1 FROM users WHERE email = ?", (email,), one=True)
    else:
        row = query(
            "SELECT 1 FROM users WHERE email = ? AND id <> ?",
            (email, exclude_id),
            one=True,
        )
    return row is not None


def slugify(value: str) -> str:
    ascii_value = (
        unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("utf-8")
    )
    slug = re.sub(r"[^a-z0-9]+", ".", ascii_value.lower()).strip(".")
    return slug or "utilisateur"


def auto_email(full_name: str) -> str:
    """Génère une adresse INTERNE unique (domaine de démonstration)."""
    base = slugify(full_name)
    candidate = f"{base}@{INTERNAL_DOMAIN}"
    counter = 1
    while email_exists(candidate):
        counter += 1
        candidate = f"{base}{counter}@{INTERNAL_DOMAIN}"
    return candidate


def create_user(full_name: str, email: str, password: str, role: str,
                active: bool = True) -> int:
    """Crée un compte. Lève ValueError avec un message en français si invalide."""
    full_name = (full_name or "").strip()
    email = normalize_email(email)
    errors = validate_name(full_name) + validate_role(role) + validate_password(password)
    if not email:
        email = auto_email(full_name)
    else:
        errors += validate_email_format(email)
    if not errors and email_exists(email):
        errors.append("Un compte utilise déjà cette adresse mail.")
    if errors:
        raise ValueError(" ".join(errors))

    return execute(
        "INSERT INTO users (full_name, email, password_hash, role, active, "
        "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            full_name,
            email,
            generate_password_hash(password),
            role,
            1 if active else 0,
            now_iso(),
            now_iso(),
        ),
        returning_id=True,
    )


def find_user_by_email(email: str):
    return query("SELECT * FROM users WHERE email = ?", (normalize_email(email),), one=True)


def get_user(user_id: int):
    return query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)


def count_active_admins(exclude_id: int | None = None) -> int:
    if exclude_id is None:
        row = query(
            "SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND active = 1",
            one=True,
        )
    else:
        row = query(
            "SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND active = 1 "
            "AND id <> ?",
            (exclude_id,),
            one=True,
        )
    return int(row["c"])


# ---------------------------------------------------------------------------
# Journal des actions administratives
# ---------------------------------------------------------------------------


def log_action(action: str, detail: str = "", admin_id: int | None = None) -> None:
    if admin_id is None:
        user = getattr(g, "user", None)
        admin_id = user["id"] if user else None
    execute(
        "INSERT INTO admin_log (admin_id, action, detail, created_at) VALUES (?, ?, ?, ?)",
        (admin_id, action, detail, now_iso()),
    )


# ---------------------------------------------------------------------------
# Règles d'accès entre rôles
# ---------------------------------------------------------------------------


def can_send(sender_role: str, recipient_role: str) -> bool:
    """Vérifie la matrice d'accès enregistrée (administrateur toujours autorisé)."""
    if sender_role == "admin" or recipient_role == "admin":
        return True
    row = query(
        "SELECT allowed FROM access_rules WHERE from_role = ? AND to_role = ?",
        (sender_role, recipient_role),
        one=True,
    )
    return bool(row and row["allowed"])


def load_rules() -> dict:
    rules = {(src, dst): True for src in ROLE_KEYS for dst in ROLE_KEYS}
    for row in query("SELECT from_role, to_role, allowed FROM access_rules"):
        rules[(row["from_role"], row["to_role"])] = bool(row["allowed"])
    return rules


def recipient_options(sender) -> list[tuple[str, list]]:
    """Comptes accessibles à l'expéditeur, groupés par rôle."""
    rows = query(
        "SELECT id, full_name, email, role FROM users "
        "WHERE active = 1 AND id <> ? ORDER BY role, full_name",
        (sender["id"],),
    )
    groups: dict[str, list] = {key: [] for key in ROLE_KEYS}
    for row in rows:
        if can_send(sender["role"], row["role"]):
            groups[row["role"]].append(row)
    return [(ROLES[key], groups[key]) for key in ROLE_KEYS if groups[key]]


def unread_count(user_id: int) -> int:
    row = query(
        "SELECT COUNT(*) AS c FROM messages "
        "WHERE recipient_id = ? AND read_at IS NULL AND deleted_by_recipient = 0",
        (user_id,),
        one=True,
    )
    return int(row["c"]) if row else 0


# ---------------------------------------------------------------------------
# Sécurité : sessions, CSRF, protections d'accès
# ---------------------------------------------------------------------------

_DUMMY_HASH = generate_password_hash("kyromail-password-placeholder")


def generate_csrf() -> str:
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


@app.before_request
def load_user() -> None:
    g.user = None
    user_id = session.get("user_id")
    if not user_id or not tables_ready():
        return
    try:
        user = get_user(int(user_id))
    except (ValueError, TypeError) + DB_ERRORS:
        user = None
    if user is None or not user["active"]:
        session.clear()
        return
    g.user = user


@app.before_request
def csrf_protect() -> None:
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    sent = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token") or ""
    expected = session.get("_csrf_token") or ""
    if not expected or not sent or not secrets.compare_digest(expected, sent):
        abort(400, description="Jeton de sécurité (CSRF) invalide. Rechargez la page.")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            if request.method == "POST":
                abort(403)
            flash("Veuillez vous connecter pour accéder à cette page.", "info")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            if request.method == "POST":
                abort(403)
            flash("Veuillez vous connecter pour accéder à cette page.", "info")
            return redirect(url_for("login", next=request.path))
        if g.user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def safe_next(target: str | None) -> str:
    """Redirection post-connexion : uniquement un chemin local (anti open redirect)."""
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return url_for("inbox")


def _client_key() -> str:
    return request.remote_addr or "inconnu"


def _login_blocked(key: str) -> bool:
    entry = _LOGIN_FAILURES.get(key)
    if not entry:
        return False
    failures, last = entry
    if time.time() - last > LOGIN_LOCK_SECONDS:
        _LOGIN_FAILURES.pop(key, None)
        return False
    return failures >= LOGIN_MAX_ATTEMPTS


def _login_failure(key: str) -> None:
    failures, _ = _LOGIN_FAILURES.get(key, (0, 0.0))
    _LOGIN_FAILURES[key] = (failures + 1, time.time())


def _login_success(key: str) -> None:
    _LOGIN_FAILURES.pop(key, None)


# ---------------------------------------------------------------------------
# Filtres et contexte partagé avec les gabarits
# ---------------------------------------------------------------------------


@app.template_filter("dt")
def format_dt(value) -> str:
    if not value:
        return "-"
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError):
            return str(value)
    return (
        f"{parsed.day} {MONTHS_FR[parsed.month - 1]} {parsed.year} "
        f"{parsed.hour:02d}:{parsed.minute:02d}"
    )


@app.template_filter("snippet")
def snippet(value, length: int = 140) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= length:
        return text
    return text[: length - 1] + "…"


@app.context_processor
def inject_globals():
    user = getattr(g, "user", None)
    try:
        badge = unread_count(user["id"]) if user else 0
    except DB_ERRORS:
        badge = 0
    return {
        "csrf_token": generate_csrf,
        "roles": ROLES,
        "current_user": user,
        "unread_total": badge,
        "internal_domain": INTERNAL_DOMAIN,
        "app_year": datetime.now().year,
    }


# ---------------------------------------------------------------------------
# Pages publiques et connexion
# ---------------------------------------------------------------------------


@app.route("/")
def landing():
    if g.user is not None:
        return redirect(url_for("inbox"))
    return render_template("landing.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user is not None:
        return redirect(url_for("inbox"))

    if request.method == "POST":
        email = normalize_email(request.form.get("email", ""))
        password = request.form.get("password", "") or ""
        key = _client_key()

        if _login_blocked(key):
            flash(
                "Trop de tentatives échouées. Patientez quelques minutes avant de "
                "réessayer.",
                "error",
            )
            return render_template("login.html"), 429

        if not email or not password:
            flash("Renseignez votre adresse mail et votre mot de passe.", "error")
            return render_template("login.html"), 400

        user = find_user_by_email(email)
        # Vérification toujours effectuée : temps de réponse égal, compte inconnu ou non.
        if user is None:
            check_password_hash(_DUMMY_HASH, password)
            _login_failure(key)
            flash("Identifiants incorrects.", "error")
            return render_template("login.html"), 401

        if not check_password_hash(user["password_hash"], password):
            _login_failure(key)
            flash("Identifiants incorrects.", "error")
            return render_template("login.html"), 401

        if not user["active"]:
            _login_failure(key)
            flash(
                "Ce compte est désactivé. Contactez l'administration du collège.",
                "error",
            )
            return render_template("login.html"), 403

        _login_success(key)
        session.clear()  # régénère l'identifiant de session (anti fixation)
        session["user_id"] = user["id"]
        session.permanent = True
        execute("UPDATE users SET last_login = ? WHERE id = ?", (now_iso(), user["id"]))
        flash(f"Bienvenue, {user['full_name']}.", "success")
        return redirect(safe_next(request.args.get("next")))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Vous êtes déconnecté.", "info")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Messagerie
# ---------------------------------------------------------------------------


def _search_filter(value: str) -> str:
    """Échappe les caractères spéciaux LIKE (%, _, \\) et passe en minuscules.

    Les comparaisons utilisent ensuite LOWER(colonne) LIKE ?, comportement
    identique sur SQLite (insensible à la casse) et PostgreSQL.
    """
    escaped = (
        value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    )
    return escaped.lower()


@app.route("/inbox")
@login_required
def inbox():
    q = (request.args.get("q") or "").strip()
    selected = request.args.get("filter", "all")
    if selected not in ("all", "unread", "read"):
        selected = "all"

    sql = (
        "SELECT m.*, u.full_name AS sender_name, u.email AS sender_email, "
        "u.role AS sender_role FROM messages m "
        "JOIN users u ON u.id = m.sender_id "
        "WHERE m.recipient_id = ? AND m.deleted_by_recipient = 0"
    )
    params: list = [g.user["id"]]

    if selected == "unread":
        sql += " AND m.read_at IS NULL"
    elif selected == "read":
        sql += " AND m.read_at IS NOT NULL"

    if q:
        like = f"%{_search_filter(q)}%"
        sql += (
            " AND (LOWER(m.subject) LIKE ? ESCAPE '\\' "
            "OR LOWER(m.body) LIKE ? ESCAPE '\\' "
            "OR LOWER(u.full_name) LIKE ? ESCAPE '\\')"
        )
        params.extend([like, like, like])

    sql += " ORDER BY m.sent_at DESC"
    items = query(sql, tuple(params))

    try:
        unread_inbox = unread_count(g.user["id"])
    except DB_ERRORS:
        unread_inbox = 0

    return render_template(
        "inbox.html",
        items=items,
        q=q,
        filter=selected,
        unread_inbox=unread_inbox,
    )


@app.route("/sent")
@login_required
def sent():
    q = (request.args.get("q") or "").strip()
    sql = (
        "SELECT m.*, u.full_name AS recipient_name, u.email AS recipient_email, "
        "u.role AS recipient_role FROM messages m "
        "JOIN users u ON u.id = m.recipient_id "
        "WHERE m.sender_id = ? AND m.deleted_by_sender = 0"
    )
    params: list = [g.user["id"]]

    if q:
        like = f"%{_search_filter(q)}%"
        sql += (
            " AND (LOWER(m.subject) LIKE ? ESCAPE '\\' "
            "OR LOWER(m.body) LIKE ? ESCAPE '\\' "
            "OR LOWER(u.full_name) LIKE ? ESCAPE '\\')"
        )
        params.extend([like, like, like])

    sql += " ORDER BY m.sent_at DESC"
    items = query(sql, tuple(params))
    return render_template("sent.html", items=items, q=q)


@app.route("/compose", methods=["GET", "POST"])
@login_required
def compose():
    options = recipient_options(g.user)

    if request.method == "POST":
        raw_recipient = (request.form.get("recipient_id") or "").strip()
        subject = (request.form.get("subject") or "").strip()
        body = (request.form.get("body") or "").strip()
        errors: list[str] = []
        recipient = None

        try:
            recipient_id = int(raw_recipient)
        except (TypeError, ValueError):
            recipient_id = None

        if recipient_id is None:
            errors.append("Choisissez un destinataire dans la liste.")
        else:
            recipient = query("SELECT * FROM users WHERE id = ?", (recipient_id,), one=True)
            if recipient is None:
                errors.append(
                    "Ce destinataire n'existe pas. Vérifiez la liste des comptes."
                )
            elif not recipient["active"]:
                errors.append("Ce destinataire est désactivé.")
            elif not can_send(g.user["role"], recipient["role"]):
                errors.append(
                    "Les règles d'accès du collège ne vous autorisent pas à écrire "
                    "à ce destinataire."
                )

        if not subject:
            errors.append("L'objet du message est obligatoire.")
        elif len(subject) > SUBJECT_MAX:
            errors.append(f"L'objet ne peut pas dépasser {SUBJECT_MAX} caractères.")

        if not body:
            errors.append("Le contenu du message est obligatoire.")
        elif len(body) > BODY_MAX:
            errors.append(f"Le message ne peut pas dépasser {BODY_MAX} caractères.")

        values = {
            "recipient_id": raw_recipient,
            "subject": subject,
            "body": body,
        }

        if errors:
            for message in errors:
                flash(message, "error")
            return render_template(
                "compose.html", recipients=options, values=values
            ), 400

        execute(
            "INSERT INTO messages (sender_id, recipient_id, subject, body, sent_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (g.user["id"], recipient["id"], subject, body, now_iso()),
        )
        flash(f"Message envoyé à {recipient['full_name']}.", "success")
        return redirect(url_for("sent"))

    values = {
        "recipient_id": request.args.get("to", ""),
        "subject": request.args.get("subject", ""),
        "body": "",
    }
    return render_template("compose.html", recipients=options, values=values)


@app.route("/message/<int:message_id>")
@login_required
def view_message(message_id: int):
    row = query(
        "SELECT m.*, s.full_name AS sender_name, s.email AS sender_email, "
        "s.role AS sender_role, r.full_name AS recipient_name, "
        "r.email AS recipient_email, r.role AS recipient_role "
        "FROM messages m "
        "JOIN users s ON s.id = m.sender_id "
        "JOIN users r ON r.id = m.recipient_id "
        "WHERE m.id = ?",
        (message_id,),
        one=True,
    )
    if row is None:
        abort(404)

    is_sender = row["sender_id"] == g.user["id"]
    is_recipient = row["recipient_id"] == g.user["id"]
    if not is_sender and not is_recipient:
        abort(403)

    message = dict(row)
    if is_recipient and message["read_at"] is None:
        read_at = now_iso()
        execute("UPDATE messages SET read_at = ? WHERE id = ?", (read_at, message_id))
        message["read_at"] = read_at

    return render_template("message.html", message=message, is_sender=is_sender)


@app.route("/message/<int:message_id>/delete", methods=["POST"])
@login_required
def delete_message(message_id: int):
    row = query(
        "SELECT id, sender_id, recipient_id, deleted_by_sender, deleted_by_recipient "
        "FROM messages WHERE id = ?",
        (message_id,),
        one=True,
    )
    if row is None:
        abort(404)

    side = request.form.get("side", "inbox")
    if side == "sent":
        if row["sender_id"] != g.user["id"]:
            abort(403)
        column = "deleted_by_sender"  # liste blanche : jamais interpolé par l'utilisateur
        back = url_for("sent")
    else:
        if row["recipient_id"] != g.user["id"]:
            abort(403)
        column = "deleted_by_recipient"
        back = url_for("inbox")

    execute(f"UPDATE messages SET {column} = 1 WHERE id = ?", (message_id,))

    refreshed = query(
        "SELECT deleted_by_sender, deleted_by_recipient FROM messages WHERE id = ?",
        (message_id,),
        one=True,
    )
    if refreshed and refreshed["deleted_by_sender"] and refreshed["deleted_by_recipient"]:
        execute("DELETE FROM messages WHERE id = ?", (message_id,))

    flash("Message supprimé.", "success")
    return redirect(back)


# ---------------------------------------------------------------------------
# Profil
# ---------------------------------------------------------------------------


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        action = request.form.get("action")

        if action == "identity":
            full_name = (request.form.get("full_name") or "").strip()
            errors = validate_name(full_name)
            if errors:
                for message in errors:
                    flash(message, "error")
                return render_template("profile.html", user=g.user), 400
            execute(
                "UPDATE users SET full_name = ?, updated_at = ? WHERE id = ?",
                (full_name, now_iso(), g.user["id"]),
            )
            flash("Profil mis à jour.", "success")
            return redirect(url_for("profile"))

        if action == "password":
            current_password = request.form.get("current_password") or ""
            new_password = request.form.get("new_password") or ""
            confirm_password = request.form.get("confirm_password") or ""

            if not check_password_hash(g.user["password_hash"], current_password):
                flash("Le mot de passe actuel est incorrect.", "error")
                return render_template("profile.html", user=g.user), 400

            errors = validate_password(new_password)
            if new_password != confirm_password:
                errors.append("La confirmation ne correspond pas au nouveau mot de passe.")
            if errors:
                for message in errors:
                    flash(message, "error")
                return render_template("profile.html", user=g.user), 400

            execute(
                "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
                (generate_password_hash(new_password), now_iso(), g.user["id"]),
            )
            flash("Mot de passe modifié.", "success")
            return redirect(url_for("profile"))

        flash("Action inconnue.", "error")
        return redirect(url_for("profile"))

    return render_template("profile.html", user=g.user)


# ---------------------------------------------------------------------------
# API légère (notifications)
# ---------------------------------------------------------------------------


@app.route("/api/unread-count")
@login_required
def api_unread_count():
    try:
        count = unread_count(g.user["id"])
    except DB_ERRORS:
        count = 0
    return jsonify({"unread": count})


# ---------------------------------------------------------------------------
# Panneau administrateur
# ---------------------------------------------------------------------------


def admin_stats() -> dict:
    def scalar(sql: str, args: tuple = ()) -> int:
        row = query(sql, args, one=True)
        if not row:
            return 0
        return int(row[0] if not USE_POSTGRES else next(iter(row.values())))

    by_role = {
        row["role"]: {"total": int(row["total"]), "active": int(row["active"] or 0)}
        for row in query(
            "SELECT role, COUNT(*) AS total, SUM(active) AS active FROM users GROUP BY role"
        )
    }

    today = datetime.now().strftime("%Y-%m-%d") + " 00:00:00"
    week = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")

    return {
        "users_total": scalar("SELECT COUNT(*) FROM users"),
        "users_active": scalar("SELECT COUNT(*) FROM users WHERE active = 1"),
        "users_disabled": scalar("SELECT COUNT(*) FROM users WHERE active = 0"),
        "messages_total": scalar("SELECT COUNT(*) FROM messages"),
        "messages_unread": scalar("SELECT COUNT(*) FROM messages WHERE read_at IS NULL"),
        "messages_today": scalar(
            "SELECT COUNT(*) FROM messages WHERE sent_at >= ?", (today,)
        ),
        "messages_week": scalar(
            "SELECT COUNT(*) FROM messages WHERE sent_at >= ?", (week,)
        ),
        "log_total": scalar("SELECT COUNT(*) FROM admin_log"),
        "by_role": [
            {
                "key": key,
                "label": ROLES[key],
                "total": by_role.get(key, {}).get("total", 0),
                "active": by_role.get(key, {}).get("active", 0),
            }
            for key in ROLE_KEYS
        ],
    }


@app.route("/admin")
@admin_required
def admin():
    tab = request.args.get("tab", "overview")
    if tab not in ("overview", "users", "rules", "log"):
        tab = "overview"

    q = (request.args.get("q") or "").strip()
    users = []
    if tab == "users":
        if q:
            like = f"%{_search_filter(q)}%"
            users = query(
                "SELECT * FROM users WHERE LOWER(full_name) LIKE ? ESCAPE '\\' "
                "OR LOWER(email) LIKE ? ESCAPE '\\' OR LOWER(role) LIKE ? ESCAPE '\\' "
                "ORDER BY active DESC, full_name",
                (like, like, like),
            )
        else:
            users = query("SELECT * FROM users ORDER BY active DESC, full_name")

    logs = []
    if tab == "log":
        logs = query(
            "SELECT l.*, u.full_name AS admin_name FROM admin_log l "
            "LEFT JOIN users u ON u.id = l.admin_id "
            "ORDER BY l.created_at DESC, l.id DESC LIMIT 200"
        )

    return render_template(
        "admin.html",
        tab=tab,
        stats=admin_stats(),
        users=users,
        q=q,
        logs=logs,
        rules=load_rules(),
    )


@app.route("/admin/users", methods=["POST"])
@admin_required
def admin_create_user():
    full_name = request.form.get("full_name", "")
    email = request.form.get("email", "")
    password = request.form.get("password", "")
    role = request.form.get("role", "")
    active = form_bool("active")

    try:
        user_id = create_user(full_name, email, password, role, bool(active))
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("admin", tab="users"))

    created = get_user(user_id)
    log_action(
        "Création de compte",
        f"{created['full_name']} <{created['email']}> - rôle {ROLES[role]}",
    )
    flash(f"Compte créé : {created['full_name']} ({created['email']}).", "success")
    return redirect(url_for("admin", tab="users"))


@app.route("/admin/users/<int:user_id>", methods=["POST"])
@admin_required
def admin_update_user(user_id: int):
    target = get_user(user_id)
    if target is None:
        abort(404)

    full_name = (request.form.get("full_name") or "").strip()
    email = normalize_email(request.form.get("email") or "")
    role = request.form.get("role") or ""
    active = form_bool("active")

    errors = validate_name(full_name) + validate_role(role)
    if not email:
        errors.append("L'adresse mail est obligatoire.")
    else:
        errors += validate_email_format(email)
    if not errors and email_exists(email, exclude_id=user_id):
        errors.append("Un autre compte utilise déjà cette adresse mail.")

    loses_admin = target["role"] == "admin" and (role != "admin" or not active)
    if loses_admin and count_active_admins(exclude_id=user_id) == 0:
        errors.append(
            "Impossible : le dernier compte administrateur actif doit être conservé."
        )
    if target["id"] == g.user["id"] and not active:
        errors.append("Vous ne pouvez pas désactiver votre propre compte.")
    if target["id"] == g.user["id"] and role != "admin":
        errors.append("Vous ne pouvez pas modifier votre propre rôle.")

    if errors:
        for message in errors:
            flash(message, "error")
        return redirect(url_for("admin", tab="users"))

    execute(
        "UPDATE users SET full_name = ?, email = ?, role = ?, active = ?, "
        "updated_at = ? WHERE id = ?",
        (full_name, email, role, active, now_iso(), user_id),
    )

    changes = []
    if target["full_name"] != full_name:
        changes.append(f"nom: {target['full_name']} -> {full_name}")
    if target["email"] != email:
        changes.append(f"mail: {target['email']} -> {email}")
    if target["role"] != role:
        changes.append(f"rôle: {ROLES.get(target['role'])} -> {ROLES[role]}")
    if bool(target["active"]) != bool(active):
        changes.append("activé" if active else "désactivé")

    log_action(
        "Modification de compte",
        f"{target['email']} - " + (", ".join(changes) if changes else "aucun changement"),
    )
    flash(f"Compte de {full_name} mis à jour.", "success")
    return redirect(url_for("admin", tab="users"))


@app.route("/admin/users/<int:user_id>/password", methods=["POST"])
@admin_required
def admin_reset_password(user_id: int):
    target = get_user(user_id)
    if target is None:
        abort(404)

    new_password = request.form.get("password") or ""
    errors = validate_password(new_password)
    if errors:
        for message in errors:
            flash(message, "error")
        return redirect(url_for("admin", tab="users"))

    execute(
        "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
        (generate_password_hash(new_password), now_iso(), user_id),
    )
    log_action("Réinitialisation de mot de passe", f"{target['email']}")
    flash(f"Mot de passe réinitialisé pour {target['full_name']}.", "success")
    return redirect(url_for("admin", tab="users"))


@app.route("/admin/rules", methods=["POST"])
@admin_required
def admin_save_rules():
    updated = 0
    for src in ROLE_KEYS:
        for dst in ROLE_KEYS:
            allowed = 1 if request.form.get(f"rule_{src}_{dst}") else 0
            execute(
                "INSERT INTO access_rules (from_role, to_role, allowed) "
                "VALUES (?, ?, ?) ON CONFLICT(from_role, to_role) "
                "DO UPDATE SET allowed = excluded.allowed",
                (src, dst, allowed),
            )
            updated += 1
    log_action("Mise à jour des règles d'accès", f"{updated} paires enregistrées")
    flash("Règles d'accès enregistrées.", "success")
    return redirect(url_for("admin", tab="rules"))


# ---------------------------------------------------------------------------
# Amorçage automatique (indispensable sur un PaaS : aucun état manuel)
# ---------------------------------------------------------------------------


def bootstrap() -> None:
    """Crée la base si elle n'existe pas et, si demandé, le premier admin.

    Variables d'environnement utilisées :
      KYROMAIL_ADMIN_EMAIL     adresse du premier administrateur
      KYROMAIL_ADMIN_PASSWORD  son mot de passe (jamais écrit dans le code)
      KYROMAIL_ADMIN_NAME      son nom (optionnel, défaut « Administrateur »)

    Rien n'est écrasé : si la base contient déjà un compte, aucune création
    n'est faite. En clair, ces variables ne servent qu'au tout premier
    démarrage (à retirer ensuite).
    """
    if not tables_ready():
        init_db()
        print(f"[KyroMail] Base de données initialisée : {db_label()}")

    email = normalize_email(os.environ.get("KYROMAIL_ADMIN_EMAIL", ""))
    password = os.environ.get("KYROMAIL_ADMIN_PASSWORD", "")
    if not email or not password:
        return

    with app.app_context():
        if query("SELECT 1 FROM users LIMIT 1", one=True) is not None:
            return  # des comptes existent déjà : on ne touche à rien
        errors = validate_password(password) + validate_email_format(email)
        if errors:
            print("[KyroMail] Administrateur initial non créé : " + " ".join(errors))
            return
        name = (os.environ.get("KYROMAIL_ADMIN_NAME", "") or "Administrateur").strip()
        user_id = create_user(name, email, password, "admin", active=True)
        log_action(
            "Création d'administrateur (amorçage)",
            f"{name} <{email}>",
            admin_id=user_id,
        )
        print(f"[KyroMail] Premier administrateur créé : {email}")


bootstrap()


# ---------------------------------------------------------------------------
# Gestion des erreurs
# ---------------------------------------------------------------------------


def _error_response(code: int, title: str, message: str):
    status = 200 if code == 0 else code
    return render_template("error.html", code=code, title=title, message=message), status


@app.errorhandler(400)
def bad_request(error):
    message = getattr(error, "description", None) or "Requête invalide."
    return _error_response(400, "Requête refusée", message)


@app.errorhandler(403)
def forbidden(error):
    return _error_response(
        403,
        "Accès refusé",
        "Vous n'avez pas les droits nécessaires pour consulter cette page.",
    )


@app.errorhandler(404)
def not_found(error):
    return _error_response(
        404,
        "Page introuvable",
        "La page demandée n'existe pas ou a été déplacée.",
    )


@app.errorhandler(413)
def too_large(error):
    return _error_response(
        413,
        "Contenu trop volumineux",
        "Le message ou la pièce jointe dépasse la taille autorisée.",
    )


@app.errorhandler(500)
def server_error(error):
    return _error_response(
        500,
        "Erreur interne",
        "Une erreur inattendue s'est produite. Réessayez dans un instant.",
    )


@app.route("/favicon.ico")
def favicon():
    return "", 204


# ---------------------------------------------------------------------------
# Point d'entrée de développement
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    debug_mode = os.environ.get("KYROMAIL_DEBUG", "0") == "1"
    print("Serveur de développement sur http://127.0.0.1:5000")
    print("En production, utilisez : waitress-serve --host=0.0.0.0 --port=5000 app:app")
    app.run(
        host=os.environ.get("KYROMAIL_HOST", "127.0.0.1"),
        port=int(os.environ.get("KYROMAIL_PORT", "5000")),
        debug=debug_mode,
    )
