import base64
import csv
import hashlib
import html
import io
import mimetypes
import os
import re
import secrets
import sqlite3
import socket
from datetime import datetime, timedelta
from email.parser import BytesParser
from email.policy import default as default_email_policy
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlencode, urlparse
from zoneinfo import ZoneInfo


APP_TITLE = "LRMDS Inventory"
PORTAL_NAME = "Learning Resources Management and Development System"
MANAGER_DISPLAY_NAME = "LRMDS Manager"
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "portal_data"
BACKUP_DIR = DATA_DIR / "backups"
MEDIA_DIR = BASE_DIR / "photo materials"
DB_PATH = Path(os.environ.get("INVENTORY_PORTAL_DB", DATA_DIR / "inventory_portal.db"))
HOST = os.environ.get("INVENTORY_PORTAL_HOST", "0.0.0.0")
PORT = int(os.environ.get("INVENTORY_PORTAL_PORT", "8000"))
DISPLAY_URL = os.environ.get("INVENTORY_PORTAL_DISPLAY_URL", "").strip()
SESSION_COOKIE_NAME = "inventory_portal_session"
SESSION_TTL_SECONDS = 60 * 60 * 12
SECURE_COOKIE = os.environ.get("INVENTORY_PORTAL_SECURE_COOKIE", "0") == "1"
DEFAULT_MANAGER_USERNAME = os.environ.get("INVENTORY_PORTAL_MANAGER_USERNAME", "manager")
INITIAL_MANAGER_PASSWORD = os.environ.get("INVENTORY_PORTAL_MANAGER_PASSWORD", "").strip()
LEGACY_DEFAULT_MANAGER_PASSWORD = "ChangeMe123!"
PAGE_SIZE = 20
AUDIT_PAGE_SIZE = 40
MAX_ATTACHMENT_SIZE = 50 * 1024 * 1024
MANAGER_SETUP_PATH = DATA_DIR / "manager_setup.txt"
MEDIA_ROUTES = {
    "round-logo": MEDIA_DIR / "round logo.png",
    "division-logo": MEDIA_DIR / "round logo.png",
    "deped-wordmark": MEDIA_DIR / "Deped word horizontal logo.png",
}

ROLE_MANAGER = "manager"
ROLE_TEACHER = "teacher"
ITEM_STATUS_PENDING = "Pending Review"
ITEM_STATUS_APPROVED = "Approved"
ITEM_STATUS_REVISION = "Needs Revision"
STATUS_OPTIONS = [ITEM_STATUS_PENDING, ITEM_STATUS_APPROVED, ITEM_STATUS_REVISION]
AUDIT_SCOPE_OPTIONS = [
    ("", "All activity"),
    ("auth", "Sign-ins"),
    ("inventory", "Inventory"),
    ("users", "Users"),
    ("system", "System"),
]

GRADE_LEVELS = ["Kindergarten"] + [f"Grade {number}" for number in range(1, 13)]
PROGRAMS = ["Alive", "IPED", "ADM", "ALS", "SNED", "DRRM", "HEALTH"]
SUBJECTS = [
    "Filipino",
    "English",
    "Math",
    "Science",
    "Makabansa",
    "Araling Panlipunan",
    "Music",
    "Arts",
    "Physical Education",
    "Health",
    "GMRC/Values",
]
CATEGORIES = [
    "Learning Mat",
    "Quarter Test Questionnaire",
    "Story Books",
    "Instructional Materials",
    "Manipulative",
    "Intervention Materials",
    "Research",
    "Video Lesson",
    "Strategic Intervention Material",
    "Science Intervention Material",
    "Learning Activity Sheet",
    "1st Term Test Questions",
    "2nd Term Test Questions",
    "3rd Term Test Questions",
    "Learning Area",
]
INVENTORY_ITEM_SELECT_COLUMNS = ", ".join(
    [
        "inventory_items.id",
        "inventory_items.title",
        "inventory_items.author",
        "inventory_items.grade_level",
        "inventory_items.program",
        "inventory_items.subject",
        "inventory_items.date_validated",
        "inventory_items.category",
        "inventory_items.remarks",
        "inventory_items.status",
        "inventory_items.attachment_name",
        "inventory_items.attachment_content_type",
        "inventory_items.attachment_size",
        "inventory_items.created_by",
        "inventory_items.updated_by",
        "inventory_items.created_at",
        "inventory_items.updated_at",
    ]
)
UTC_TIMEZONE = ZoneInfo("UTC")
DISPLAY_TIMEZONE_NAME = os.environ.get("INVENTORY_PORTAL_TIMEZONE", "Asia/Manila").strip() or "Asia/Manila"
try:
    DISPLAY_TIMEZONE = ZoneInfo(DISPLAY_TIMEZONE_NAME)
except Exception:
    DISPLAY_TIMEZONE = datetime.now().astimezone().tzinfo or UTC_TIMEZONE


def utc_now():
    return datetime.utcnow().replace(microsecond=0).isoformat()


def utc_after(seconds):
    return (datetime.utcnow() + timedelta(seconds=seconds)).replace(microsecond=0).isoformat()


def to_display_datetime(value):
    if not value:
        return None

    normalized = str(value).strip()
    if not normalized:
        return None
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC_TIMEZONE)
    return parsed.astimezone(DISPLAY_TIMEZONE)


def human_time(value):
    display_value = to_display_datetime(value)
    if display_value:
        return display_value.strftime("%Y-%m-%d %H:%M:%S")
    if not value:
        return "-"
    return value.replace("T", " ")


def human_date(value):
    display_value = to_display_datetime(value)
    if display_value:
        return display_value.strftime("%Y-%m-%d")
    if not value:
        return "-"
    return value.split("T", 1)[0]


def human_clock(value):
    display_value = to_display_datetime(value)
    if display_value:
        return display_value.strftime("%H:%M:%S")
    if not value:
        return "-"
    return value.split("T", 1)[1] if "T" in value else value


def safe_page_number(value):
    try:
        page = int(value)
        return page if page > 0 else 1
    except (TypeError, ValueError):
        return 1


def relative_display_path(path):
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)


def detect_lan_ip():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 80))
        return probe.getsockname()[0]
    except OSError:
        return None
    finally:
        probe.close()


def ensure_directories():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    STATIC_DIR.mkdir(parents=True, exist_ok=True)


def generate_temporary_password(length=16):
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@$%?"
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password) and re.search(r"[0-9]", password):
            return password


def write_manager_setup_note(username, password):
    ensure_directories()
    content = "\n".join(
        [
            f"{APP_TITLE} initial manager access",
            "",
            f"Username: {username}",
            f"Temporary password: {password}",
            "",
            "Use these details only on the host computer.",
            "Sign in once, change the password immediately, then delete this file.",
            f"Created: {human_time(utc_now())}",
            "",
        ]
    )
    MANAGER_SETUP_PATH.write_text(content, encoding="utf-8")
    return MANAGER_SETUP_PATH


def remove_manager_setup_note():
    try:
        MANAGER_SETUP_PATH.unlink()
    except FileNotFoundError:
        return


def format_file_size(num_bytes):
    size = float(num_bytes)
    units = ["B", "KB", "MB", "GB"]
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} {unit}"
        size /= 1024


def sanitize_attachment_name(filename):
    cleaned = (filename or "").replace("\\", "/").split("/")[-1].strip()
    cleaned = re.sub(r"[\r\n\t]+", " ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" .")
    return cleaned[:180] or None


def validate_attachment_upload(form_files):
    upload = form_files.get("attachment")
    if not upload:
        return None, []

    filename = sanitize_attachment_name(upload.get("filename", ""))
    content = upload.get("content", b"")
    if not filename and not content:
        return None, []

    errors = []
    if not filename:
        errors.append("Attachment file name is invalid.")
        return None, errors
    if not content:
        errors.append("Attachment file is empty.")
    if len(content) > MAX_ATTACHMENT_SIZE:
        errors.append(f"Attachment must be {format_file_size(MAX_ATTACHMENT_SIZE)} or smaller.")

    content_type = (upload.get("content_type") or "").split(";", 1)[0].strip() or "application/octet-stream"
    return {
        "name": filename,
        "content": content,
        "content_type": content_type,
        "size": len(content),
    }, errors


def build_attachment_info(item):
    if not item or not item["attachment_name"]:
        return None

    size_label = format_file_size(item["attachment_size"]) if item["attachment_size"] is not None else ""
    return {
        "name": item["attachment_name"],
        "href": f'/inventory/{item["id"]}/attachment',
        "size_label": size_label,
    }


def build_content_disposition(filename):
    fallback = re.sub(r"[^A-Za-z0-9._-]+", "_", filename).strip("._") or "attachment"
    return f'inline; filename="{fallback}"; filename*=UTF-8\'\'{quote(filename)}'


def get_connection():
    ensure_directories()
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


def create_database_backup(prefix="inventory_backup"):
    ensure_directories()
    backup_name = f"{prefix}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.db"
    backup_path = BACKUP_DIR / backup_name
    with get_connection() as source_connection:
        with sqlite3.connect(backup_path) as target_connection:
            source_connection.backup(target_connection)
    return backup_path


def resolve_backup_path(backup_name):
    if not backup_name:
        raise FileNotFoundError("Backup file name is required.")
    resolved_root = BACKUP_DIR.resolve()
    backup_path = (BACKUP_DIR / backup_name).resolve()
    if backup_path.parent != resolved_root or backup_path.suffix.lower() != ".db" or not backup_path.exists():
        raise FileNotFoundError("Backup file not found.")
    return backup_path


def list_database_backups():
    ensure_directories()
    backups = []
    for backup_path in BACKUP_DIR.glob("*.db"):
        stat = backup_path.stat()
        backups.append(
            {
                "name": backup_path.name,
                "created_at": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                "size": format_file_size(stat.st_size),
                "sort_key": stat.st_mtime,
            }
        )
    return sorted(backups, key=lambda row: row["sort_key"], reverse=True)


def restore_database_backup(backup_name):
    backup_path = resolve_backup_path(backup_name)
    with sqlite3.connect(backup_path, timeout=30) as source_connection:
        with sqlite3.connect(DB_PATH, timeout=30) as target_connection:
            source_connection.backup(target_connection)
    return backup_path


def hash_password(password, salt=None, iterations=260000):
    salt_bytes = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.b64encode(salt_bytes).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    )


def verify_password(password, stored_hash):
    try:
        algorithm, iterations_text, salt_text, digest_text = stored_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_text)
        salt_bytes = base64.b64decode(salt_text.encode("ascii"))
        expected = base64.b64decode(digest_text.encode("ascii"))
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, iterations)
        return secrets.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def password_strength_error(password):
    if len(password) < 10:
        return "Password must be at least 10 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must include at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must include at least one number."
    return None


def clean_username(value):
    username = value.strip().lower()
    if not re.fullmatch(r"[a-z0-9._-]{3,30}", username):
        return None
    return username


def init_db():
    ensure_directories()
    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('manager', 'teacher')),
                is_active INTEGER NOT NULL DEFAULT 1,
                must_change_password INTEGER NOT NULL DEFAULT 1,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS inventory_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                author TEXT NOT NULL,
                grade_level TEXT NOT NULL,
                program TEXT NOT NULL,
                subject TEXT NOT NULL,
                date_validated TEXT NOT NULL,
                category TEXT NOT NULL,
                remarks TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'Pending Review',
                attachment_name TEXT,
                attachment_content_type TEXT,
                attachment_size INTEGER,
                attachment_blob BLOB,
                created_by INTEGER NOT NULL,
                updated_by INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (created_by) REFERENCES users(id),
                FOREIGN KEY (updated_by) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                item_id INTEGER,
                ip_address TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (item_id) REFERENCES inventory_items(id)
            );

            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                csrf_token TEXT NOT NULL,
                flash_kind TEXT,
                flash_message TEXT,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            CREATE INDEX IF NOT EXISTS idx_inventory_updated_at ON inventory_items(updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_inventory_status ON inventory_items(status);
            CREATE INDEX IF NOT EXISTS idx_activity_created_at ON activity_logs(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
            """
        )
        ensure_inventory_attachment_columns(connection)
        ensure_default_manager(connection)
        ensure_lrmds_branding(connection)
        ensure_manager_setup_note(connection)
        clear_expired_sessions(connection)


def ensure_inventory_attachment_columns(connection):
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(inventory_items)").fetchall()}
    desired_columns = {
        "attachment_name": "TEXT",
        "attachment_content_type": "TEXT",
        "attachment_size": "INTEGER",
        "attachment_blob": "BLOB",
    }
    for column_name, column_type in desired_columns.items():
        if column_name not in columns:
            connection.execute(f"ALTER TABLE inventory_items ADD COLUMN {column_name} {column_type}")


def ensure_default_manager(connection):
    count = connection.execute("SELECT COUNT(*) AS total FROM users WHERE role = ?", (ROLE_MANAGER,)).fetchone()["total"]
    if count:
        return

    now = utc_now()
    initial_password = INITIAL_MANAGER_PASSWORD or generate_temporary_password()
    connection.execute(
        """
        INSERT INTO users (
            full_name, username, password_hash, role, is_active, must_change_password,
            failed_attempts, locked_until, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, 1, 1, 0, NULL, ?, ?)
        """,
        (
            MANAGER_DISPLAY_NAME,
            DEFAULT_MANAGER_USERNAME,
            hash_password(initial_password),
            ROLE_MANAGER,
            now,
            now,
        ),
    )
    setup_note = write_manager_setup_note(DEFAULT_MANAGER_USERNAME, initial_password)
    log_action(
        connection,
        None,
        "system.seed_manager",
        f'Created the initial manager account and wrote a setup note at "{relative_display_path(setup_note)}".',
        None,
        "127.0.0.1",
    )


def ensure_lrmds_branding(connection):
    connection.execute(
        """
        UPDATE users
        SET full_name = ?, updated_at = ?
        WHERE role = ? AND full_name = ?
        """,
        (MANAGER_DISPLAY_NAME, utc_now(), ROLE_MANAGER, "ILRC Manager"),
    )


def ensure_manager_setup_note(connection):
    manager = connection.execute(
        """
        SELECT username, password_hash, must_change_password
        FROM users
        WHERE role = ?
        ORDER BY id ASC
        LIMIT 1
        """,
        (ROLE_MANAGER,),
    ).fetchone()
    if not manager or not manager["must_change_password"] or manager["username"] != DEFAULT_MANAGER_USERNAME:
        return
    if MANAGER_SETUP_PATH.exists():
        return
    if INITIAL_MANAGER_PASSWORD and verify_password(INITIAL_MANAGER_PASSWORD, manager["password_hash"]):
        write_manager_setup_note(DEFAULT_MANAGER_USERNAME, INITIAL_MANAGER_PASSWORD)
        return
    if verify_password(LEGACY_DEFAULT_MANAGER_PASSWORD, manager["password_hash"]):
        write_manager_setup_note(DEFAULT_MANAGER_USERNAME, LEGACY_DEFAULT_MANAGER_PASSWORD)


def log_action(connection, user_id, action, details, item_id, ip_address):
    connection.execute(
        """
        INSERT INTO activity_logs (user_id, action, details, item_id, ip_address, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user_id, action, details, item_id, ip_address, utc_now()),
    )


def get_user_by_id(connection, user_id):
    if not user_id:
        return None
    return connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_user_by_username(connection, username):
    return connection.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def clear_expired_sessions(connection):
    connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (utc_now(),))


def create_session(user_id):
    now = utc_now()
    session_id = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(24)
    expires_at = utc_after(SESSION_TTL_SECONDS)
    session = {"user_id": user_id, "csrf_token": csrf_token, "expires_at": expires_at}
    with get_connection() as connection:
        clear_expired_sessions(connection)
        connection.execute(
            """
            INSERT INTO sessions (session_id, user_id, csrf_token, flash_kind, flash_message, expires_at, created_at, updated_at)
            VALUES (?, ?, ?, NULL, NULL, ?, ?, ?)
            """,
            (session_id, user_id, csrf_token, expires_at, now, now),
        )
    return session_id, session


def get_session(session_id):
    if not session_id:
        return None
    with get_connection() as connection:
        clear_expired_sessions(connection)
        session = connection.execute(
            "SELECT user_id, csrf_token FROM sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        if not session:
            return None
        expires_at = utc_after(SESSION_TTL_SECONDS)
        connection.execute(
            "UPDATE sessions SET expires_at = ?, updated_at = ? WHERE session_id = ?",
            (expires_at, utc_now(), session_id),
        )
    return {"user_id": session["user_id"], "csrf_token": session["csrf_token"], "expires_at": expires_at}


def destroy_session(session_id):
    if not session_id:
        return
    with get_connection() as connection:
        connection.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))


def escape(value):
    return html.escape("" if value is None else str(value), quote=True)


def nav_items(user):
    items = [
        ("dashboard", "/dashboard", "Dashboard"),
        ("inventory", "/inventory", "Inventory"),
        ("new-item", "/inventory/new", "Add Entry"),
        ("account", "/account/password", "Account"),
    ]
    if user and user["role"] == ROLE_MANAGER:
        items.extend(
            [
                ("users", "/users", "Users"),
                ("audit", "/audit", "Audit Log"),
                ("backups", "/backups", "Backups"),
            ]
        )
    return items


def render_options(options, selected):
    markup = []
    if selected and selected not in options:
        markup.append(f'<option value="{escape(selected)}" selected>{escape(selected)}</option>')
    for option in options:
        is_selected = " selected" if option == selected else ""
        markup.append(f'<option value="{escape(option)}"{is_selected}>{escape(option)}</option>')
    return "".join(markup)


def render_named_options(options, selected):
    markup = []
    for value, label in options:
        is_selected = " selected" if value == selected else ""
        markup.append(f'<option value="{escape(value)}"{is_selected}>{escape(label)}</option>')
    return "".join(markup)


def render_flash(kind, message):
    if not message:
        return ""
    return f'<div class="flash flash-{escape(kind)}">{escape(message)}</div>'


def page_intro(active_key, title):
    mapping = {
        "dashboard": (
            f"Welcome to the {PORTAL_NAME}",
            "Monitor submissions, approvals, and shared resource activity from one shared LRMDS workspace.",
        ),
        "inventory": (
            "Learning Resource Records",
            "Browse, filter, and review the shared inventory of learning resources across the portal.",
        ),
        "new-item": (
            "Resource Submission",
            "Add a new learning resource entry for review, approval, and shared portal access.",
        ),
        "users": (
            "Portal User Management",
            "Manage account access, teacher participation, and shared portal permissions.",
        ),
        "audit": (
            "Audit and Oversight",
            "Review sign-ins, updates, and account actions to keep portal use accountable and traceable.",
        ),
        "backups": (
            "Backup and Recovery",
            "Protect the shared portal with quick backups and a clear restore history before larger changes.",
        ),
        "account": (
            "Account Access",
            "Maintain your password and keep access to the shared learning resource portal secure.",
        ),
    }
    return mapping.get(active_key, (PORTAL_NAME, f"Manage {title.lower()} in the shared LRMDS inventory workspace."))


def render_layout(title, user, content, active_key, csrf_token="", flash=""):
    role_class = "badge-manager" if user["role"] == ROLE_MANAGER else "badge-teacher"
    intro_title, intro_copy = page_intro(active_key, title)
    navigation = "".join(
        f'<a class="nav-link{" active" if key == active_key else ""}" href="{href}">{label}</a>'
        for key, href, label in nav_items(user)
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(title)} | {escape(APP_TITLE)}</title>
  <link rel="icon" type="image/png" href="/media/division-logo?v=2">
  <link rel="stylesheet" href="/static/portal.css?v=5">
</head>
<body class="app-body">
  <div class="portal-shell">
    <aside class="sidebar app-sidebar">
      <div class="sidebar-shell">
        <a class="sidebar-brand" href="/dashboard">
          <img class="sidebar-logo" src="/media/division-logo?v=2" alt="LRMDS portal logo">
          <div class="sidebar-brand-copy">
            <p class="eyebrow">LRMDS Inventory</p>
            <h1>{escape(APP_TITLE)}</h1>
            <p class="sidebar-brand-meta">{escape(PORTAL_NAME)}</p>
            <p class="sidebar-brand-note">Shared workspace for teacher submissions, review, and inventory tracking.</p>
          </div>
        </a>
        <nav class="sidebar-nav nav-stack">
          {navigation}
        </nav>
        <div class="sidebar-session">
          <div class="sidebar-user">
            <span class="portal-user-label">Signed in as</span>
            <strong>{escape(user["full_name"])}</strong>
            <span class="pill {role_class}">{escape(user["role"].title())}</span>
          </div>
          <a class="btn btn-ghost sidebar-action" href="/account/password">Change Password</a>
          <form method="post" action="/logout">
            <input type="hidden" name="csrf_token" value="{escape(csrf_token)}">
            <button class="btn btn-secondary sidebar-action" type="submit">Sign Out</button>
          </form>
        </div>
      </div>
    </aside>
    <main class="portal-main app-main">
      <header class="page-header">
        <div class="page-header-copy">
          <p class="eyebrow">{escape(intro_title)}</p>
          <h2>{escape(title)}</h2>
          <p class="lead">{escape(intro_copy)}</p>
        </div>
        <div class="page-header-meta">
          <div class="page-inline-meta">
            <span class="page-summary-label">Current Role</span>
            <strong>{escape(user["role"].title())}</strong>
            <span class="muted small">Shared access level for this portal session</span>
          </div>
          <div class="page-inline-meta">
            <span class="page-summary-label">Inventory Focus</span>
            <strong>{escape(title)}</strong>
            <span class="muted small">Learning resource management across the shared portal</span>
          </div>
        </div>
      </header>
      {flash}
      <section class="page-content">
        {content}
      </section>
      <footer class="portal-footer portal-footer-inline">
        <p>{escape(PORTAL_NAME)} portal for shared submission, review, and inventory tracking.</p>
      </footer>
    </main>
  </div>
  <script>
    document.addEventListener("submit", function(event) {{
      const form = event.target;
      if (form.dataset.confirm && !window.confirm(form.dataset.confirm)) {{
        event.preventDefault();
      }}
    }});
  </script>
</body>
</html>"""


def render_login_page(error_message="", username=""):
    error_markup = render_flash("danger", error_message)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign In | {escape(APP_TITLE)}</title>
  <link rel="icon" type="image/png" href="/media/division-logo?v=2">
  <link rel="stylesheet" href="/static/portal.css?v=5">
</head>
<body class="login-body">
  <div class="ambient ambient-one"></div>
  <div class="ambient ambient-two"></div>
  <main class="login-shell">
    <section class="login-copy">
      <div class="login-copy-top">
        <img class="login-wordmark" src="/media/deped-wordmark" alt="DepEd wordmark">
        <div class="login-brand-cluster">
          <img class="login-seal" src="/media/division-logo?v=2" alt="LRMDS portal logo">
          <div class="login-brand-text">
            <p class="eyebrow">Department of Education</p>
            <h1>{escape(PORTAL_NAME)}</h1>
            <p class="login-subtitle">Inventory Portal</p>
          </div>
        </div>
      </div>
      <div class="login-copy-body">
        <p class="eyebrow">Welcome to the {escape(PORTAL_NAME)}</p>
        <h2 class="login-hero-title">Shared access for submission, review, and inventory tracking.</h2>
        <p class="lead">A lighter shared workspace for teachers and the LRMDS manager to manage learning resources without separate desktop files.</p>
        <div class="login-badge-list">
          <span class="login-badge">Teacher submissions</span>
          <span class="login-badge">Manager approvals</span>
          <span class="login-badge">Shared portal records</span>
        </div>
      </div>
      <div class="login-meta-grid">
        <div class="login-meta-item">
          <span class="login-meta-label">For Teachers</span>
          <p>Submit new learning resources and monitor the status of your entries in one place.</p>
        </div>
        <div class="login-meta-item">
          <span class="login-meta-label">For the LRMDS Manager</span>
          <p>Review, approve, and maintain a shared LRMDS inventory with audit visibility.</p>
        </div>
        <div class="login-meta-item">
          <span class="login-meta-label">For Shared Access</span>
          <p>Keep records centralized, current, and easier to access across the portal.</p>
        </div>
      </div>
    </section>
    <section class="login-card">
      <p class="eyebrow">Inventory Access</p>
      <h2>Sign In</h2>
      <p class="muted login-help">Use your assigned account to continue to the shared learning resource workspace.</p>
      {error_markup}
      <form method="post" action="/login" class="form-grid login-access-form">
        <label>
          <span>Username</span>
          <input type="text" name="username" value="{escape(username)}" autocomplete="username" required>
        </label>
        <label>
          <span>Password</span>
          <input type="password" name="password" autocomplete="current-password" required>
        </label>
        <button class="btn btn-primary" type="submit">Sign In to Inventory</button>
      </form>
    </section>
  </main>
</body>
</html>"""


def render_stat_card(title, value, subtitle):
    return (
        '<article class="stat-card">'
        f"<p>{escape(title)}</p>"
        f"<h3>{escape(value)}</h3>"
        f'<span class="muted small">{escape(subtitle)}</span>'
        "</article>"
    )


def render_dashboard(connection, user, csrf_token):
    total_items = connection.execute("SELECT COUNT(*) AS total FROM inventory_items").fetchone()["total"]
    pending_items = connection.execute(
        "SELECT COUNT(*) AS total FROM inventory_items WHERE status = ?",
        (ITEM_STATUS_PENDING,),
    ).fetchone()["total"]
    approved_items = connection.execute(
        "SELECT COUNT(*) AS total FROM inventory_items WHERE status = ?",
        (ITEM_STATUS_APPROVED,),
    ).fetchone()["total"]
    active_teachers = connection.execute(
        "SELECT COUNT(*) AS total FROM users WHERE role = ? AND is_active = 1",
        (ROLE_TEACHER,),
    ).fetchone()["total"]
    my_items = connection.execute(
        "SELECT COUNT(*) AS total FROM inventory_items WHERE created_by = ?",
        (user["id"],),
    ).fetchone()["total"]
    recent_items = connection.execute(
        """
        SELECT """
        + INVENTORY_ITEM_SELECT_COLUMNS
        + """, users.full_name AS owner_name
        FROM inventory_items
        JOIN users ON users.id = inventory_items.created_by
        ORDER BY inventory_items.updated_at DESC
        LIMIT 6
        """
    ).fetchall()
    grade_rows = connection.execute(
        """
        SELECT grade_level, COUNT(*) AS total
        FROM inventory_items
        GROUP BY grade_level
        """
    ).fetchall()

    grade_totals = {row["grade_level"]: row["total"] for row in grade_rows}
    chart_rows = [{"grade_level": grade, "total": grade_totals.get(grade, 0)} for grade in GRADE_LEVELS]
    legacy_rows = sorted(
        (
            {"grade_level": grade_level, "total": total}
            for grade_level, total in grade_totals.items()
            if grade_level not in GRADE_LEVELS
        ),
        key=lambda row: row["grade_level"],
    )
    chart_rows.extend(legacy_rows)
    chart_peak = max((row["total"] for row in chart_rows), default=0)

    if total_items and chart_peak:
        distribution_markup = "".join(
            (
                '<div class="metric-row metric-row-grade">'
                f'<div class="metric-label">{escape(row["grade_level"])}</div>'
                f'<div class="metric-bar"><span style="width:{(max(8, (row["total"] / chart_peak) * 100) if row["total"] else 0):.2f}%"></span></div>'
                f'<div class="metric-value">{escape(row["total"])}</div>'
                "</div>"
            )
            for row in chart_rows
        )
    else:
        distribution_markup = '<p class="empty-state">No inventory items yet. Start by adding a resource entry.</p>'

    recent_markup = "".join(
        (
            '<tr>'
            f'<td>{escape(item["title"])}</td>'
            f'<td>{escape(item["owner_name"])}</td>'
            f'<td><span class="pill {status_class(item["status"])}">{escape(item["status"])}</span></td>'
            f'<td>{escape(item["category"])}</td>'
            f'<td>{escape(item["updated_at"].replace("T", " "))}</td>'
            "</tr>"
        )
        for item in recent_items
    )
    if not recent_markup:
        recent_markup = '<tr><td colspan="5" class="empty-state">No recent activity yet.</td></tr>'

    stats = [
        render_stat_card("All Resources", total_items, "shared across the portal"),
        render_stat_card("Pending Review", pending_items, "awaiting manager action"),
        render_stat_card("Approved", approved_items, "ready for wider use"),
        render_stat_card("Active Teachers", active_teachers, "contributors with portal access"),
    ]

    if user["role"] == ROLE_TEACHER:
        stats[-1] = render_stat_card("My Entries", my_items, "items you submitted")

    must_change_notice = ""
    if user["must_change_password"]:
        must_change_notice = (
            '<div class="notice-card warning">'
            "<strong>Password update required.</strong> Change your password before normal use so the shared portal stays safe."
            "</div>"
        )

    manager_tools = ""
    if user["role"] == ROLE_MANAGER:
        manager_tools = '<a class="btn btn-secondary" href="/backups">Backups</a>'

    return (
        f"{must_change_notice}"
        '<section class="dashboard-shell">'
        '<div class="dashboard-toolbar">'
        '<div class="dashboard-copy">'
        '<p class="eyebrow">Workspace Overview</p>'
        f'<h3>{escape("Manager view" if user["role"] == ROLE_MANAGER else "Teacher workspace")}</h3>'
        '<p class="lead">The portal keeps your learning-resource records centralized, reviewable, and easier to manage across the LRMDS workspace.</p>'
        '</div>'
        '<div class="hero-actions dashboard-actions">'
        '<a class="btn btn-primary" href="/inventory/new">Add New Resource</a>'
        '<a class="btn btn-ghost" href="/inventory">Browse Inventory</a>'
        f"{manager_tools}"
        '</div>'
        '</div>'
        f'<section class="stat-grid dashboard-stats">{"".join(stats)}</section>'
        '<section class="dashboard-grid">'
        '<article class="dashboard-section dashboard-activity">'
        '<div class="card-header"><h3>Recent Activity</h3><p class="muted small">Most recently updated resources</p></div>'
        '<div class="table-shell"><table><thead><tr><th>Title</th><th>Owner</th><th>Status</th><th>Category</th><th>Updated</th></tr></thead>'
        f"<tbody>{recent_markup}</tbody></table></div>"
        '</article>'
        '<article class="dashboard-section dashboard-insight">'
        '<div class="card-header"><h3>Grade Level Distribution</h3><p class="muted small">Shows where submitted resources are concentrated across kindergarten to Grade 12.</p></div>'
        f'<div class="metrics-list">{distribution_markup}</div>'
        '</article>'
        '</section>'
        '</section>'
    )


def status_class(status):
    if status == ITEM_STATUS_APPROVED:
        return "badge-approved"
    if status == ITEM_STATUS_REVISION:
        return "badge-revision"
    return "badge-pending"


def role_class(role):
    return "badge-manager" if role == ROLE_MANAGER else "badge-teacher"


def base_item_values():
    return {
        "title": "",
        "author": "",
        "grade_level": GRADE_LEVELS[0],
        "program": PROGRAMS[0],
        "subject": SUBJECTS[0],
        "date_validated": datetime.utcnow().strftime("%Y-%m-%d"),
        "category": CATEGORIES[0],
        "remarks": "",
        "status": ITEM_STATUS_PENDING,
    }


def validate_date(date_text):
    try:
        datetime.strptime(date_text, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def validate_item_form(raw_values, user, is_edit=False):
    values = base_item_values()
    values.update({key: raw_values.get(key, "").strip() for key in values})
    errors = []

    if not values["title"]:
        errors.append("Title is required.")
    if not values["author"]:
        errors.append("Author or writer is required.")
    if len(values["title"]) > 140:
        errors.append("Title must stay under 140 characters.")
    if len(values["author"]) > 120:
        errors.append("Author or writer must stay under 120 characters.")
    if len(values["remarks"]) > 300:
        errors.append("Remarks must stay under 300 characters.")
    if values["grade_level"] not in GRADE_LEVELS:
        errors.append("Grade level is invalid.")
    if values["program"] not in PROGRAMS:
        errors.append("Program is invalid.")
    if values["subject"] not in SUBJECTS:
        errors.append("Subject is invalid.")
    if values["category"] not in CATEGORIES:
        errors.append("Category is invalid.")
    if not validate_date(values["date_validated"]):
        errors.append("Date validated must use YYYY-MM-DD format.")

    if user["role"] == ROLE_MANAGER:
        if values["status"] not in STATUS_OPTIONS:
            errors.append("Status is invalid.")
    else:
        values["status"] = ITEM_STATUS_PENDING

    return values, errors


def render_form_errors(errors):
    if not errors:
        return ""
    items = "".join(f"<li>{escape(error)}</li>" for error in errors)
    return f'<div class="flash flash-danger"><ul class="error-list">{items}</ul></div>'


def render_item_form(user, csrf_token, values, errors, mode, item_id=None, existing_attachment=None):
    heading = "Edit Resource Entry" if mode == "edit" else "Add Resource Entry"
    eyebrow = "Update Entry" if mode == "edit" else "New Submission"
    intro = (
        "Teachers can submit entries for review. The manager can approve, revise, or update any record."
        if user["role"] == ROLE_MANAGER
        else "Your submission will go into the shared inventory and stay marked for manager review."
    )
    action = f"/inventory/{item_id}/edit" if item_id else "/inventory/new"
    submit_label = "Save Changes" if mode == "edit" else "Save Entry"
    helper_note = (
        "Teacher edits return the record to manager review after saving."
        if mode == "edit" and user["role"] != ROLE_MANAGER
        else "Use clear titles, categories, and remarks so the shared inventory stays easy to search."
    )
    status_input = (
        f"""
        <label>
          <span>Status</span>
          <select name="status">
            {render_options(STATUS_OPTIONS, values["status"])}
          </select>
        </label>
        """
        if user["role"] == ROLE_MANAGER
        else f"""
        <label>
          <span>Status</span>
          <div class="readonly-pill">
            <span class="pill badge-pending">{escape(values.get("status", ITEM_STATUS_PENDING))}</span>
          </div>
          <input type="hidden" name="current_status" value="{escape(values.get("status", ITEM_STATUS_PENDING))}">
        </label>
        """
    )
    attachment_markup = ""
    if existing_attachment:
        attachment_markup = (
            '<div class="attachment-current">'
            '<span class="attachment-label">Current File</span>'
            f'<a class="table-action" href="{existing_attachment["href"]}">{escape(existing_attachment["name"])}</a>'
            f'<p class="muted small attachment-meta">{escape(existing_attachment["size_label"] or "Attached to this entry")}</p>'
            '<div class="attachment-remove">'
            '<input id="remove-attachment" type="checkbox" name="remove_attachment" value="1">'
            '<label for="remove-attachment">Remove current file</label>'
            "</div>"
            "</div>"
        )
    attachment_reset_note = (
        '<p class="muted small attachment-meta">If validation fails after you choose a file, select it again before resubmitting.</p>'
        if errors
        else ""
    )

    return (
        '<section class="entry-page">'
        '<div class="entry-page-header">'
        f'<p class="eyebrow">{escape(eyebrow)}</p>'
        f"<h3>{escape(heading)}</h3>"
        f'<p class="lead entry-lead">{escape(intro)}</p>'
        f'<p class="muted small entry-note">{escape(helper_note)}</p>'
        "</div>"
        f"{render_form_errors(errors)}"
        f'<form method="post" action="{action}" enctype="multipart/form-data" class="form-grid inventory-form entry-form-grid">'
        f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
        '<label class="span-2">'
        "<span>Title</span>"
        f'<input type="text" name="title" maxlength="140" value="{escape(values["title"])}" required>'
        "</label>"
        '<label>'
        "<span>Author or Writer</span>"
        f'<input type="text" name="author" maxlength="120" value="{escape(values["author"])}" required>'
        "</label>"
        '<label>'
        "<span>Date Validated</span>"
        f'<input type="date" name="date_validated" value="{escape(values["date_validated"])}" required>'
        "</label>"
        '<label>'
        "<span>Grade Level</span>"
        f'<select name="grade_level">{render_options(GRADE_LEVELS, values["grade_level"])}</select>'
        "</label>"
        '<label>'
        "<span>Program</span>"
        f'<select name="program">{render_options(PROGRAMS, values["program"])}</select>'
        "</label>"
        '<label>'
        "<span>Subject</span>"
        f'<select name="subject">{render_options(SUBJECTS, values["subject"])}</select>'
        "</label>"
        '<label>'
        "<span>Category</span>"
        f'<select name="category">{render_options(CATEGORIES, values["category"])}</select>'
        "</label>"
        f"{status_input}"
        '<div class="span-2 attachment-field">'
        '<span class="field-label">Attach File</span>'
        '<input id="attachment-upload" type="file" name="attachment">'
        '<p class="muted small attachment-meta">Optional. Upload the supporting file the validator needs to review. Maximum size: 50 MB.</p>'
        f"{attachment_markup}"
        f"{attachment_reset_note}"
        "</div>"
        '<label class="span-2">'
        "<span>Remarks</span>"
        f'<textarea name="remarks" rows="4" maxlength="300" placeholder="Notes, special use, review remarks, or location details.">{escape(values["remarks"])}</textarea>'
        "</label>"
        '<div class="span-2 form-actions entry-actions">'
        f'<button class="btn btn-primary" type="submit">{escape(submit_label)}</button>'
        '<a class="btn btn-ghost" href="/inventory">Back to Inventory</a>'
        "</div>"
        "</form>"
        "</section>"
    )


def render_item_detail_page(connection, user, csrf_token, item):
    attachment = build_attachment_info(item)
    field_rows = [
        ("Title", item["title"]),
        ("Author/Writer", item["author"]),
        ("Grade Level", item["grade_level"]),
        ("Program", item["program"]),
        ("Subject", item["subject"]),
        ("Date Validated", item["date_validated"]),
        ("Category", item["category"]),
        ("Submitted By", item["owner_name"]),
        ("Created", human_time(item["created_at"])),
        ("Updated", human_time(item["updated_at"])),
    ]
    details_markup = "".join(
        (
            '<div class="detail-item">'
            f'<span class="detail-label">{escape(label)}</span>'
            f'<strong class="detail-value">{escape(value)}</strong>'
            "</div>"
        )
        for label, value in field_rows
    )
    remarks_markup = escape(item["remarks"]) if item["remarks"] else "No remarks added."
    audit_rows = connection.execute(
        """
        SELECT activity_logs.*, users.full_name
        FROM activity_logs
        LEFT JOIN users ON users.id = activity_logs.user_id
        WHERE activity_logs.item_id = ?
        ORDER BY activity_logs.created_at DESC
        LIMIT 10
        """,
        (item["id"],),
    ).fetchall()
    audit_markup = "".join(
        (
            '<div class="history-row">'
            f'<strong>{escape(row["action"])}</strong>'
            f'<span class="muted small">{escape(row["full_name"] or "System")} - {escape(human_time(row["created_at"]))}</span>'
            f'<p>{escape(row["details"])}</p>'
            "</div>"
        )
        for row in audit_rows
    )
    if not audit_markup:
        audit_markup = '<p class="empty-state">No activity history yet for this item.</p>'

    attachment_markup = (
        '<div class="remarks-card attachment-card">'
        '<span class="detail-label">Attached File</span>'
        '<div class="attachment-actions">'
        f'<a class="btn btn-secondary" href="{attachment["href"]}">Open File</a>'
        "</div>"
        f'<p class="detail-remarks attachment-copy">{escape(attachment["name"])}</p>'
        f'<p class="muted small attachment-meta">{escape(attachment["size_label"] or "Supporting file attached to this entry.")}</p>'
        "</div>"
        if attachment
        else (
            '<div class="remarks-card attachment-card">'
            '<span class="detail-label">Attached File</span>'
            '<p class="detail-remarks attachment-copy">No supporting file was attached to this entry.</p>'
            "</div>"
        )
    )

    edit_link = (
        f'<a class="btn btn-primary" href="/inventory/{item["id"]}/edit">Edit Entry</a>'
        if can_edit_item(user, item)
        else ""
    )
    manager_status_actions = ""
    if user["role"] == ROLE_MANAGER:
        manager_status_actions = "".join(
            (
                f'<form method="post" action="/inventory/{item["id"]}/status">'
                f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
                f'<input type="hidden" name="status" value="{escape(status)}">'
                f'<button class="btn btn-inline {"btn-primary" if status == item["status"] else "btn-secondary"}" type="submit">{escape(status)}</button>'
                "</form>"
            )
            for status in STATUS_OPTIONS
        )
        manager_status_actions = (
            '<div class="review-panel">'
            '<h4>Manager Review</h4>'
            '<p class="muted small">Update status without opening the full edit form.</p>'
            f'<div class="status-actions">{manager_status_actions}</div>'
            "</div>"
        )

    return (
        '<section class="card resource-stage">'
        '<div class="card-header split">'
        '<div>'
        f'<h3>{escape(item["title"])}</h3>'
        '<p class="muted small">Review the full entry details, remarks, and recent history before editing or approving.</p>'
        "</div>"
        '<div class="stack-actions">'
        f'<span class="pill {status_class(item["status"])}">{escape(item["status"])}</span>'
        f"{edit_link}"
        '<a class="btn btn-ghost" href="/inventory">Back to Inventory</a>'
        "</div>"
        "</div>"
        '<div class="detail-grid">'
        f"{details_markup}"
        "</div>"
        f"{attachment_markup}"
        '<div class="remarks-card">'
        '<span class="detail-label">Remarks</span>'
        f'<p class="detail-remarks">{remarks_markup}</p>'
        "</div>"
        f"{manager_status_actions}"
        '<div class="card-header section-gap"><h3>Item History</h3><p class="muted small">Latest activity tied to this record.</p></div>'
        f'<div class="history-list">{audit_markup}</div>'
        "</section>"
    )


def build_inventory_query(filters):
    clauses = []
    params = []
    search_text = filters.get("search", "").strip()
    if search_text:
        pattern = f"%{search_text}%"
        clauses.append(
            "(title LIKE ? OR author LIKE ? OR subject LIKE ? OR category LIKE ? OR remarks LIKE ?)"
        )
        params.extend([pattern, pattern, pattern, pattern, pattern])

    for key in ("grade_level", "program", "subject", "category", "status"):
        value = filters.get(key, "").strip()
        if value:
            clauses.append(f"inventory_items.{key} = ?")
            params.append(value)

    if filters.get("mine_only") == "1":
        clauses.append("inventory_items.created_by = ?")
        params.append(filters["current_user_id"])

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return where_sql, params


def build_inventory_url(filters, page):
    params = {}
    for key in ("search", "grade_level", "program", "subject", "category", "status"):
        value = filters.get(key, "").strip()
        if value:
            params[key] = value
    if filters.get("mine_only") == "1":
        params["mine_only"] = "1"
    if page > 1:
        params["page"] = str(page)
    query_string = urlencode(params)
    return f"/inventory?{query_string}" if query_string else "/inventory"


def build_inventory_filter_chips(filters):
    chips = []
    labels = {
        "search": "Search",
        "grade_level": "Grade",
        "program": "Program",
        "subject": "Subject",
        "category": "Category",
        "status": "Status",
    }
    for key, label in labels.items():
        value = filters.get(key, "").strip()
        if not value:
            continue
        cleared = dict(filters)
        cleared[key] = ""
        cleared["page"] = "1"
        chips.append((f"{label}: {value}", build_inventory_url(cleared, 1)))
    if filters.get("mine_only") == "1":
        cleared = dict(filters)
        cleared["mine_only"] = ""
        cleared["page"] = "1"
        chips.append(("My entries", build_inventory_url(cleared, 1)))
    return chips


def render_filter_chip_bar(chips, reset_href):
    if not chips:
        return ""
    markup = "".join(
        f'<a class="filter-chip" href="{escape(href)}"><span>{escape(label)}</span><strong aria-hidden="true">x</strong></a>'
        for label, href in chips
    )
    return (
        '<div class="filter-chip-bar">'
        '<span class="filter-chip-label">Active filters</span>'
        f"{markup}"
        f'<a class="filter-chip-reset" href="{escape(reset_href)}">Clear all</a>'
        "</div>"
    )


def build_audit_query(filters):
    clauses = []
    params = []
    search_text = filters.get("search", "").strip()
    if search_text:
        pattern = f"%{search_text}%"
        clauses.append(
            "(activity_logs.action LIKE ? OR activity_logs.details LIKE ? OR IFNULL(users.full_name, '') LIKE ? OR IFNULL(activity_logs.ip_address, '') LIKE ?)"
        )
        params.extend([pattern, pattern, pattern, pattern])

    scope = filters.get("scope", "").strip()
    if scope in {value for value, _label in AUDIT_SCOPE_OPTIONS if value}:
        clauses.append("activity_logs.action LIKE ?")
        params.append(f"{scope}.%")

    actor = filters.get("actor", "").strip()
    if actor.isdigit():
        clauses.append("activity_logs.user_id = ?")
        params.append(int(actor))

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return where_sql, params


def build_audit_url(filters, page):
    params = {}
    for key in ("search", "scope", "actor"):
        value = filters.get(key, "").strip()
        if value:
            params[key] = value
    if page > 1:
        params["page"] = str(page)
    query_string = urlencode(params)
    return f"/audit?{query_string}" if query_string else "/audit"


def build_audit_filter_chips(filters, actor_lookup):
    chips = []
    search_text = filters.get("search", "").strip()
    if search_text:
        cleared = dict(filters)
        cleared["search"] = ""
        cleared["page"] = "1"
        chips.append((f"Search: {search_text}", build_audit_url(cleared, 1)))

    scope = filters.get("scope", "").strip()
    if scope:
        label = next((item_label for item_value, item_label in AUDIT_SCOPE_OPTIONS if item_value == scope), scope)
        cleared = dict(filters)
        cleared["scope"] = ""
        cleared["page"] = "1"
        chips.append((f"Scope: {label}", build_audit_url(cleared, 1)))

    actor = filters.get("actor", "").strip()
    if actor:
        cleared = dict(filters)
        cleared["actor"] = ""
        cleared["page"] = "1"
        chips.append((f'User: {actor_lookup.get(actor, "Unknown")}', build_audit_url(cleared, 1)))
    return chips


def render_inventory_page(connection, user, csrf_token, filters):
    where_sql, params = build_inventory_query({**filters, "current_user_id": user["id"]})
    total_count = connection.execute(
        f"""
        SELECT COUNT(*) AS total
        FROM inventory_items
        {where_sql}
        """,
        params,
    ).fetchone()["total"]
    current_page = safe_page_number(filters.get("page", "1"))
    total_pages = max(1, (total_count + PAGE_SIZE - 1) // PAGE_SIZE)
    if current_page > total_pages:
        current_page = total_pages
    offset = (current_page - 1) * PAGE_SIZE
    rows = connection.execute(
        f"""
        SELECT {INVENTORY_ITEM_SELECT_COLUMNS}, users.full_name AS owner_name
        FROM inventory_items
        JOIN users ON users.id = inventory_items.created_by
        {where_sql}
        ORDER BY inventory_items.updated_at DESC, inventory_items.id DESC
        LIMIT ? OFFSET ?
        """,
        [*params, PAGE_SIZE, offset],
    ).fetchall()

    items_markup = []
    for row in rows:
        can_edit = user["role"] == ROLE_MANAGER or row["created_by"] == user["id"]
        can_delete = user["role"] == ROLE_MANAGER
        actions = ['<div class="inventory-actions">']
        actions.append(f'<a class="table-action" href="/inventory/{row["id"]}">View</a>')
        if row["attachment_name"]:
            actions.append(f'<a class="table-action" href="/inventory/{row["id"]}/attachment">View File</a>')
        if can_edit:
            actions.append(f'<a class="table-action" href="/inventory/{row["id"]}/edit">Edit</a>')
        if can_delete:
            actions.append(
                f"""
                <form method="post" action="/inventory/{row["id"]}/delete" class="inline-form" data-confirm="Delete this entry from the shared portal?">
                  <input type="hidden" name="csrf_token" value="{escape(csrf_token)}">
                  <button class="table-action table-action-danger" type="submit">Delete</button>
                </form>
                """
            )
        actions.append("</div>")

        items_markup.append(
            "<tr>"
            f'<td><strong>{escape(row["title"])}</strong><div class="muted small">#{row["id"]}</div></td>'
            f"<td>{escape(row['author'])}</td>"
            f"<td>{escape(row['grade_level'])}</td>"
            f"<td>{escape(row['program'])}</td>"
            f"<td>{escape(row['subject'])}</td>"
            f"<td>{escape(row['date_validated'])}</td>"
            f"<td>{escape(row['category'])}</td>"
            f'<td><span class="pill {status_class(row["status"])}">{escape(row["status"])}</span></td>'
            f"<td>{escape(row['owner_name'])}</td>"
            f"<td>{''.join(actions)}</td>"
            "</tr>"
        )

    if not items_markup:
        items_markup.append('<tr><td colspan="10" class="empty-state">No records matched your filters.</td></tr>')

    export_button = (
        '<a class="btn btn-secondary" href="/export.csv">Export CSV</a>'
        if user["role"] == ROLE_MANAGER
        else ""
    )
    backup_button = (
        '<a class="btn btn-ghost" href="/backups">Backups</a>'
        if user["role"] == ROLE_MANAGER
        else ""
    )
    start_number = offset + 1 if total_count else 0
    end_number = min(offset + PAGE_SIZE, total_count)
    previous_link = (
        f'<a class="btn btn-ghost" href="{build_inventory_url(filters, current_page - 1)}">Previous</a>'
        if current_page > 1
        else '<span class="btn btn-ghost btn-disabled">Previous</span>'
    )
    next_link = (
        f'<a class="btn btn-ghost" href="{build_inventory_url(filters, current_page + 1)}">Next</a>'
        if current_page < total_pages
        else '<span class="btn btn-ghost btn-disabled">Next</span>'
    )
    pagination_markup = (
        '<div class="pagination-row">'
        f'<p class="results-meta">Showing {start_number}-{end_number} of {total_count} entries</p>'
        '<div class="pagination-actions">'
        f"{previous_link}"
        f'<span class="page-indicator">Page {current_page} of {total_pages}</span>'
        f"{next_link}"
        "</div>"
        "</div>"
    )

    mine_checked = " checked" if filters.get("mine_only") == "1" else ""
    total_label = f"{total_count} entry" if total_count == 1 else f"{total_count} entries"
    filter_chips = render_filter_chip_bar(build_inventory_filter_chips(filters), "/inventory")
    return (
        '<section class="inventory-page">'
        '<div class="inventory-toolbar">'
        '<div class="inventory-toolbar-copy">'
        '<p class="eyebrow">Shared Records</p>'
        '<h3>Inventory</h3>'
        '<p class="lead">Browse, search, and manage submitted resources with a cleaner list-first workspace.</p>'
        f'<p class="muted small inventory-toolbar-note">{escape(total_label)} currently in the shared portal.</p>'
        '</div>'
        '<div class="inventory-toolbar-actions">'
        '<a class="btn btn-primary" href="/inventory/new">Add Entry</a>'
        f"{export_button}"
        f"{backup_button}"
        "</div>"
        "</div>"
        '<form method="get" action="/inventory" class="inventory-filter-form inventory-filter-form-flat">'
        '<div class="inventory-search-row">'
        '<label class="inventory-search-field">'
        "<span>Search</span>"
        f'<input type="text" name="search" value="{escape(filters.get("search", ""))}" placeholder="title, author, subject, category, remarks">'
        "</label>"
        '<div class="inventory-search-actions">'
        '<button class="btn btn-primary" type="submit">Search</button>'
        '<a class="btn btn-ghost" href="/inventory">Reset</a>'
        "</div>"
        "</div>"
        '<div class="filter-grid inventory-filter-grid-flat">'
        '<label><span>Grade Level</span><select name="grade_level"><option value="">All</option>'
        f'{render_options(GRADE_LEVELS, filters.get("grade_level", ""))}</select></label>'
        '<label><span>Program</span><select name="program"><option value="">All</option>'
        f'{render_options(PROGRAMS, filters.get("program", ""))}</select></label>'
        '<label><span>Subject</span><select name="subject"><option value="">All</option>'
        f'{render_options(SUBJECTS, filters.get("subject", ""))}</select></label>'
        '<label><span>Category</span><select name="category"><option value="">All</option>'
        f'{render_options(CATEGORIES, filters.get("category", ""))}</select></label>'
        '<label><span>Status</span><select name="status"><option value="">All</option>'
        f'{render_options(STATUS_OPTIONS, filters.get("status", ""))}</select></label>'
        '<label class="checkbox-row inventory-filter-check"><input type="checkbox" name="mine_only" value="1"'
        f"{mine_checked}>"
        "<span>Only show my entries</span>"
        "</label>"
        "</div>"
        "</form>"
        f"{filter_chips}"
        '<div class="table-shell inventory-table-shell">'
        '<table><thead><tr><th>Title</th><th>Author</th><th>Grade</th><th>Program</th><th>Subject</th><th>Date</th><th>Category</th><th>Status</th><th>Owner</th><th>Actions</th></tr></thead>'
        f"<tbody>{''.join(items_markup)}</tbody>"
        "</table>"
        "</div>"
        f"{pagination_markup}"
        "</section>"
    )


def render_users_page(connection, csrf_token, current_user_id):
    rows = connection.execute(
        """
        SELECT id, full_name, username, role, is_active, must_change_password, created_at, updated_at
        FROM users
        ORDER BY role ASC, full_name ASC
        """
    ).fetchall()

    markup = []
    for row in rows:
        status_text = "Active" if row["is_active"] else "Disabled"
        toggle_label = "Disable" if row["is_active"] else "Enable"
        action_markup = [
            '<div class="action-row">',
            f'<form method="post" action="/users/{row["id"]}/toggle">',
            f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">',
            f'<button class="btn btn-inline" type="submit">{escape(toggle_label)}</button>',
            "</form>",
        ]
        if row["id"] != current_user_id:
            action_markup.append(f'<a class="btn btn-inline btn-ghost" href="/users/{row["id"]}/reset-password">Reset Password</a>')
        else:
            action_markup.append('<span class="muted small">Use Account page</span>')
        action_markup.append("</div>")
        markup.append(
            "<tr>"
            f"<td>{escape(row['full_name'])}</td>"
            f"<td>{escape(row['username'])}</td>"
            f'<td><span class="pill {role_class(row["role"])}">{escape(row["role"].title())}</span></td>'
            f"<td>{escape(status_text)}</td>"
            f"<td>{'Yes' if row['must_change_password'] else 'No'}</td>"
            f"<td>{escape(human_time(row['updated_at']))}</td>"
            f"<td>{''.join(action_markup)}</td>"
            "</tr>"
        )

    if not markup:
        markup.append('<tr><td colspan="7" class="empty-state">No users have been created yet.</td></tr>')

    return (
        '<section class="card people-stage">'
        '<div class="card-header split">'
        '<div><h3>User Access</h3><p class="muted small">Create teacher accounts, keep access current, and force password changes for safer shared use.</p></div>'
        '<a class="btn btn-primary" href="/users/new">Create User</a>'
        "</div>"
        '<div class="table-shell">'
        '<table><thead><tr><th>Name</th><th>Username</th><th>Role</th><th>Status</th><th>Must Change Password</th><th>Updated</th><th>Actions</th></tr></thead>'
        f"<tbody>{''.join(markup)}</tbody></table>"
        "</div>"
        "</section>"
    )


def render_new_user_page(csrf_token, values, errors):
    role_value = values.get("role", ROLE_TEACHER)
    return (
        '<section class="card form-card people-editor-stage">'
        '<div class="card-header"><h3>Create Portal User</h3><p class="muted small">Give teachers controlled access without sharing the manager account.</p></div>'
        f"{render_form_errors(errors)}"
        '<form method="post" action="/users/new" class="form-grid">'
        f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
        '<label>'
        "<span>Full Name</span>"
        f'<input type="text" name="full_name" maxlength="80" value="{escape(values.get("full_name", ""))}" required>'
        "</label>"
        '<label>'
        "<span>Username</span>"
        f'<input type="text" name="username" maxlength="30" value="{escape(values.get("username", ""))}" required>'
        "</label>"
        '<label>'
        "<span>Role</span>"
        f'<select name="role"><option value="{ROLE_TEACHER}"{" selected" if role_value == ROLE_TEACHER else ""}>Teacher</option><option value="{ROLE_MANAGER}"{" selected" if role_value == ROLE_MANAGER else ""}>Manager</option></select>'
        "</label>"
        '<label>'
        "<span>Temporary Password</span>"
        '<input type="password" name="password" minlength="10" required>'
        "</label>"
        '<div class="span-2 form-actions">'
        '<button class="btn btn-primary" type="submit">Create User</button>'
        '<a class="btn btn-ghost" href="/users">Back to Users</a>'
        "</div>"
        "</form>"
        "</section>"
    )


def render_reset_user_password_page(csrf_token, target_user, errors):
    return (
        '<section class="card form-card people-editor-stage">'
        '<div class="card-header">'
        f'<h3>Reset Password for {escape(target_user["full_name"])}</h3>'
        f'<p class="muted small">Set a temporary password for @{escape(target_user["username"])}. The user will be forced to change it at the next login.</p>'
        "</div>"
        f"{render_form_errors(errors)}"
        f'<form method="post" action="/users/{target_user["id"]}/reset-password" class="form-grid">'
        f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
        '<label>'
        "<span>Temporary Password</span>"
        '<input type="password" name="password" minlength="10" required>'
        "</label>"
        '<div class="span-2 form-actions">'
        '<button class="btn btn-primary" type="submit">Reset Password</button>'
        '<a class="btn btn-ghost" href="/users">Back to Users</a>'
        "</div>"
        "</form>"
        "</section>"
    )


def render_audit_page(connection, filters):
    actor_rows = connection.execute(
        """
        SELECT id, full_name
        FROM users
        ORDER BY full_name ASC
        """
    ).fetchall()
    actor_lookup = {str(row["id"]): row["full_name"] for row in actor_rows}
    where_sql, params = build_audit_query(filters)
    total_count = connection.execute(
        f"""
        SELECT COUNT(*) AS total
        FROM activity_logs
        LEFT JOIN users ON users.id = activity_logs.user_id
        {where_sql}
        """,
        params,
    ).fetchone()["total"]
    current_page = safe_page_number(filters.get("page", "1"))
    total_pages = max(1, (total_count + AUDIT_PAGE_SIZE - 1) // AUDIT_PAGE_SIZE)
    if current_page > total_pages:
        current_page = total_pages
    offset = (current_page - 1) * AUDIT_PAGE_SIZE
    rows = connection.execute(
        f"""
        SELECT activity_logs.*, users.full_name
        FROM activity_logs
        LEFT JOIN users ON users.id = activity_logs.user_id
        {where_sql}
        ORDER BY activity_logs.created_at DESC, activity_logs.id DESC
        LIMIT ? OFFSET ?
        """,
        [*params, AUDIT_PAGE_SIZE, offset],
    ).fetchall()
    markup = []
    for row in rows:
        markup.append(
            "<tr>"
            f"<td>{escape(human_date(row['created_at']))}</td>"
            f"<td>{escape(human_clock(row['created_at']))}</td>"
            f"<td>{escape(row['full_name'] or 'System')}</td>"
            f"<td>{escape(row['action'])}</td>"
            f"<td>{escape(row['details'])}</td>"
            f"<td>{escape(row['ip_address'] or '-')}</td>"
            "</tr>"
        )
    if not markup:
        markup.append('<tr><td colspan="6" class="empty-state">No activity logs yet.</td></tr>')
    previous_link = (
        f'<a class="btn btn-ghost" href="{build_audit_url(filters, current_page - 1)}">Previous</a>'
        if current_page > 1
        else '<span class="btn btn-ghost btn-disabled">Previous</span>'
    )
    next_link = (
        f'<a class="btn btn-ghost" href="{build_audit_url(filters, current_page + 1)}">Next</a>'
        if current_page < total_pages
        else '<span class="btn btn-ghost btn-disabled">Next</span>'
    )
    filter_chips = render_filter_chip_bar(build_audit_filter_chips(filters, actor_lookup), "/audit")
    start_number = offset + 1 if total_count else 0
    end_number = min(offset + AUDIT_PAGE_SIZE, total_count)
    total_label = f"{total_count} log entry" if total_count == 1 else f"{total_count} log entries"
    return (
        '<section class="inventory-page audit-page">'
        '<div class="inventory-toolbar">'
        '<div class="inventory-toolbar-copy">'
        '<p class="eyebrow">Activity History</p>'
        '<h3>Audit Log</h3>'
        '<p class="lead">Review sign-ins, edits, backups, and account actions with cleaner filtering when you need to trace what happened.</p>'
        f'<p class="muted small inventory-toolbar-note">{escape(total_label)} currently available.</p>'
        '</div>'
        '<div class="inventory-toolbar-actions">'
        '<a class="btn btn-ghost" href="/backups">Backups</a>'
        '</div>'
        '</div>'
        '<form method="get" action="/audit" class="inventory-filter-form inventory-filter-form-flat">'
        '<div class="inventory-search-row">'
        '<label class="inventory-search-field">'
        '<span>Search</span>'
        f'<input type="text" name="search" value="{escape(filters.get("search", ""))}" placeholder="action, details, user, or IP">'
        '</label>'
        '<div class="inventory-search-actions">'
        '<button class="btn btn-primary" type="submit">Filter</button>'
        '<a class="btn btn-ghost" href="/audit">Reset</a>'
        '</div>'
        '</div>'
        '<div class="filter-grid inventory-filter-grid-flat audit-filter-grid">'
        '<label><span>Scope</span><select name="scope">'
        f'{render_named_options(AUDIT_SCOPE_OPTIONS, filters.get("scope", ""))}</select></label>'
        '<label><span>User</span><select name="actor"><option value="">All users</option>'
        f'{render_named_options([(str(row["id"]), row["full_name"]) for row in actor_rows], filters.get("actor", ""))}</select></label>'
        '</div>'
        '</form>'
        f"{filter_chips}"
        '<div class="table-shell inventory-table-shell">'
        '<table><thead><tr><th>Date</th><th>Time</th><th>User</th><th>Action</th><th>Details</th><th>IP</th></tr></thead>'
        f"<tbody>{''.join(markup)}</tbody></table>"
        "</div>"
        '<div class="pagination-row">'
        f'<p class="results-meta">Showing {start_number}-{end_number} of {total_count} logs</p>'
        '<div class="pagination-actions">'
        f"{previous_link}"
        f'<span class="page-indicator">Page {current_page} of {total_pages}</span>'
        f"{next_link}"
        "</div>"
        "</div>"
        '</section>'
    )


def render_backups_page(csrf_token):
    backups = list_database_backups()
    rows = []
    for backup in backups:
        rows.append(
            "<tr>"
            f"<td><strong>{escape(backup['name'])}</strong><div class=\"muted small\">{escape(relative_display_path(BACKUP_DIR / backup['name']))}</div></td>"
            f"<td>{escape(backup['created_at'])}</td>"
            f"<td>{escape(backup['size'])}</td>"
            "<td>"
            '<form method="post" action="/backups/restore" class="inline-form" data-confirm="Restore this backup? A safeguard copy of the current database will be created first.">'
            f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
            f'<input type="hidden" name="backup_name" value="{escape(backup["name"])}">'
            '<button class="btn btn-inline btn-secondary" type="submit">Restore</button>'
            "</form>"
            "</td>"
            "</tr>"
        )
    if not rows:
        rows.append('<tr><td colspan="4" class="empty-state">No backups yet. Create one before larger changes or imports.</td></tr>')

    return (
        '<section class="inventory-page backups-page">'
        '<div class="inventory-toolbar">'
        '<div class="inventory-toolbar-copy">'
        '<p class="eyebrow">Recovery Tools</p>'
        '<h3>Backups</h3>'
        '<p class="lead">Create a fresh backup before imports or major edits, then restore older snapshots if you need to roll the portal back.</p>'
        '<p class="muted small inventory-toolbar-note">Every restore creates a safeguard copy of the current database first.</p>'
        '</div>'
        '<div class="inventory-toolbar-actions">'
        '<form method="post" action="/backup">'
        f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
        '<button class="btn btn-primary" type="submit">Create Backup</button>'
        '</form>'
        '<a class="btn btn-ghost" href="/inventory">Back to Inventory</a>'
        '</div>'
        '</div>'
        '<div class="notice-card backups-note"><strong>Restore carefully.</strong> Restoring replaces the live database for everyone currently using the portal.</div>'
        '<div class="table-shell inventory-table-shell">'
        '<table><thead><tr><th>Backup File</th><th>Saved</th><th>Size</th><th>Action</th></tr></thead>'
        f"<tbody>{''.join(rows)}</tbody></table>"
        "</div>"
        '</section>'
    )


def render_password_page(csrf_token, errors, force_change):
    notice = (
        '<div class="notice-card warning"><strong>Password update required.</strong> This account is still using a temporary or default password.</div>'
        if force_change
        else ""
    )
    return (
        '<section class="card form-card account-stage">'
        '<div class="card-header"><h3>Change Password</h3><p class="muted small">Use a strong password before sharing the portal more widely.</p></div>'
        f"{notice}"
        f"{render_form_errors(errors)}"
        '<form method="post" action="/account/password" class="form-grid">'
        f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
        '<label><span>Current Password</span><input type="password" name="current_password" required></label>'
        '<label><span>New Password</span><input type="password" name="new_password" minlength="10" required></label>'
        '<label><span>Confirm New Password</span><input type="password" name="confirm_password" minlength="10" required></label>'
        '<div class="span-2 form-actions"><button class="btn btn-primary" type="submit">Update Password</button></div>'
        "</form>"
        "</section>"
    )


def parse_form_body(handler):
    length = int(handler.headers.get("Content-Length", "0") or "0")
    raw = handler.rfile.read(length) if length else b""
    content_type = handler.headers.get("Content-Type", "")

    if content_type.startswith("multipart/form-data"):
        message = BytesParser(policy=default_email_policy).parsebytes(
            f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8") + raw
        )
        if not message.is_multipart():
            return {}, {}
        form_values = {}
        form_files = {}
        for part in message.iter_parts():
            if part.get_content_disposition() != "form-data":
                continue
            field_name = part.get_param("name", header="content-disposition")
            if not field_name:
                continue

            payload = part.get_payload(decode=True) or b""
            filename = part.get_filename()
            if filename is not None:
                form_files[field_name] = {
                    "filename": filename,
                    "content_type": part.get_content_type(),
                    "content": payload,
                }
                continue

            charset = part.get_content_charset() or "utf-8"
            form_values[field_name] = payload.decode(charset, errors="replace")
        return form_values, form_files

    parsed = parse_qs(raw.decode("utf-8"), keep_blank_values=True) if raw else {}
    return {key: values[0] for key, values in parsed.items()}, {}


def ensure_csrf(form_values, session):
    return bool(session and form_values.get("csrf_token") == session["csrf_token"])


def get_filters(query_string):
    parsed = parse_qs(query_string)
    return {
        "search": parsed.get("search", [""])[0],
        "grade_level": parsed.get("grade_level", [""])[0],
        "program": parsed.get("program", [""])[0],
        "subject": parsed.get("subject", [""])[0],
        "category": parsed.get("category", [""])[0],
        "status": parsed.get("status", [""])[0],
        "mine_only": parsed.get("mine_only", [""])[0],
        "page": parsed.get("page", ["1"])[0],
    }


def get_audit_filters(query_string):
    parsed = parse_qs(query_string)
    return {
        "search": parsed.get("search", [""])[0],
        "scope": parsed.get("scope", [""])[0],
        "actor": parsed.get("actor", [""])[0],
        "page": parsed.get("page", ["1"])[0],
    }


def create_user(connection, full_name, username, password, role):
    now = utc_now()
    connection.execute(
        """
        INSERT INTO users (
            full_name, username, password_hash, role, is_active, must_change_password,
            failed_attempts, locked_until, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, 1, 1, 0, NULL, ?, ?)
        """,
        (full_name, username, hash_password(password), role, now, now),
    )


def validate_user_form(connection, raw_values):
    values = {
        "full_name": raw_values.get("full_name", "").strip(),
        "username": raw_values.get("username", "").strip(),
        "role": raw_values.get("role", ROLE_TEACHER).strip(),
    }
    password = raw_values.get("password", "")
    errors = []

    if not values["full_name"]:
        errors.append("Full name is required.")
    if len(values["full_name"]) > 80:
        errors.append("Full name must stay under 80 characters.")
    clean_name = clean_username(values["username"])
    if not clean_name:
        errors.append("Username must be 3-30 characters and use only letters, numbers, dots, hyphens, or underscores.")
    else:
        values["username"] = clean_name
        if get_user_by_username(connection, clean_name):
            errors.append("That username is already in use.")
    if values["role"] not in (ROLE_TEACHER, ROLE_MANAGER):
        errors.append("Role is invalid.")

    password_error = password_strength_error(password)
    if password_error:
        errors.append(password_error)

    return values, password, errors


def can_edit_item(user, item_row):
    return user["role"] == ROLE_MANAGER or item_row["created_by"] == user["id"]


def render_not_found():
    return (
        '<section class="card">'
        '<div class="card-header"><h3>Page Not Found</h3></div>'
        '<p class="muted">The page you requested does not exist.</p>'
        '<a class="btn btn-primary" href="/dashboard">Back to Dashboard</a>'
        "</section>"
    )


class InventoryPortalHandler(BaseHTTPRequestHandler):
    server_version = "InventoryPortal/1.0"

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/static/portal.css":
            return self.serve_static_css()
        if path.startswith("/media/"):
            return self.serve_media(path.removeprefix("/media/"))
        if path == "/health":
            return self.send_text(200, "OK")

        session_id, session, user = self.get_auth_context()
        if path in ("/", "/login"):
            if user:
                return self.redirect("/dashboard")
            return self.send_html(200, render_login_page())

        if not user:
            return self.redirect("/login")
        if user["must_change_password"] and path != "/account/password":
            self.set_flash(session_id, "warning", "Change your temporary password before continuing.")
            return self.redirect("/account/password")

        flash = self.pop_flash(session_id)
        csrf_token = session["csrf_token"]

        if path == "/dashboard":
            with get_connection() as connection:
                body = render_dashboard(connection, user, csrf_token)
            return self.send_html(200, render_layout("Dashboard", user, body, "dashboard", csrf_token, flash))

        if path == "/inventory":
            filters = get_filters(parsed.query)
            with get_connection() as connection:
                body = render_inventory_page(connection, user, csrf_token, filters)
            return self.send_html(200, render_layout("Inventory", user, body, "inventory", csrf_token, flash))

        if path == "/inventory/new":
            body = render_item_form(user, csrf_token, base_item_values(), [], "new")
            return self.send_html(200, render_layout("Add Entry", user, body, "new-item", csrf_token, flash))

        attachment_match = re.fullmatch(r"/inventory/(\d+)/attachment", path)
        if attachment_match:
            return self.handle_item_attachment(int(attachment_match.group(1)), user)

        item_match = re.fullmatch(r"/inventory/(\d+)", path)
        if item_match:
            item_id = int(item_match.group(1))
            with get_connection() as connection:
                item = connection.execute(
                    """
                    SELECT """
                    + INVENTORY_ITEM_SELECT_COLUMNS
                    + """, users.full_name AS owner_name
                    FROM inventory_items
                    JOIN users ON users.id = inventory_items.created_by
                    WHERE inventory_items.id = ?
                    """,
                    (item_id,),
                ).fetchone()
                if not item:
                    return self.send_html(404, render_layout("Not Found", user, render_not_found(), "inventory", csrf_token, flash))
                body = render_item_detail_page(connection, user, csrf_token, item)
            return self.send_html(200, render_layout("Resource Details", user, body, "inventory", csrf_token, flash))

        edit_match = re.fullmatch(r"/inventory/(\d+)/edit", path)
        if edit_match:
            item_id = int(edit_match.group(1))
            with get_connection() as connection:
                item = connection.execute("SELECT * FROM inventory_items WHERE id = ?", (item_id,)).fetchone()
            if not item:
                return self.send_html(404, render_layout("Not Found", user, render_not_found(), "inventory", csrf_token, flash))
            if not can_edit_item(user, item):
                return self.send_html(403, render_layout("Forbidden", user, self.render_forbidden("You cannot edit that item."), "inventory", csrf_token, flash))
            values = {
                "title": item["title"],
                "author": item["author"],
                "grade_level": item["grade_level"],
                "program": item["program"],
                "subject": item["subject"],
                "date_validated": item["date_validated"],
                "category": item["category"],
                "remarks": item["remarks"],
                "status": item["status"],
            }
            body = render_item_form(
                user,
                csrf_token,
                values,
                [],
                "edit",
                item_id=item_id,
                existing_attachment=build_attachment_info(item),
            )
            return self.send_html(200, render_layout("Edit Entry", user, body, "inventory", csrf_token, flash))

        if path == "/users":
            if user["role"] != ROLE_MANAGER:
                return self.send_html(403, render_layout("Forbidden", user, self.render_forbidden("Only managers can manage user accounts."), "dashboard", csrf_token, flash))
            with get_connection() as connection:
                body = render_users_page(connection, csrf_token, user["id"])
            return self.send_html(200, render_layout("Users", user, body, "users", csrf_token, flash))

        if path == "/users/new":
            if user["role"] != ROLE_MANAGER:
                return self.send_html(403, render_layout("Forbidden", user, self.render_forbidden("Only managers can create new users."), "dashboard", csrf_token, flash))
            body = render_new_user_page(csrf_token, {}, [])
            return self.send_html(200, render_layout("Create User", user, body, "users", csrf_token, flash))

        reset_password_match = re.fullmatch(r"/users/(\d+)/reset-password", path)
        if reset_password_match:
            if user["role"] != ROLE_MANAGER:
                return self.send_html(403, render_layout("Forbidden", user, self.render_forbidden("Only managers can reset user passwords."), "dashboard", csrf_token, flash))
            target_id = int(reset_password_match.group(1))
            if target_id == user["id"]:
                self.set_flash(session_id, "warning", "Use the Account page to change your own password.")
                return self.redirect("/account/password")
            with get_connection() as connection:
                target_user = connection.execute("SELECT * FROM users WHERE id = ?", (target_id,)).fetchone()
                if not target_user:
                    return self.send_html(404, render_layout("Not Found", user, render_not_found(), "users", csrf_token, flash))
                body = render_reset_user_password_page(csrf_token, target_user, [])
            return self.send_html(200, render_layout("Reset Password", user, body, "users", csrf_token, flash))

        if path == "/audit":
            if user["role"] != ROLE_MANAGER:
                return self.send_html(403, render_layout("Forbidden", user, self.render_forbidden("Only managers can access the audit log."), "dashboard", csrf_token, flash))
            filters = get_audit_filters(parsed.query)
            with get_connection() as connection:
                body = render_audit_page(connection, filters)
            return self.send_html(200, render_layout("Audit Log", user, body, "audit", csrf_token, flash))

        if path == "/backups":
            if user["role"] != ROLE_MANAGER:
                return self.send_html(403, render_layout("Forbidden", user, self.render_forbidden("Only managers can access backup tools."), "dashboard", csrf_token, flash))
            body = render_backups_page(csrf_token)
            return self.send_html(200, render_layout("Backups", user, body, "backups", csrf_token, flash))

        if path == "/account/password":
            body = render_password_page(csrf_token, [], bool(user["must_change_password"]))
            return self.send_html(200, render_layout("Account", user, body, "account", csrf_token, flash))

        if path == "/export.csv":
            if user["role"] != ROLE_MANAGER:
                return self.send_html(403, render_layout("Forbidden", user, self.render_forbidden("Only managers can export the shared inventory."), "inventory", csrf_token, flash))
            with get_connection() as connection:
                rows = connection.execute(
                    """
                    SELECT """
                    + INVENTORY_ITEM_SELECT_COLUMNS
                    + """, users.full_name AS owner_name
                    FROM inventory_items
                    JOIN users ON users.id = inventory_items.created_by
                    ORDER BY inventory_items.updated_at DESC, inventory_items.id DESC
                    """
                ).fetchall()
                csv_text = self.build_csv(rows)
                log_action(
                    connection,
                    user["id"],
                    "inventory.export",
                    "Exported the current shared inventory to CSV.",
                    None,
                    self.client_address[0],
                )
            return self.send_csv("shared_learning_inventory.csv", csv_text)

        return self.send_html(404, render_layout("Not Found", user, render_not_found(), "dashboard", csrf_token, flash))

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        session_id, session, user = self.get_auth_context()
        form_values, form_files = parse_form_body(self)

        if path == "/login":
            return self.handle_login(form_values)

        if not user:
            return self.redirect("/login")
        if not ensure_csrf(form_values, session):
            self.set_flash(session_id, "danger", "Security token expired. Please try again.")
            return self.redirect("/dashboard")

        if path == "/logout":
            destroy_session(session_id)
            self.expire_cookie(SESSION_COOKIE_NAME)
            return self.redirect("/login")

        if user["must_change_password"] and path != "/account/password":
            self.set_flash(session_id, "warning", "Change your temporary password before continuing.")
            return self.redirect("/account/password")

        if path == "/inventory/new":
            return self.handle_create_item(user, session, session_id, form_values, form_files)

        if path == "/backup":
            return self.handle_backup(user, session, session_id)

        if path == "/backups/restore":
            return self.handle_restore_backup(user, session, session_id, form_values)

        status_match = re.fullmatch(r"/inventory/(\d+)/status", path)
        if status_match:
            return self.handle_update_item_status(int(status_match.group(1)), user, session, session_id, form_values)

        edit_match = re.fullmatch(r"/inventory/(\d+)/edit", path)
        if edit_match:
            return self.handle_edit_item(int(edit_match.group(1)), user, session, session_id, form_values, form_files)

        delete_match = re.fullmatch(r"/inventory/(\d+)/delete", path)
        if delete_match:
            return self.handle_delete_item(int(delete_match.group(1)), user, session, session_id)

        if path == "/users/new":
            return self.handle_create_user(user, session, session_id, form_values)

        toggle_match = re.fullmatch(r"/users/(\d+)/toggle", path)
        if toggle_match:
            return self.handle_toggle_user(int(toggle_match.group(1)), user, session, session_id)

        reset_password_match = re.fullmatch(r"/users/(\d+)/reset-password", path)
        if reset_password_match:
            return self.handle_reset_user_password(int(reset_password_match.group(1)), user, session, session_id, form_values)

        if path == "/account/password":
            return self.handle_change_password(user, session, session_id, form_values)

        self.set_flash(session_id, "danger", "Unknown action.")
        return self.redirect("/dashboard")

    def get_auth_context(self):
        session_id = None
        session = None
        user = None
        cookie_header = self.headers.get("Cookie", "")
        if cookie_header:
            jar = cookies.SimpleCookie()
            jar.load(cookie_header)
            if SESSION_COOKIE_NAME in jar:
                session_id = jar[SESSION_COOKIE_NAME].value
        session = get_session(session_id)
        if session:
            with get_connection() as connection:
                user = get_user_by_id(connection, session["user_id"])
        if user and not user["is_active"]:
            destroy_session(session_id)
            user = None
            session = None
        return session_id, session, user

    def handle_item_attachment(self, item_id, user):
        with get_connection() as connection:
            item = connection.execute(
                """
                SELECT id, title, attachment_name, attachment_content_type, attachment_blob
                FROM inventory_items
                WHERE id = ?
                """,
                (item_id,),
            ).fetchone()
        if not item:
            return self.send_text(404, "Attachment item not found.")
        if not item["attachment_name"] or item["attachment_blob"] is None:
            return self.send_text(404, "No attachment found for this item.")

        content_type = item["attachment_content_type"] or mimetypes.guess_type(item["attachment_name"])[0] or "application/octet-stream"
        headers = {"Content-Disposition": build_content_disposition(item["attachment_name"])}
        return self.send_response_with_body(200, item["attachment_blob"], content_type, headers)

    def handle_login(self, form_values):
        username = clean_username(form_values.get("username", "") or "")
        password = form_values.get("password", "")
        if not username or not password:
            return self.send_html(200, render_login_page("Enter both username and password.", form_values.get("username", "")))

        with get_connection() as connection:
            user = get_user_by_username(connection, username)
            if not user:
                return self.send_html(200, render_login_page("Invalid username or password.", form_values.get("username", "")))
            if not user["is_active"]:
                return self.send_html(200, render_login_page("This account has been disabled. Contact the LRMDS manager.", form_values.get("username", "")))
            if user["locked_until"]:
                locked_until = datetime.fromisoformat(user["locked_until"])
                if locked_until > datetime.utcnow():
                    return self.send_html(200, render_login_page("Too many login attempts. Try again later.", form_values.get("username", "")))

            if not verify_password(password, user["password_hash"]):
                failed = user["failed_attempts"] + 1
                locked_until = None
                if failed >= 5:
                    failed = 0
                    locked_until = (datetime.utcnow() + timedelta(minutes=15)).replace(microsecond=0).isoformat()
                connection.execute(
                    "UPDATE users SET failed_attempts = ?, locked_until = ?, updated_at = ? WHERE id = ?",
                    (failed, locked_until, utc_now(), user["id"]),
                )
                log_action(
                    connection,
                    user["id"],
                    "auth.failed_login",
                    "Failed sign-in attempt.",
                    None,
                    self.client_address[0],
                )
                return self.send_html(200, render_login_page("Invalid username or password.", form_values.get("username", "")))

            connection.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?",
                (utc_now(), user["id"]),
            )
            log_action(
                connection,
                user["id"],
                "auth.login",
                "Signed into the portal.",
                None,
                self.client_address[0],
            )

        session_id, _session = create_session(user["id"])
        self.set_cookie(SESSION_COOKIE_NAME, session_id)
        return self.redirect("/dashboard")

    def handle_create_item(self, user, session, session_id, form_values, form_files):
        values, errors = validate_item_form(form_values, user)
        attachment, attachment_errors = validate_attachment_upload(form_files)
        errors.extend(attachment_errors)
        if errors:
            body = render_item_form(user, session["csrf_token"], values, errors, "new")
            return self.send_html(200, render_layout("Add Entry", user, body, "new-item", session["csrf_token"]))

        now = utc_now()
        with get_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO inventory_items (
                    title, author, grade_level, program, subject, date_validated,
                    category, remarks, status, attachment_name, attachment_content_type,
                    attachment_size, attachment_blob, created_by, updated_by, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    values["title"],
                    values["author"],
                    values["grade_level"],
                    values["program"],
                    values["subject"],
                    values["date_validated"],
                    values["category"],
                    values["remarks"],
                    values["status"] if user["role"] == ROLE_MANAGER else ITEM_STATUS_PENDING,
                    attachment["name"] if attachment else None,
                    attachment["content_type"] if attachment else None,
                    attachment["size"] if attachment else None,
                    attachment["content"] if attachment else None,
                    user["id"],
                    user["id"],
                    now,
                    now,
                ),
            )
            log_action(
                connection,
                user["id"],
                "inventory.create",
                (
                    f'Created inventory item "{values["title"]}" with attachment "{attachment["name"]}".'
                    if attachment
                    else f'Created inventory item "{values["title"]}".'
                ),
                cursor.lastrowid,
                self.client_address[0],
            )
        self.set_flash(session_id, "success", "Inventory entry saved to the shared portal.")
        return self.redirect("/inventory")

    def handle_edit_item(self, item_id, user, session, session_id, form_values, form_files):
        with get_connection() as connection:
            item = connection.execute("SELECT * FROM inventory_items WHERE id = ?", (item_id,)).fetchone()
            if not item:
                self.set_flash(session_id, "danger", "The inventory item was not found.")
                return self.redirect("/inventory")
            if not can_edit_item(user, item):
                return self.send_html(403, render_layout("Forbidden", user, self.render_forbidden("You cannot edit that item."), "inventory", session["csrf_token"]))

            values, errors = validate_item_form(form_values, user, is_edit=True)
            attachment, attachment_errors = validate_attachment_upload(form_files)
            errors.extend(attachment_errors)
            if errors:
                values["status"] = item["status"] if user["role"] != ROLE_MANAGER else values["status"]
                body = render_item_form(
                    user,
                    session["csrf_token"],
                    values,
                    errors,
                    "edit",
                    item_id=item_id,
                    existing_attachment=build_attachment_info(item),
                )
                return self.send_html(200, render_layout("Edit Entry", user, body, "inventory", session["csrf_token"]))

            status_value = values["status"] if user["role"] == ROLE_MANAGER else ITEM_STATUS_PENDING
            remove_attachment = form_values.get("remove_attachment") == "1"
            attachment_name = item["attachment_name"]
            attachment_content_type = item["attachment_content_type"]
            attachment_size = item["attachment_size"]
            attachment_blob = item["attachment_blob"]
            attachment_note = ""
            if attachment:
                attachment_name = attachment["name"]
                attachment_content_type = attachment["content_type"]
                attachment_size = attachment["size"]
                attachment_blob = attachment["content"]
                attachment_note = f' Replaced attachment with "{attachment["name"]}".'
            elif remove_attachment and item["attachment_name"]:
                attachment_name = None
                attachment_content_type = None
                attachment_size = None
                attachment_blob = None
                attachment_note = " Removed the attachment."
            connection.execute(
                """
                UPDATE inventory_items
                SET title = ?, author = ?, grade_level = ?, program = ?, subject = ?,
                    date_validated = ?, category = ?, remarks = ?, status = ?,
                    attachment_name = ?, attachment_content_type = ?, attachment_size = ?, attachment_blob = ?,
                    updated_by = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    values["title"],
                    values["author"],
                    values["grade_level"],
                    values["program"],
                    values["subject"],
                    values["date_validated"],
                    values["category"],
                    values["remarks"],
                    status_value,
                    attachment_name,
                    attachment_content_type,
                    attachment_size,
                    attachment_blob,
                    user["id"],
                    utc_now(),
                    item_id,
                ),
            )
            log_action(
                connection,
                user["id"],
                "inventory.update",
                (
                    f'Updated inventory item "{values["title"]}".'
                    if user["role"] == ROLE_MANAGER
                    else f'Updated inventory item "{values["title"]}" and returned it for manager review.'
                )
                + attachment_note,
                item_id,
                self.client_address[0],
            )

        flash_message = (
            "Inventory entry updated."
            if user["role"] == ROLE_MANAGER
            else "Inventory entry updated and sent back for manager review."
        )
        self.set_flash(session_id, "success", flash_message)
        return self.redirect("/inventory")

    def handle_update_item_status(self, item_id, user, session, session_id, form_values):
        if user["role"] != ROLE_MANAGER:
            return self.send_html(403, render_layout("Forbidden", user, self.render_forbidden("Only managers can update review status."), "inventory", session["csrf_token"]))

        status_value = form_values.get("status", "").strip()
        if status_value not in STATUS_OPTIONS:
            self.set_flash(session_id, "danger", "That review status is invalid.")
            return self.redirect(f"/inventory/{item_id}")

        with get_connection() as connection:
            item = connection.execute("SELECT * FROM inventory_items WHERE id = ?", (item_id,)).fetchone()
            if not item:
                self.set_flash(session_id, "danger", "The inventory item was not found.")
                return self.redirect("/inventory")

            connection.execute(
                "UPDATE inventory_items SET status = ?, updated_by = ?, updated_at = ? WHERE id = ?",
                (status_value, user["id"], utc_now(), item_id),
            )
            log_action(
                connection,
                user["id"],
                "inventory.status_update",
                f'Changed status for "{item["title"]}" to {status_value}.',
                item_id,
                self.client_address[0],
            )

        self.set_flash(session_id, "success", f"Status updated to {status_value}.")
        return self.redirect(f"/inventory/{item_id}")

    def handle_delete_item(self, item_id, user, session, session_id):
        if user["role"] != ROLE_MANAGER:
            return self.send_html(403, render_layout("Forbidden", user, self.render_forbidden("Only managers can delete inventory items."), "inventory", session["csrf_token"]))
        with get_connection() as connection:
            item = connection.execute("SELECT * FROM inventory_items WHERE id = ?", (item_id,)).fetchone()
            if not item:
                self.set_flash(session_id, "danger", "The inventory item was not found.")
                return self.redirect("/inventory")
            connection.execute("DELETE FROM inventory_items WHERE id = ?", (item_id,))
            log_action(
                connection,
                user["id"],
                "inventory.delete",
                f'Deleted inventory item "{item["title"]}".',
                item_id,
                self.client_address[0],
            )
        self.set_flash(session_id, "success", "Inventory entry deleted.")
        return self.redirect("/inventory")

    def handle_create_user(self, user, session, session_id, form_values):
        if user["role"] != ROLE_MANAGER:
            return self.send_html(403, render_layout("Forbidden", user, self.render_forbidden("Only managers can create new users."), "dashboard", session["csrf_token"]))

        with get_connection() as connection:
            values, password, errors = validate_user_form(connection, form_values)
            if errors:
                body = render_new_user_page(session["csrf_token"], values, errors)
                return self.send_html(200, render_layout("Create User", user, body, "users", session["csrf_token"]))

            create_user(connection, values["full_name"], values["username"], password, values["role"])
            created = get_user_by_username(connection, values["username"])
            log_action(
                connection,
                user["id"],
                "users.create",
                f'Created {values["role"]} account "{values["username"]}".',
                None,
                self.client_address[0],
            )
            if created:
                log_action(
                    connection,
                    created["id"],
                    "users.password_temp",
                    "A temporary password was assigned and must be changed on first login.",
                    None,
                    self.client_address[0],
                )

        self.set_flash(session_id, "success", "Portal user created with a temporary password.")
        return self.redirect("/users")

    def handle_toggle_user(self, user_id, user, session, session_id):
        if user["role"] != ROLE_MANAGER:
            return self.send_html(403, render_layout("Forbidden", user, self.render_forbidden("Only managers can update user access."), "dashboard", session["csrf_token"]))
        if user_id == user["id"]:
            self.set_flash(session_id, "danger", "You cannot disable your own account while signed in.")
            return self.redirect("/users")

        with get_connection() as connection:
            target = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if not target:
                self.set_flash(session_id, "danger", "User account not found.")
                return self.redirect("/users")

            new_active = 0 if target["is_active"] else 1
            if target["role"] == ROLE_MANAGER and new_active == 0:
                active_managers = connection.execute(
                    "SELECT COUNT(*) AS total FROM users WHERE role = ? AND is_active = 1",
                    (ROLE_MANAGER,),
                ).fetchone()["total"]
                if active_managers <= 1:
                    self.set_flash(session_id, "danger", "At least one active manager account must remain available.")
                    return self.redirect("/users")

            connection.execute(
                "UPDATE users SET is_active = ?, updated_at = ? WHERE id = ?",
                (new_active, utc_now(), user_id),
            )
            action_text = "enabled" if new_active else "disabled"
            log_action(
                connection,
                user["id"],
                "users.toggle",
                f'{action_text.title()} account "{target["username"]}".',
                None,
                self.client_address[0],
            )

        self.set_flash(session_id, "success", "User access updated.")
        return self.redirect("/users")

    def handle_reset_user_password(self, user_id, user, session, session_id, form_values):
        if user["role"] != ROLE_MANAGER:
            return self.send_html(403, render_layout("Forbidden", user, self.render_forbidden("Only managers can reset user passwords."), "dashboard", session["csrf_token"]))
        if user_id == user["id"]:
            self.set_flash(session_id, "warning", "Use the Account page to change your own password.")
            return self.redirect("/account/password")

        password = form_values.get("password", "")
        errors = []
        password_error = password_strength_error(password)
        if password_error:
            errors.append(password_error)

        with get_connection() as connection:
            target_user = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if not target_user:
                self.set_flash(session_id, "danger", "User account not found.")
                return self.redirect("/users")

            if errors:
                body = render_reset_user_password_page(session["csrf_token"], target_user, errors)
                return self.send_html(200, render_layout("Reset Password", user, body, "users", session["csrf_token"]))

            connection.execute(
                """
                UPDATE users
                SET password_hash = ?, must_change_password = 1, failed_attempts = 0,
                    locked_until = NULL, updated_at = ?
                WHERE id = ?
                """,
                (hash_password(password), utc_now(), user_id),
            )
            log_action(
                connection,
                user["id"],
                "users.reset_password",
                f'Reset password for account "{target_user["username"]}".',
                None,
                self.client_address[0],
            )

        self.set_flash(session_id, "success", "Temporary password set. The user must change it after login.")
        return self.redirect("/users")

    def handle_change_password(self, user, session, session_id, form_values):
        current_password = form_values.get("current_password", "")
        new_password = form_values.get("new_password", "")
        confirm_password = form_values.get("confirm_password", "")
        errors = []
        should_remove_setup_note = False

        with get_connection() as connection:
            current_user = get_user_by_id(connection, user["id"])
            if not verify_password(current_password, current_user["password_hash"]):
                errors.append("Current password is incorrect.")
            password_error = password_strength_error(new_password)
            if password_error:
                errors.append(password_error)
            if new_password != confirm_password:
                errors.append("New password and confirmation do not match.")
            if current_password == new_password:
                errors.append("New password must be different from the current password.")

            if errors:
                body = render_password_page(session["csrf_token"], errors, bool(current_user["must_change_password"]))
                return self.send_html(200, render_layout("Account", current_user, body, "account", session["csrf_token"]))

            connection.execute(
                """
                UPDATE users
                SET password_hash = ?, must_change_password = 0, updated_at = ?
                WHERE id = ?
                """,
                (hash_password(new_password), utc_now(), user["id"]),
            )
            should_remove_setup_note = (
                current_user["role"] == ROLE_MANAGER
                and current_user["username"] == DEFAULT_MANAGER_USERNAME
                and current_user["must_change_password"]
            )
            log_action(
                connection,
                user["id"],
                "users.change_password",
                "Changed account password.",
                None,
                self.client_address[0],
            )
        if should_remove_setup_note:
            remove_manager_setup_note()
        self.set_flash(session_id, "success", "Password updated successfully.")
        return self.redirect("/dashboard")

    def handle_backup(self, user, session, session_id):
        if user["role"] != ROLE_MANAGER:
            return self.send_html(403, render_layout("Forbidden", user, self.render_forbidden("Only managers can create database backups."), "dashboard", session["csrf_token"]))
        with get_connection() as connection:
            backup_path = create_database_backup()
            log_action(
                connection,
                user["id"],
                "system.backup",
                f'Created database backup at "{relative_display_path(backup_path)}".',
                None,
                self.client_address[0],
            )
        self.set_flash(session_id, "success", f'Backup created: {relative_display_path(backup_path)}')
        return self.redirect("/backups")

    def handle_restore_backup(self, user, session, session_id, form_values):
        if user["role"] != ROLE_MANAGER:
            return self.send_html(403, render_layout("Forbidden", user, self.render_forbidden("Only managers can restore database backups."), "dashboard", session["csrf_token"]))

        backup_name = form_values.get("backup_name", "").strip()
        if not backup_name:
            self.set_flash(session_id, "danger", "Choose a backup to restore.")
            return self.redirect("/backups")

        try:
            safeguard_path = create_database_backup(prefix="inventory_backup_before_restore")
            restored_path = restore_database_backup(backup_name)
        except FileNotFoundError:
            self.set_flash(session_id, "danger", "That backup file could not be found.")
            return self.redirect("/backups")
        except sqlite3.Error:
            self.set_flash(session_id, "danger", "Backup restore failed. The current database was left in place.")
            return self.redirect("/backups")

        restored_user = None
        with get_connection() as connection:
            restored_user = get_user_by_username(connection, user["username"])
            if not restored_user or not restored_user["is_active"]:
                restored_user = connection.execute(
                    """
                    SELECT *
                    FROM users
                    WHERE role = ? AND is_active = 1
                    ORDER BY id ASC
                    LIMIT 1
                    """,
                    (ROLE_MANAGER,),
                ).fetchone()
            log_action(
                connection,
                restored_user["id"] if restored_user else None,
                "system.restore",
                (
                    f'Restored database from "{relative_display_path(restored_path)}" '
                    f'after creating safeguard backup "{relative_display_path(safeguard_path)}".'
                ),
                None,
                self.client_address[0],
            )

        if restored_user:
            new_session_id, _session = create_session(restored_user["id"])
            self.set_cookie(SESSION_COOKIE_NAME, new_session_id)
            self.set_flash(
                new_session_id,
                "success",
                f'Restored {restored_path.name}. A safeguard copy was saved as {safeguard_path.name}.',
            )
            return self.redirect("/backups")

        self.expire_cookie(SESSION_COOKIE_NAME)
        return self.send_html(200, render_login_page("Backup restored. Sign in again to continue."))

    def render_forbidden(self, message):
        return (
            '<section class="card">'
            '<div class="card-header"><h3>Access Restricted</h3></div>'
            f'<p class="muted">{escape(message)}</p>'
            '<a class="btn btn-primary" href="/dashboard">Back to Dashboard</a>'
            "</section>"
        )

    def serve_static_css(self):
        css_path = STATIC_DIR / "portal.css"
        if not css_path.exists():
            return self.send_text(404, "Missing CSS")
        content = css_path.read_text(encoding="utf-8")
        return self.send_response_with_body(200, content.encode("utf-8"), "text/css; charset=utf-8")

    def serve_media(self, media_key):
        media_path = MEDIA_ROUTES.get(media_key)
        if not media_path or not media_path.exists():
            return self.send_text(404, "Missing media")
        content_type = mimetypes.guess_type(media_path.name)[0] or "application/octet-stream"
        return self.send_response_with_body(200, media_path.read_bytes(), content_type)

    def build_csv(self, rows):
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            [
                "Title",
                "Author/Writer",
                "Grade Level",
                "Program",
                "Subject",
                "Date Validated",
                "Category",
                "Attachment",
                "Remarks",
                "Status",
                "Submitted By",
                "Created At",
                "Updated At",
            ]
        )
        for row in rows:
            writer.writerow(
                [
                    row["title"],
                    row["author"],
                    row["grade_level"],
                    row["program"],
                    row["subject"],
                    row["date_validated"],
                    row["category"],
                    row["attachment_name"] or "",
                    row["remarks"],
                    row["status"],
                    row["owner_name"],
                    row["created_at"],
                    row["updated_at"],
                ]
            )
        return buffer.getvalue()

    def send_html(self, status_code, content):
        return self.send_response_with_body(status_code, content.encode("utf-8"), "text/html; charset=utf-8")

    def send_text(self, status_code, content):
        return self.send_response_with_body(status_code, content.encode("utf-8"), "text/plain; charset=utf-8")

    def send_csv(self, filename, content):
        body = content.encode("utf-8")
        headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
        return self.send_response_with_body(200, body, "text/csv; charset=utf-8", headers)

    def redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.apply_standard_headers()
        for header, value in getattr(self, "_pending_headers", []):
            self.send_header(header, value)
        self.end_headers()

    def set_cookie(self, name, value):
        cookie = cookies.SimpleCookie()
        cookie[name] = value
        cookie[name]["path"] = "/"
        cookie[name]["httponly"] = True
        cookie[name]["samesite"] = "Lax"
        if SECURE_COOKIE:
            cookie[name]["secure"] = True
        self.queue_header("Set-Cookie", cookie.output(header="").strip())

    def expire_cookie(self, name):
        cookie = cookies.SimpleCookie()
        cookie[name] = ""
        cookie[name]["path"] = "/"
        cookie[name]["expires"] = "Thu, 01 Jan 1970 00:00:00 GMT"
        cookie[name]["httponly"] = True
        cookie[name]["samesite"] = "Lax"
        self.queue_header("Set-Cookie", cookie.output(header="").strip())

    def queue_header(self, name, value):
        headers = getattr(self, "_pending_headers", [])
        headers.append((name, value))
        self._pending_headers = headers

    def send_response_with_body(self, status_code, body, content_type, extra_headers=None):
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.apply_standard_headers()
        for header, value in getattr(self, "_pending_headers", []):
            self.send_header(header, value)
        self._pending_headers = []
        if extra_headers:
            for header, value in extra_headers.items():
                self.send_header(header, value)
        self.end_headers()
        self.wfile.write(body)

    def apply_standard_headers(self):
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
        )

    def set_flash(self, session_id, kind, message):
        if not session_id:
            return
        with get_connection() as connection:
            clear_expired_sessions(connection)
            connection.execute(
                """
                UPDATE sessions
                SET flash_kind = ?, flash_message = ?, updated_at = ?
                WHERE session_id = ?
                """,
                (kind, message, utc_now(), session_id),
            )

    def pop_flash(self, session_id):
        if not session_id:
            return ""
        with get_connection() as connection:
            clear_expired_sessions(connection)
            flash = connection.execute(
                "SELECT flash_kind, flash_message FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            if not flash or not flash["flash_message"]:
                return ""
            connection.execute(
                """
                UPDATE sessions
                SET flash_kind = NULL, flash_message = NULL, updated_at = ?
                WHERE session_id = ?
                """,
                (utc_now(), session_id),
            )
        if not flash["flash_kind"]:
            return ""
        return render_flash(flash["flash_kind"], flash["flash_message"])


def announce_startup():
    port_suffix = "" if PORT == 80 else f":{PORT}"
    local_url = DISPLAY_URL or f"http://127.0.0.1{port_suffix}"
    lan_ip = detect_lan_ip()
    print("=" * 72)
    print(APP_TITLE)
    print(f"Database: {DB_PATH}")
    print(f"Launch mode: {'Local only' if HOST in ('127.0.0.1', 'localhost') else 'Shared network'}")
    print(f"Inventory URL: {local_url}")
    if HOST not in ("127.0.0.1", "localhost"):
        lan_url = f"http://{lan_ip}{port_suffix}" if lan_ip else f"http://<this-computer-ip>{port_suffix}"
        print(f"LAN URL:    {lan_url}")
    if MANAGER_SETUP_PATH.exists():
        print(f"Initial manager note: {relative_display_path(MANAGER_SETUP_PATH)}")
        print("Open that file on the host computer for the one-time sign-in details.")
    else:
        print("Manager sign-in: use the credentials already set for this portal.")
    print("=" * 72)


def run():
    init_db()
    announce_startup()
    server = ThreadingHTTPServer((HOST, PORT), InventoryPortalHandler)
    server.serve_forever()


if __name__ == "__main__":
    run()


