"""
SQLite access layer.

Rules followed here:
  * Every query uses '?' placeholders: user input is never pasted into SQL.
  * Foreign keys are switched on for every connection (SQLite has them off by default).
  * Connections are always closed; failed transactions are rolled back.
"""
import logging
import re
import sqlite3
from contextlib import contextmanager

from werkzeug.security import check_password_hash, generate_password_hash

import config
from database.schema import COLUMN_MIGRATIONS, SCHEMA_STATEMENTS, USER_ROLES

log = logging.getLogger("soc.db")

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PASSWORD_LENGTH = 8


class DatabaseError(Exception):
    """Raised when a database operation fails (wraps sqlite3.Error)."""


def get_connection():
    """Open a new connection. DATABASE_PATH is read at call time so tests can override it."""
    config.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DATABASE_PATH, timeout=10)
    conn.row_factory = sqlite3.Row            # rows behave like dicts: row["username"]
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def db_session():
    """
    Use for multi-step work that must succeed or fail together:

        with db_session() as conn:
            conn.execute("INSERT ...", params)
            conn.execute("UPDATE ...", params)
    Commits on success, rolls back on any error, always closes.
    """
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except sqlite3.Error as exc:
        conn.rollback()
        log.error("Database error: %s", exc)
        raise DatabaseError(str(exc)) from exc
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------- simple helpers ----------
def query_all(sql, params=()):
    """Run a SELECT and return a list of sqlite3.Row."""
    with db_session() as conn:
        return conn.execute(sql, params).fetchall()


def query_one(sql, params=()):
    """Run a SELECT and return one row (or None)."""
    with db_session() as conn:
        return conn.execute(sql, params).fetchone()


def execute(sql, params=()):
    """Run INSERT/UPDATE/DELETE. Returns the last inserted row id."""
    with db_session() as conn:
        return conn.execute(sql, params).lastrowid


def execute_many(sql, rows):
    """Bulk insert/update (used later to store thousands of logs quickly)."""
    with db_session() as conn:
        return conn.executemany(sql, rows).rowcount


def _apply_migrations(conn):
    """Add columns that older databases lack. Table/column names come from our own constants."""
    for table, column, definition in COLUMN_MIGRATIONS:
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
            log.info("Migration: added %s.%s", table, column)


def init_db():
    """Create all tables and indexes if missing, then apply column migrations. Safe on every startup."""
    with db_session() as conn:
        for statement in SCHEMA_STATEMENTS:
            conn.execute(statement)
        _apply_migrations(conn)
    log.info("Database ready at %s", config.DATABASE_PATH)


def list_tables():
    """Names of our tables (used by tests and /health)."""
    rows = query_all(
        "SELECT name FROM sqlite_master "
        "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    )
    return [r["name"] for r in rows]


# ---------- users ----------
def create_user(username, password, role="analyst"):
    """Create a user with a hashed password. Raises ValueError on invalid input."""
    if not USERNAME_PATTERN.match(username or ""):
        raise ValueError("Username must be 3-32 characters: letters, digits, _ . -")
    if len(password or "") < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    if role not in USER_ROLES:
        raise ValueError(f"Role must be one of {USER_ROLES}")
    return execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        (username, generate_password_hash(password), role),
    )


def get_user(username):
    return query_one("SELECT * FROM users WHERE username = ?", (username,))


def verify_user(username, password):
    """True if the username exists and the password matches."""
    user = get_user(username)
    return bool(user) and check_password_hash(user["password_hash"], password)