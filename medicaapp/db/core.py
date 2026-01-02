from __future__ import annotations
import sqlite3
from typing import Any, Iterable

from ..config import DB_PATH
from ..utils import now_str
from ..auth.security import hash_password, ROLE_ADMIN

def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    # bezpieczniej na początku: jawnie włącz FK tylko jeśli chcesz
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
    except Exception:
        pass
    return conn

def db_exec(q: str, p: Iterable[Any] = ()):
    with connect() as conn:
        cur = conn.cursor()
        cur.execute(q, tuple(p))
        conn.commit()
        return cur.lastrowid

def db_one(q: str, p: Iterable[Any] = ()):
    with connect() as conn:
        cur = conn.cursor()
        cur.execute(q, tuple(p))
        return cur.fetchone()

def db_all(q: str, p: Iterable[Any] = ()):
    with connect() as conn:
        cur = conn.cursor()
        cur.execute(q, tuple(p))
        return cur.fetchall()

def ensure_column(table: str, col: str, decl: str):
    with connect() as conn:
        cur = conn.cursor()
        cur.execute(f"PRAGMA table_info({table})")
        cols = {r[1] for r in cur.fetchall()}
        if col in cols:
            return
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
        conn.commit()

def init_db():
    """Tworzy tabele jeśli nie istnieją + drobne migracje kolumn."""
    with connect() as conn:
        cur = conn.cursor()

        # settings
        cur.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )""")

        # users
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL,
            password_hash TEXT,
            password_salt TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_by INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            phone TEXT,
            notes TEXT
        )""")

        # patients
        cur.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            patient_id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            pesel TEXT,
            birth_date TEXT,
            room TEXT,
            notes TEXT,
            color_hex TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )""")

        # meds (lokalne)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS meds (
            med_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            form TEXT,
            default_dose_text TEXT,
            notes TEXT,
            color_hex TEXT
        )""")

        # orders (zlecenia)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            order_id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL DEFAULT 1,
            med_id TEXT NOT NULL,
            order_type TEXT NOT NULL,
            schedule_json TEXT,
            start_date TEXT,
            end_date TEXT,
            dose_text TEXT,
            route TEXT,
            notes TEXT,
            created_by INTEGER,
            created_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1
        )""")

        # administrations (podania)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS administrations (
            admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL DEFAULT 1,
            order_id INTEGER,
            med_id TEXT NOT NULL,
            given_at TEXT NOT NULL,
            given_date TEXT NOT NULL,
            dose_text TEXT,
            reason TEXT,
            status TEXT NOT NULL DEFAULT 'GIVEN',
            notes TEXT,
            given_by INTEGER
        )""")

        # drugs_catalog (URPL)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS drugs_catalog (
            drug_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            substance TEXT,
            dose TEXT,
            form TEXT,
            atc TEXT,
            source_date TEXT,
            imported_at TEXT NOT NULL
        )""")
        cur.execute("""CREATE INDEX IF NOT EXISTS idx_drugs_name ON drugs_catalog(name)""")
        cur.execute("""CREATE INDEX IF NOT EXISTS idx_drugs_substance ON drugs_catalog(substance)""")

        # titrations (jeśli używasz)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS titrations (
            titration_id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL DEFAULT 1,
            med_id TEXT NOT NULL,
            start_date TEXT NOT NULL,
            start_mg INTEGER NOT NULL,
            step_mg INTEGER NOT NULL,
            step_days INTEGER NOT NULL,
            max_mg INTEGER NOT NULL,
            notes TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            UNIQUE(patient_id, med_id)
        )""")

        conn.commit()

    # migracje kolumn (dla starszych baz)
    ensure_column("meds", "color_hex", "TEXT")
    ensure_column("orders", "patient_id", "INTEGER NOT NULL DEFAULT 1")
    ensure_column("administrations", "patient_id", "INTEGER NOT NULL DEFAULT 1")

    # konto startowe admin (admin/admin) jeśli pusto
    if not db_one("SELECT 1 FROM users LIMIT 1"):
        pw_hash, pw_salt = hash_password("admin")
        db_exec(
            "INSERT INTO users(username, full_name, role, password_hash, password_salt, is_active, created_at) VALUES (?,?,?,?,?,1,?)",
            ("admin", "Administrator", ROLE_ADMIN, pw_hash, pw_salt, now_str()),
        )

def get_setting(key: str, default: str = "") -> str:
    row = db_one("SELECT value FROM settings WHERE key=?", (key,))
    return row["value"] if row and row["value"] is not None else default

def set_setting(key: str, value: str):
    db_exec("INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
