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
            display_name TEXT NOT NULL,
            full_name TEXT,
            pesel TEXT,
            birth_date TEXT,
            address TEXT,
            allergies TEXT,
            chronic_conditions TEXT,
            emergency_contact TEXT,
            doctor_notes TEXT,
            id_photo_path TEXT,
            color_hex TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT
        )""")

        # meds (lokalne)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS meds (
            med_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            form TEXT,
            default_dose_text TEXT,
            notes TEXT,
            color_hex TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            med_type TEXT NOT NULL DEFAULT 'STAŁY',
            can_stop INTEGER NOT NULL DEFAULT 1,
            critical INTEGER NOT NULL DEFAULT 0,
            requires_doctor_to_hold INTEGER NOT NULL DEFAULT 0,
            policy TEXT,
            drug_class TEXT,
            drug_group TEXT,
            max_dose_text TEXT,
            mechanism TEXT,
            contraindications TEXT,
            extra_info TEXT,
            interactions_lvl1 TEXT,
            interactions_lvl2 TEXT,
            interactions_lvl3 TEXT
        )""")

        # orders (zlecenia)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            order_id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL DEFAULT 1,
            med_id TEXT NOT NULL,
            order_type TEXT,
            schedule_json TEXT,
            start_date TEXT,
            end_date TEXT,
            dose_text TEXT,
            route TEXT,
            notes TEXT,
            slot_label TEXT,
            time_str TEXT,
            days_rule TEXT,
            window_min INTEGER,
            priority INTEGER,
            effective_from TEXT,
            effective_to TEXT,
            status TEXT,
            created_by INTEGER,
            reason TEXT,
            created_at TEXT NOT NULL,
            earliest_admin_time TEXT,
            latest_admin_time TEXT,
            is_active INTEGER NOT NULL DEFAULT 1
        )""")

        # administrations (podania)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS administrations (
            admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL DEFAULT 1,
            order_id INTEGER,
            med_id TEXT NOT NULL,
            med_name TEXT,
            ts TEXT,
            planned_dt TEXT,
            slot_or_time TEXT,
            dose_text TEXT,
            prn_mg INTEGER,
            status TEXT NOT NULL DEFAULT 'GIVEN',
            who_user_id INTEGER,
            who_name TEXT,
            notes TEXT,
            reason TEXT,
            created_at TEXT
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

        cur.execute("""
        CREATE TABLE IF NOT EXISTS doctor_profile (
            doctor_id INTEGER PRIMARY KEY,
            full_name TEXT,
            pwz TEXT,
            phone TEXT,
            clinic TEXT,
            notes TEXT,
            created_at TEXT,
            updated_at TEXT
        )""")

        cur.execute("""
        CREATE TABLE IF NOT EXISTS blocks (
            block_id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL DEFAULT 1,
            block_type TEXT NOT NULL,
            block_value TEXT NOT NULL,
            status TEXT NOT NULL,
            reason TEXT,
            created_at TEXT NOT NULL,
            lifted_at TEXT,
            lifted_by INTEGER,
            lift_reason TEXT
        )""")

        cur.execute("""
        CREATE TABLE IF NOT EXISTS prn_permissions (
            prn_id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL DEFAULT 1,
            user_id INTEGER NOT NULL,
            med_id TEXT NOT NULL,
            mg_min INTEGER NOT NULL,
            mg_max INTEGER NOT NULL,
            mg_step INTEGER NOT NULL,
            max_mg_per_day INTEGER NOT NULL,
            min_interval_min INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1
        )""")

        conn.commit()

    # migracje kolumn (dla starszych baz)
    ensure_column("patients", "display_name", "TEXT")
    ensure_column("patients", "address", "TEXT")
    ensure_column("patients", "allergies", "TEXT")
    ensure_column("patients", "chronic_conditions", "TEXT")
    ensure_column("patients", "emergency_contact", "TEXT")
    ensure_column("patients", "doctor_notes", "TEXT")
    ensure_column("patients", "id_photo_path", "TEXT")
    ensure_column("patients", "updated_at", "TEXT")
    ensure_column("patients", "color_hex", "TEXT")

    ensure_column("meds", "color_hex", "TEXT")
    ensure_column("meds", "is_active", "INTEGER NOT NULL DEFAULT 1")
    ensure_column("meds", "med_type", "TEXT NOT NULL DEFAULT 'STAŁY'")
    ensure_column("meds", "can_stop", "INTEGER NOT NULL DEFAULT 1")
    ensure_column("meds", "critical", "INTEGER NOT NULL DEFAULT 0")
    ensure_column("meds", "requires_doctor_to_hold", "INTEGER NOT NULL DEFAULT 0")
    ensure_column("meds", "policy", "TEXT")
    ensure_column("meds", "drug_class", "TEXT")
    ensure_column("meds", "drug_group", "TEXT")
    ensure_column("meds", "max_dose_text", "TEXT")
    ensure_column("meds", "mechanism", "TEXT")
    ensure_column("meds", "contraindications", "TEXT")
    ensure_column("meds", "extra_info", "TEXT")
    ensure_column("meds", "interactions_lvl1", "TEXT")
    ensure_column("meds", "interactions_lvl2", "TEXT")
    ensure_column("meds", "interactions_lvl3", "TEXT")

    ensure_column("orders", "patient_id", "INTEGER NOT NULL DEFAULT 1")
    ensure_column("orders", "slot_label", "TEXT")
    ensure_column("orders", "time_str", "TEXT")
    ensure_column("orders", "days_rule", "TEXT")
    ensure_column("orders", "window_min", "INTEGER")
    ensure_column("orders", "priority", "INTEGER")
    ensure_column("orders", "effective_from", "TEXT")
    ensure_column("orders", "effective_to", "TEXT")
    ensure_column("orders", "status", "TEXT")
    ensure_column("orders", "reason", "TEXT")
    ensure_column("orders", "created_by", "INTEGER")
    ensure_column("orders", "earliest_admin_time", "TEXT")
    ensure_column("orders", "latest_admin_time", "TEXT")
    ensure_column("orders", "is_active", "INTEGER NOT NULL DEFAULT 1")

    ensure_column("administrations", "patient_id", "INTEGER NOT NULL DEFAULT 1")
    ensure_column("administrations", "med_name", "TEXT")
    ensure_column("administrations", "ts", "TEXT")
    ensure_column("administrations", "planned_dt", "TEXT")
    ensure_column("administrations", "slot_or_time", "TEXT")
    ensure_column("administrations", "prn_mg", "INTEGER")
    ensure_column("administrations", "who_user_id", "INTEGER")
    ensure_column("administrations", "who_name", "TEXT")
    ensure_column("administrations", "reason", "TEXT")
    ensure_column("administrations", "created_at", "TEXT")

    if not db_one("SELECT 1 FROM patients LIMIT 1"):
        db_exec(
            "INSERT INTO patients(display_name, full_name, created_at, updated_at, is_active) VALUES (?,?,?,?,1)",
            ("Pacjent", None, now_str(), now_str()),
        )

    if not db_one("SELECT 1 FROM doctor_profile WHERE doctor_id=1"):
        db_exec(
            "INSERT INTO doctor_profile(doctor_id, full_name, created_at, updated_at) VALUES (1, 'Lekarz', ?, ?)",
            (now_str(), now_str()),
        )

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
