from __future__ import annotations

import csv
import json
import os
from pathlib import Path
import random
import re
from datetime import date, datetime, timedelta

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog

from .config import APP_NAME, BASE_DIR, URPL_HINTS
from .db import init_db, db_exec, db_one, db_all, connect, get_setting, set_setting
from .auth.security import (
    ROLE_ADMIN, ROLE_DOCTOR, ROLE_NURSE, ROLE_LABEL,
    hash_password, verify_password
)
from .services.import_urpl import import_urpl_csv
from .utils import now_str

def setup_style(root: tk.Tk):
    try:
        root.tk.call("tk", "scaling", 1.1)
    except Exception:
        pass

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass

    base_font = ("Segoe UI", 10)
    style.configure(".", font=base_font)
    style.configure("Title.TLabel", font=("Segoe UI", 14, "bold"))
    style.configure("H1.TLabel", font=("Segoe UI", 12, "bold"))
    style.configure("Muted.TLabel", foreground="#555")
    style.configure("Danger.TLabel", foreground="#b00020")
    style.configure("Good.TLabel", foreground="#1b5e20")
    style.configure("Note.TLabel", foreground="#0d47a1")

    style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"), padding=(10, 8))
    style.configure("Soft.TButton", padding=(8, 6))
    style.configure("Card.TFrame", relief="solid", borderwidth=1)
    style.configure("Toolbar.TFrame", padding=(10, 8))
    style.configure("Page.TFrame", padding=(12, 10))

class ScrollableFrame(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        root = parent.winfo_toplevel()
        colors = getattr(root, "theme_colors", {}) or {}
        c_bg = colors.get("bg")
        self.canvas = tk.Canvas(self, highlightthickness=0)
        if c_bg:
            try:
                self.canvas.configure(bg=c_bg)
            except Exception:
                pass
        self.scroll = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.inner = ttk.Frame(self)

        self.inner.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scroll.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scroll.pack(side="right", fill="y")
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def _on_mousewheel(self, e):
        try:
            self.canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
        except Exception:
            pass

def show_med_details(parent, med_id: str):
    m = db_one("SELECT * FROM meds WHERE med_id=?", (med_id,))
    if not m:
        messagebox.showinfo("Lek", "Brak danych leku.")
        return

    win = tk.Toplevel(parent)
    win.title(f"{m['name']} — szczegóły")
    win.geometry("760x650")

    frm = ttk.Frame(win, style="Page.TFrame")
    frm.pack(fill="both", expand=True)

    ttk.Label(frm, text=m["name"], style="Title.TLabel").pack(anchor="w")
    ttk.Label(frm, text=f"ID: {m['med_id']}   |   Forma: {m['form'] or '-'}   |   Typ: {m['med_type']}",
              style="Muted.TLabel").pack(anchor="w", pady=(2, 10))

    def block(title, text, kind=None):
        if not text:
            return
        lbl_style = "H1.TLabel" if not kind else kind
        ttk.Label(frm, text=title, style=lbl_style).pack(anchor="w", pady=(8, 2))
        t = tk.Text(frm, height=4, wrap="word")
        t.insert("1.0", text)
        t.configure(state="disabled")
        t.pack(fill="x")

    if m["max_dose_text"]:
        block("Max / zasady", m["max_dose_text"], "Note.TLabel")
    if m["mechanism"]:
        block("Jak działa", m["mechanism"])
    if m["notes"]:
        block("Instrukcje", m["notes"])

    ttk.Label(frm, text="Interakcje / czego nie łączyć", style="H1.TLabel").pack(anchor="w", pady=(10, 2))
    any_int = False
    if m["interactions_lvl3"]:
        any_int = True
        ttk.Label(frm, text=f"{ICON_3} bardzo niebezpieczne", style="Danger.TLabel").pack(anchor="w")
        block("Poziom 3", m["interactions_lvl3"])
    if m["interactions_lvl2"]:
        any_int = True
        ttk.Label(frm, text=f"{ICON_2} poważne ryzyko", style="Danger.TLabel").pack(anchor="w")
        block("Poziom 2", m["interactions_lvl2"])
    if m["interactions_lvl1"]:
        any_int = True
        ttk.Label(frm, text=f"{ICON_1} lekkie ostrzeżenie", style="Muted.TLabel").pack(anchor="w")
        block("Poziom 1", m["interactions_lvl1"])
    if not any_int:
        ttk.Label(frm, text="Brak wpisanych interakcji.", style="Muted.TLabel").pack(anchor="w")

    if m["contraindications"]:
        block("Przeciwwskazania / ostrzeżenia", m["contraindications"])
    if m["extra_info"]:
        block("Dodatkowe", m["extra_info"])

    ttk.Button(frm, text="Zamknij", style="Soft.TButton", command=win.destroy).pack(anchor="e", pady=10)


# ======================= APP =======================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        init_db()
        setup_style(self)

        self._auto_import_drugs_catalog_if_present()

        self.title(APP_NAME)
        self.geometry("1120x760")
        self.minsize(980, 640)

        self.user = None
        self.dark_mode = (get_setting('dark_mode','0') == '1')
        self.apply_theme()

        # odświeżanie dzienne: przełącza widoki przy zmianie daty (reset zleceń stałych)
        self._last_day = date.today()
        self.after(30_000, self._day_rollover_tick)

        self.show_role_picker()

    # ===== start: role picker =====
    def show_role_picker(self):
        for w in self.winfo_children():
            w.destroy()

        page = ttk.Frame(self, style="Page.TFrame")
        page.pack(fill="both", expand=True)

        box = ttk.Frame(page, style="Card.TFrame", padding=18)
        box.place(relx=0.5, rely=0.5, anchor="c")

        ttk.Label(box, text="Logowanie", style="H1.TLabel").grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Label(box, text="Wybierz profil i wpisz hasło.", style="Muted.TLabel").grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 14))

        users = db_all("SELECT user_id, username, full_name, role FROM users WHERE is_active=1 ORDER BY role, full_name")
        if not users:
            messagebox.showerror("Baza", "Brak użytkowników w bazie. Uruchom ponownie — tworzy się admin (admin/admin).")
            init_db()
            users = db_all("SELECT user_id, username, full_name, role FROM users WHERE is_active=1 ORDER BY role, full_name")

        self._login_map = {}
        labels = []
        for u in users:
            role_lbl = ROLE_LABEL.get(u["role"], u["role"])
            lbl = f'{u["full_name"]} ({role_lbl}) — {u["username"]}'
            self._login_map[lbl] = dict(u)
            labels.append(lbl)

        ttk.Label(box, text="Profil", style="Muted.TLabel").grid(row=2, column=0, sticky="w")
        cb = ttk.Combobox(box, state="readonly", width=46, values=labels)
        cb.grid(row=3, column=0, columnspan=2, sticky="we", pady=(0, 10))
        cb.current(0)

        ttk.Label(box, text="Hasło", style="Muted.TLabel").grid(row=4, column=0, sticky="w")
        pw = ttk.Entry(box, show="•", width=30)
        pw.grid(row=5, column=0, sticky="w")

        def do_login():
            lbl = cb.get()
            u = self._login_map.get(lbl)
            if not u:
                messagebox.showerror("Logowanie", "Wybierz profil.")
                return
            self.login_user(u["username"], pw.get())

        ttk.Button(box, text="Zaloguj", style="Primary.TButton", command=do_login).grid(row=5, column=1, sticky="e")
        pw.bind("<Return>", lambda _e: do_login())

        ttk.Label(box, text="Domyślne konto: admin / admin (zmień po pierwszym logowaniu).",
                  style="Muted.TLabel").grid(row=6, column=0, columnspan=2, sticky="w", pady=(12, 0))


    def login_user(self, username: str, password: str):
        u = db_one("SELECT * FROM users WHERE username=? AND is_active=1", (username,))
        if not u:
            messagebox.showerror("Logowanie", "Nieprawidłowy login.")
            return
        u = dict(u)
        if not u.get("password_hash") or not u.get("password_salt"):
            # stare konto bez hasła: akceptuj puste i od razu ustaw nowe
            if (password or "").strip() != "":
                messagebox.showerror("Logowanie", "To konto nie ma ustawionego hasła — wpisz puste i ustaw nowe po zalogowaniu.")
                return
        else:
            if not verify_password(password or "", u["password_hash"], u["password_salt"]):
                messagebox.showerror("Logowanie", "Błędne hasło.")
                return

        if self._must_change_default_admin_password(u):
            if not self._force_admin_password_change(u):
                return
            refreshed = db_one("SELECT * FROM users WHERE user_id=?", (u["user_id"],))
            if refreshed:
                u = dict(refreshed)

        self.user = u
        self.admin_view_as_doctor = False
        self.show_main()

    def _must_change_default_admin_password(self, user: dict) -> bool:
        try:
            if not user:
                return False
            if (user.get("username") or "").lower() != "admin" or user.get("role") != ROLE_ADMIN:
                return False
            ph = user.get("password_hash") or ""
            ps = user.get("password_salt") or ""
            if not ph or not ps:
                return True
            return verify_password("admin", ph, ps)
        except Exception:
            return False

    def _force_admin_password_change(self, user: dict) -> bool:
        messagebox.showinfo(
            "Logowanie",
            "Wymagana jest zmiana domyślnego hasła konta admin. Podaj nowe hasło.",
        )

        while True:
            new_pw = simpledialog.askstring(
                "Nowe hasło admin",
                "Wpisz nowe hasło (min. 4 znaki).",
                show="•",
                parent=self,
            )
            if new_pw is None:
                messagebox.showwarning("Logowanie", "Zmiana hasła jest wymagana dla konta admin.")
                return False
            new_pw = new_pw.strip()
            if len(new_pw) < 4:
                messagebox.showerror("Logowanie", "Hasło musi mieć co najmniej 4 znaki.")
                continue

            confirm = simpledialog.askstring(
                "Powtórz hasło",
                "Powtórz nowe hasło dla potwierdzenia.",
                show="•",
                parent=self,
            )
            if confirm is None:
                messagebox.showwarning("Logowanie", "Zmiana hasła jest wymagana dla konta admin.")
                return False
            if new_pw != (confirm or "").strip():
                messagebox.showerror("Logowanie", "Hasła nie są zgodne. Spróbuj ponownie.")
                continue

            ph, ps = hash_password(new_pw)
            db_exec(
                "UPDATE users SET password_hash=?, password_salt=?, updated_at=? WHERE user_id=?",
                (ph, ps, now_str(), user.get("user_id")),
            )
            messagebox.showinfo("Logowanie", "Hasło zostało zmienione. Kontynuuję logowanie.")
            return True

    # ===== main =====
    def show_main(self):
        for w in self.winfo_children():
            w.destroy()

        self.apply_theme()

        toolbar = ttk.Frame(self, style="Toolbar.TFrame")
        toolbar.pack(fill="x")

        ttk.Label(toolbar, text="MedicaApp", style="H1.TLabel").pack(side="left")
        ttk.Label(toolbar, text=f"  •  {self.user['role']}  •  {self.user['username']}", style="Muted.TLabel").pack(side="left")
        ttk.Button(toolbar, text="Tryb nocny", style="Soft.TButton", command=self.toggle_dark_mode).pack(side="right", padx=(0, 8))
        ttk.Button(toolbar, text="Zmień profil", style="Soft.TButton", command=self.show_role_picker).pack(side="right")
        if self.user and self.user.get("role")==ROLE_ADMIN:
            ttk.Button(toolbar, text=("Widok admina" if getattr(self,"admin_view_as_doctor",False) else "Widok lekarza"),
                       style="Soft.TButton", command=self._toggle_admin_view).pack(side="right", padx=(0,8))

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=10, pady=10)

        if self.user["role"] == ROLE_ADMIN and not getattr(self,"admin_view_as_doctor",False):
            self.tab_admin = ttk.Frame(self.nb)
            self.nb.add(self.tab_admin, text="ADMIN")
            self.build_admin()
            self.refresh_admin()
        elif self.user["role"] == ROLE_NURSE:
            # prosto: podawanie na dziś + PRN; kalendarz jako dodatek
            self.tab_give = ttk.Frame(self.nb)
            self.tab_cal = ttk.Frame(self.nb)
            self.tab_hist = ttk.Frame(self.nb)

            self.nb.add(self.tab_give, text="PODAWANIE (DZIŚ)")
            self.nb.add(self.tab_cal, text="KALENDARZ")
            self.nb.add(self.tab_hist, text="HISTORIA")

            self.build_give_page()
            self.build_calendar_page()
            self.build_history()
            self.refresh_all()
        else:
            self.tab_lekarz = ttk.Frame(self.nb)
            self.tab_today = ttk.Frame(self.nb)
            self.tab_prn = ttk.Frame(self.nb)
            self.tab_hist = ttk.Frame(self.nb)

            # lekarz ma od razu wejść w konfigurację
            self.nb.add(self.tab_lekarz, text="LEKARZ")
            self.nb.add(self.tab_today, text="DZISIAJ")
            self.nb.add(self.tab_prn, text="DORAŹNE (PRN)")
            self.nb.add(self.tab_hist, text="HISTORIA")

            self.build_lekarz()
            self.build_today()
            self.build_prn()
            self.build_history()
            self.refresh_all()

            try:
                self.nb.select(self.tab_lekarz)
            except Exception:
                pass


    
    def _day_rollover_tick(self):
        try:
            today = date.today()
            if getattr(self, "_last_day", today) != today:
                self._last_day = today
                # automatycznie przełącz kalendarz na dziś (jeśli istnieje) i odśwież widoki
                if hasattr(self, "cal_selected_date"):
                    self.cal_selected_date = today
                    self.cal_year = today.year
                    self.cal_month = today.month
                self.refresh_all()
        except Exception:
            pass
        self.after(30_000, self._day_rollover_tick)

    def refresh_all(self):
        if self.user["role"] == ROLE_ADMIN and not getattr(self,"admin_view_as_doctor",False):
            self.tab_admin = ttk.Frame(self.nb)
            self.nb.add(self.tab_admin, text="ADMIN")
            self.build_admin()
            self.refresh_admin()
        elif self.user["role"] == ROLE_NURSE:
            self.refresh_give_page()
            self.refresh_calendar_page()
            self.refresh_history()
        else:
            self.refresh_today()
            self.refresh_prn()
            self.refresh_history()
            self.refresh_lekarz()


    # =================== ADMIN ===================
    def build_admin(self):
        page = ttk.Frame(self.tab_admin, style="Page.TFrame")
        page.pack(fill="both", expand=True)

        top = ttk.Frame(page)
        top.pack(fill="x")
        ttk.Label(top, text="Panel administratora", style="Title.TLabel").pack(side="left")
        ttk.Button(top, text="Odśwież", style="Soft.TButton", command=self.refresh_admin).pack(side="right")

        # sekcja: dodawanie personelu
        card = ttk.Frame(page, style="Card.TFrame", padding=12)
        card.pack(fill="x", pady=(10, 10))

        ttk.Label(card, text="Personel", style="H1.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(card, text="Administrator dodaje lekarzy i pielęgniarki. Lekarz może dodawać tylko pielęgniarki.",
                  style="Muted.TLabel").grid(row=1, column=0, columnspan=6, sticky="w", pady=(2, 10))

        ttk.Label(card, text="Imię i nazwisko", style="Muted.TLabel").grid(row=2, column=0, sticky="w")
        self.e_new_fullname = ttk.Entry(card, width=30)
        self.e_new_fullname.grid(row=3, column=0, sticky="w")

        ttk.Label(card, text="Login", style="Muted.TLabel").grid(row=2, column=1, sticky="w", padx=(10,0))
        self.e_new_username = ttk.Entry(card, width=18)
        self.e_new_username.grid(row=3, column=1, sticky="w", padx=(10,0))

        ttk.Label(card, text="Hasło", style="Muted.TLabel").grid(row=2, column=2, sticky="w", padx=(10,0))
        self.e_new_pw = ttk.Entry(card, width=16, show="•")
        self.e_new_pw.grid(row=3, column=2, sticky="w", padx=(10,0))

        ttk.Label(card, text="Rola", style="Muted.TLabel").grid(row=2, column=3, sticky="w", padx=(10,0))
        self.cb_new_role = ttk.Combobox(card, state="readonly", width=16,
                                        values=[ROLE_ADMIN, ROLE_DOCTOR, ROLE_NURSE])
        self.cb_new_role.grid(row=3, column=3, sticky="w", padx=(10,0))
        self.cb_new_role.set(ROLE_NURSE)

        ttk.Button(card, text="Dodaj", style="Primary.TButton", command=self.admin_add_user).grid(row=3, column=4, padx=(12,0))

        # lista personelu
        self.admin_users_tree = ttk.Treeview(page, columns=("id","name","role","user","active"), show="headings", height=10)
        for c, w in [("id",60),("name",240),("role",120),("user",140),("active",90)]:
            self.admin_users_tree.heading(c, text=c.upper())
            self.admin_users_tree.column(c, width=w, anchor="w")
        self.admin_users_tree.pack(fill="x", pady=(0,10))

        # sekcja: bazy
        dbcard = ttk.Frame(page, style="Card.TFrame", padding=12)
        dbcard.pack(fill="both", expand=True)

        ttk.Label(dbcard, text="Bazy danych", style="H1.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(dbcard, text="Podgląd emar.db i słownika leków (read-only).", style="Muted.TLabel").grid(row=1, column=0, columnspan=3, sticky="w", pady=(2,10))

        ttk.Label(dbcard, text="Tabela", style="Muted.TLabel").grid(row=2, column=0, sticky="w")
        self.cb_tables = ttk.Combobox(dbcard, state="readonly", width=28)
        self.cb_tables.grid(row=3, column=0, sticky="w")
        ttk.Button(dbcard, text="Pokaż", style="Soft.TButton", command=self.admin_show_table).grid(row=3, column=1, padx=8)

        ttk.Button(dbcard, text="Import bazy leków (CSV URPL)", style="Primary.TButton",
                   command=self.import_drugs_catalog).grid(row=3, column=2, sticky="e")

        self.admin_table_frame = ttk.Frame(dbcard)
        self.admin_table_frame.grid(row=4, column=0, columnspan=3, sticky="nsew", pady=(10,0))
        dbcard.rowconfigure(4, weight=1)
        dbcard.columnconfigure(2, weight=1)

    def refresh_admin(self):
        # users
        if not hasattr(self, "admin_users_tree"):
            return
        for i in self.admin_users_tree.get_children():
            self.admin_users_tree.delete(i)
        rows = db_all("SELECT user_id, full_name, role, username, is_active FROM users ORDER BY role, full_name")
        for r in rows:
            self.admin_users_tree.insert("", "end", values=(r["user_id"], r["full_name"], r["role"], r["username"], "TAK" if r["is_active"] else "NIE"))

        # tables list
        tabs = db_all("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        self.cb_tables["values"] = [t["name"] for t in tabs]
        if tabs and not self.cb_tables.get():
            self.cb_tables.current(0)

    def admin_add_user(self):
        if not self.user or self.user.get("role") != ROLE_ADMIN:
            return
        full_name = (self.e_new_fullname.get() or "").strip()
        username = (self.e_new_username.get() or "").strip()
        password = (self.e_new_pw.get() or "").strip()
        role = (self.cb_new_role.get() or "").strip()

        if not full_name or not username or not password or role not in (ROLE_ADMIN, ROLE_DOCTOR, ROLE_NURSE):
            messagebox.showerror("ADMIN", "Uzupełnij: imię i nazwisko, login, hasło oraz rolę.")
            return

        if db_one("SELECT 1 FROM users WHERE username=?", (username,)):
            messagebox.showerror("ADMIN", "Taki login już istnieje.")
            return

        pw_hash, pw_salt = hash_password(password)
        db_exec(
            "INSERT INTO users(username, full_name, role, password_hash, password_salt, is_active, created_by, created_at) VALUES (?,?,?,?,?,1,?,?)",
            (username, full_name, role, pw_hash, pw_salt, self.user["user_id"], now_str())
        )
        self.e_new_fullname.delete(0, "end")
        self.e_new_username.delete(0, "end")
        self.e_new_pw.delete(0, "end")
        self.refresh_admin()
        messagebox.showinfo("ADMIN", "Dodano użytkownika.")

    def admin_show_table(self):
        t = getattr(self, "cb_tables", None)
        if not t:
            return
        table = (self.cb_tables.get() or "").strip()
        if not table:
            return

        for w in self.admin_table_frame.winfo_children():
            w.destroy()

        # pobierz do 200 wierszy
        try:
            rows = db_all(f"SELECT * FROM {table} LIMIT 200")
        except Exception as e:
            messagebox.showerror("ADMIN", f"Nie mogę odczytać tabeli {table}.\n\n{e}")
            return
        cols = rows[0].keys() if rows else []
        tv = ttk.Treeview(self.admin_table_frame, columns=list(cols), show="headings", height=12)
        vs = ttk.Scrollbar(self.admin_table_frame, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vs.set)
        tv.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")

        for c in cols:
            tv.heading(c, text=c)
            tv.column(c, width=140, anchor="w")
        for r in rows:
            tv.insert("", "end", values=[r[c] for c in cols])

    # =================== TRYB NOCNY ===================


    def _auto_import_drugs_catalog_if_present(self):
        """Jeśli słownik leków jest pusty i w folderze programu jest CSV URPL, importuje automatycznie."""
        try:
            r = db_one("SELECT COUNT(1) AS c FROM drugs_catalog")
            if r and int(r["c"]) > 0:
                return
        except Exception:
            return

        # szukaj CSV w folderze projektu (BASE_DIR) i w folderze modułu jako rezerwę
        try:
            search_roots = [Path(BASE_DIR), Path(__file__).resolve().parent]
        except Exception:
            search_roots = [Path(os.getcwd())]

        cand: str | None = None
        try:
            for root in search_roots:
                if not root.exists():
                    continue
                for entry in root.iterdir():
                    if not entry.is_file() or entry.suffix.lower() != ".csv":
                        continue
                    lower_name = entry.name.lower()
                    hint_match = any(h.lower() in lower_name for h in URPL_HINTS)
                    if hint_match:
                        cand = str(entry)
                        break
                    if cand is None:
                        cand = str(entry)
                if cand:
                    break
            if cand is None:
                return
        except Exception:
            return

        # import bez UI (żeby działało na starcie)
        try:
            import_urpl_csv(cand)
        except Exception:
            pass

    # --- leki: import URPL do słownika ---

    def _import_drugs_catalog_from_path(self, fp: str, silent: bool = False):
        if not fp:
            return
        try:
            source_date = None
            bn = os.path.basename(fp)
            m = re.search(r"(20\d{2})(\d{2})(\d{2})", bn)
            if m:
                source_date = f"{m.group(1)}-{m.group(2)}-{m.group(3)}"

            imported_at = now_str()

            with connect() as conn:
                cur = conn.cursor()
                cur.execute("DELETE FROM drugs_catalog")
                conn.commit()

                with open(fp, "r", encoding="utf-8", newline="") as f:
                    reader = csv.DictReader(f, delimiter=";")
                    def g(row, *keys):
                        for k in keys:
                            if k in row and row[k] not in (None, ""):
                                return row[k]
                        return None

                    buf = []
                    for row in reader:
                        name = g(row, "NAZWA_PRODUKTU", "Nazwa produktu", "NAZWA")
                        if not name:
                            continue
                        substance = g(row, "SUBSTANCJA_CZYNNA", "Substancja czynna")
                        dose = g(row, "MOC", "Moc")
                        form = g(row, "POSTAC", "Postać")
                        atc = g(row, "KOD_ATC", "Kod ATC", "ATC")
                        buf.append((name.strip(),
                                    (substance or "").strip() or None,
                                    (dose or "").strip() or None,
                                    (form or "").strip() or None,
                                    (atc or "").strip() or None,
                                    source_date, imported_at))
                        if len(buf) >= 3000:
                            cur.executemany(
                                "INSERT INTO drugs_catalog(name, substance, dose, form, atc, source_date, imported_at) VALUES (?,?,?,?,?,?,?)",
                                buf
                            )
                            conn.commit()
                            buf.clear()
                    if buf:
                        cur.executemany(
                            "INSERT INTO drugs_catalog(name, substance, dose, form, atc, source_date, imported_at) VALUES (?,?,?,?,?,?,?)",
                            buf
                        )
                        conn.commit()

            set_setting("drugs_catalog_source_date", source_date or "")
            set_setting("drugs_catalog_imported_at", imported_at)

            if not silent:
                messagebox.showinfo("LEKI", f"Import bazy leków zakończony.\n\nPlik: {os.path.basename(fp)}")
        except Exception as e:
            if not silent:
                messagebox.showerror("LEKI", f"Nie udało się zaimportować CSV.\n\n{e}")
            else:
                raise

    
    def import_drugs_catalog(self):
        fp = filedialog.askopenfilename(
            title="Wybierz plik CSV z Rejestru Produktów Leczniczych (URPL)",
            filetypes=[("CSV", "*.csv"), ("Wszystkie pliki", "*.*")]
        )
        if not fp:
            return
        import_urpl_csv(fp)

    def _catalog_suggest(self, text: str, limit: int = 30):
        text = (text or "").strip()
        if not text:
            return []
        like = f"%{text}%"
        rows = db_all(
            "SELECT name, dose, form, substance FROM drugs_catalog WHERE name LIKE ? OR substance LIKE ? ORDER BY name LIMIT ?",
            (like, like, limit)
        )
        out = []
        for r in rows:
            parts = [r["name"]]
            if r["dose"]:
                parts.append(r["dose"])
            if r["form"]:
                parts.append(r["form"])
            if r["substance"]:
                parts.append(f"[{r['substance']}]")
            out.append(" | ".join(parts))
        return out

    def _ensure_med_from_catalog_label(self, label: str) -> str | None:
        if not label:
            return None
        chunks = [c.strip() for c in label.split("|")]
        name = chunks[0] if chunks else ""
        dose = chunks[1] if len(chunks) > 1 else None
        form = chunks[2] if len(chunks) > 2 else None
        key = f"{name}|{dose or ''}|{form or ''}"
        mid = "URPL_" + hashlib.md5(key.encode("utf-8")).hexdigest()[:12]
        col = "#" + hashlib.md5(name.encode("utf-8")).hexdigest()[:6]
        if not db_one("SELECT 1 FROM meds WHERE med_id=?", (mid,)):
            db_exec("INSERT INTO meds(med_id, name, form, default_dose_text, notes, color_hex) VALUES (?,?,?,?,?,?)",
                    (mid, name, form, dose, "URPL", col))
        return mid

    def apply_theme(self):
        style = ttk.Style(self)
        dark = bool(self.dark_mode)

        if dark:
            bg = "#0f1115"
            fg = "#e6e6e6"
            card = "#171b24"
            panel = "#121620"
            mut = "#a7b0c0"
            danger = "#ff6b6b"
            good = "#7ee787"
            note = "#79c0ff"
            entry = "#121620"
            border = "#2b3342"
        else:
            bg = "#f7f7f7"
            fg = "#111111"
            card = "#ffffff"
            panel = "#ffffff"
            mut = "#555555"
            danger = "#b00020"
            good = "#1b5e20"
            note = "#0d47a1"
            entry = "#ffffff"
            border = "#d0d0d0"

        self.configure(bg=bg)

        style.configure(".", background=bg, foreground=fg)
        style.configure("TFrame", background=bg)
        style.configure("Page.TFrame", background=bg)
        style.configure("Toolbar.TFrame", background=panel)
        style.configure("Card.TFrame", background=card, relief="solid", borderwidth=1)

        style.configure("TLabel", background=bg, foreground=fg)
        style.configure("Title.TLabel", background=bg, foreground=fg)
        style.configure("H1.TLabel", background=bg, foreground=fg)

        style.configure("Muted.TLabel", background=bg, foreground=mut)
        style.configure("Danger.TLabel", background=bg, foreground=danger)
        style.configure("Good.TLabel", background=bg, foreground=good)
        style.configure("Note.TLabel", background=bg, foreground=note)

        style.configure("TEntry", fieldbackground=entry, foreground=fg)
        style.configure("TCombobox", fieldbackground=entry, foreground=fg)
        style.configure("TSpinbox", fieldbackground=entry, foreground=fg)

        style.configure("TNotebook", background=bg, borderwidth=0)
        style.configure("TNotebook.Tab", padding=(12, 8))
        style.map("TNotebook.Tab",
                  background=[("selected", card), ("active", panel)],
                  foreground=[("selected", fg), ("active", fg)])

        style.configure("TButton", background=panel, foreground=fg)
        style.map("TButton",
                  background=[("active", card), ("pressed", card)],
                  foreground=[("disabled", mut)])

        # zapamiętaj kolory (do tk widgets, np. kalendarz/canvas/spinbox)
        self.theme_colors = {
            "bg": bg, "fg": fg, "card": card, "panel": panel, "mut": mut,
            "danger": danger, "good": good, "note": note, "entry": entry, "border": border,
            # kalendarz (tk) – proste, czytelne
            "cal_ok": good,
            "cal_warn": "#b26a00" if not dark else "#d29922",
            "cal_prn": note,
            "cal_off": mut,
        }

        # tk widgets default colors (ttk ma style, ale tk.Text / tk.Spinbox / Canvas potrzebują tego)
        self.option_add("*Text.background", entry)
        self.option_add("*Text.foreground", fg)
        self.option_add("*Text.insertBackground", fg)
        self.option_add("*Entry.background", entry)
        self.option_add("*Entry.foreground", fg)
        self.option_add("*Spinbox.background", entry)
        self.option_add("*Spinbox.foreground", fg)
        self.option_add("*Listbox.background", entry)
        self.option_add("*Listbox.foreground", fg)

    def _allowed_roles_for_creator(self):
        if not self.user:
            return []
        r = self.user.get("role")
        if r == ROLE_ADMIN:
            return [ROLE_ADMIN, ROLE_DOCTOR, ROLE_NURSE]
        if r == ROLE_DOCTOR:
            return [ROLE_NURSE]
        return []

    def _role_label(self, role: str) -> str:
        return ROLE_LABEL.get(role, role)


    def _toggle_admin_view(self):
        if not self.user or self.user.get("role") != ROLE_ADMIN:
            return
        self.admin_view_as_doctor = not bool(getattr(self, "admin_view_as_doctor", False))
        self.show_main()

    def toggle_dark_mode(self):
        self.dark_mode = not self.dark_mode
        set_setting("dark_mode", "1" if self.dark_mode else "0")
        # przebuduj UI, żeby ttk + tk odświeżyły kolory
        if self.user:
            cur = dict(self.user)
            self.apply_theme()
            self.user = cur
            self.show_main()
        else:
            self.apply_theme()
            self.show_role_picker()


    def render_patient_header(self, parent):
        pr = patient_row()

        card = ttk.Frame(parent, style="Card.TFrame", padding=10)
        card.pack(fill="x", pady=(0, 10))

        left = ttk.Frame(card)
        left.pack(side="left", fill="x", expand=True)

        name = pr["display_name"] or "Pacjent"
        line2 = pr["full_name"] or ""
        pesel = pr["pesel"] or ""
        bdate = pr["birth_date"] or ""

        ttk.Label(left, text=name, style="H1.TLabel").pack(anchor="w")
        info = "  •  ".join([x for x in [line2, f"PESEL: {pesel}" if pesel else "", f"ur.: {bdate}" if bdate else ""] if x])
        ttk.Label(left, text=info, style="Muted.TLabel").pack(anchor="w", pady=(2, 0))

        # przełączanie pacjenta + dane lekarza
        right = ttk.Frame(card)
        right.pack(side="right", anchor="e")

        ttk.Label(right, text="Pacjent", style="Muted.TLabel").pack(anchor="e")

        rows = db_all("SELECT patient_id, display_name FROM patients ORDER BY patient_id ASC")
        if not rows:
            rows = [(1, "Pacjent")]

        labels = []
        self._patient_map = {}
        cur_pid = current_patient_id()
        cur_label = None
        for r in rows:
            pid = int(r["patient_id"]) if hasattr(r, "keys") else int(r[0])
            nm = (r["display_name"] if hasattr(r, "keys") else r[1]) or f"Pacjent {pid}"
            lbl = f"{pid}: {nm}"
            labels.append(lbl)
            self._patient_map[lbl] = pid
            if pid == cur_pid:
                cur_label = lbl

        self.cb_patient = ttk.Combobox(right, state="readonly", width=26, values=labels)
        self.cb_patient.pack(anchor="e")
        if cur_label:
            self.cb_patient.set(cur_label)
        else:
            self.cb_patient.current(0)

        def on_patient_change(_e=None):
            lbl = self.cb_patient.get()
            pid = self._patient_map.get(lbl, 1)
            set_current_patient_id(pid)
            self.refresh_all()

        self.cb_patient.bind("<<ComboboxSelected>>", on_patient_change)

        doc = db_one("SELECT * FROM doctor_profile WHERE doctor_id=1")
        doc_name = (doc["full_name"] if doc else None) or "Lekarz"
        ttk.Label(right, text=f"Lekarz: {doc_name}", style="Muted.TLabel").pack(anchor="e", pady=(4, 0))

        return card
    # =================== NURSE: PODAWANIE (DZIŚ) ===================
    def build_give_page(self):
        page = ttk.Frame(self.tab_give, style="Page.TFrame")
        page.pack(fill="both", expand=True)

        top = ttk.Frame(page)
        top.pack(fill="x")
        ttk.Label(top, text="Podawanie — dziś", style="Title.TLabel").pack(side="left")
        ttk.Button(top, text="Odśwież", style="Soft.TButton", command=self.refresh_all).pack(side="right")

        self.render_patient_header(page)

        self.lbl_blocks_give = ttk.Label(page, text="", style="Danger.TLabel")
        self.lbl_blocks_give.pack(anchor="w", pady=(2, 8))

        # lista dawek na dziś (minimum klikania)
        self.give_today_list = ScrollableFrame(page)
        self.give_today_list.pack(fill="both", expand=True, pady=(6, 10))

        # PRN pod spodem — na tej samej stronie
        prn_card = ttk.Frame(page, style="Card.TFrame", padding=12)
        prn_card.pack(fill="x")

        ttk.Label(prn_card, text="Doraźne (PRN)", style="H1.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(prn_card, text="Lek wybiera lekarz. Pielęgniarka: wybierz → mg → wpisz powód → PODAJ PRN.",
                  style="Muted.TLabel").grid(row=1, column=0, columnspan=6, sticky="w", pady=(2, 10))

        ttk.Label(prn_card, text="Lek", style="Muted.TLabel").grid(row=2, column=0, sticky="w")
        self.cb_prn2 = ttk.Combobox(prn_card, state="readonly", width=48)
        self.cb_prn2.grid(row=3, column=0, sticky="w")

        ttk.Button(prn_card, text="Szczegóły", style="Soft.TButton",
                   command=lambda: self._prn_details_combo(self.cb_prn2)).grid(row=3, column=1, padx=8)

        ttk.Label(prn_card, text="mg", style="Muted.TLabel").grid(row=2, column=2, sticky="w")
        self.sp_prn_mg = tk.Spinbox(prn_card, from_=0, to=0, increment=1, width=8)
        self.sp_prn_mg.grid(row=3, column=2, sticky="w")

        ttk.Label(prn_card, text="Powód (wpisz)", style="Muted.TLabel").grid(row=2, column=3, sticky="w", padx=(10, 0))
        self.e_prn_reason = ttk.Entry(prn_card, width=22)
        self.e_prn_reason.grid(row=3, column=3, sticky="we", padx=(10, 0))

        ttk.Label(prn_card, text="Uwagi (opc.)", style="Muted.TLabel").grid(row=2, column=4, sticky="w", padx=(10, 0))
        self.e_prn_notes2 = ttk.Entry(prn_card, width=28)
        self.e_prn_notes2.grid(row=3, column=4, sticky="we", padx=(10, 0))

        self.lbl_prn_limits2 = ttk.Label(prn_card, text="", style="Muted.TLabel")
        self.lbl_prn_limits2.grid(row=4, column=0, columnspan=6, sticky="w", pady=(10, 0))

        ttk.Button(prn_card, text="PODAJ PRN", style="Primary.TButton", command=self._give_prn_from_combo).grid(
            row=3, column=5, padx=(12, 0), sticky="e"
        )

        prn_card.columnconfigure(4, weight=1)
        self.cb_prn2.bind("<<ComboboxSelected>>", lambda e: self._update_prn_limits_combo())

    def refresh_give_page(self):
        self.lbl_blocks_give.configure(text=active_blocks_text())
        self._refresh_today_into(self.give_today_list.inner)
        self._refresh_prn_combo(self.cb_prn2)
        self._update_prn_limits_combo()

    # =================== NURSE: KALENDARZ (DODATEK) ===================
    def build_calendar_page(self):
        self.cal_selected_date = date.today()
        self.cal_year = self.cal_selected_date.year
        self.cal_month = self.cal_selected_date.month

        page = ttk.Frame(self.tab_cal, style="Page.TFrame")
        page.pack(fill="both", expand=True)

        top = ttk.Frame(page)
        top.pack(fill="x")
        ttk.Label(top, text="Kalendarz dawek (podgląd)", style="Title.TLabel").pack(side="left")
        ttk.Button(top, text="Odśwież", style="Soft.TButton", command=self.refresh_calendar_page).pack(side="right")

        self.render_patient_header(page)

        self.lbl_blocks_cal = ttk.Label(page, text="", style="Danger.TLabel")
        self.lbl_blocks_cal.pack(anchor="w", pady=(2, 6))

        card = ttk.Frame(page, style="Card.TFrame", padding=10)
        card.pack(fill="x", pady=(0, 10))

        head = ttk.Frame(card)
        head.pack(fill="x")

        ttk.Button(head, text="◀", style="Soft.TButton", width=3, command=lambda: self._cal_shift_month(-1)).pack(side="left")
        self.lbl_cal = ttk.Label(head, text="", style="H1.TLabel")
        self.lbl_cal.pack(side="left", padx=10)
        ttk.Button(head, text="▶", style="Soft.TButton", width=3, command=lambda: self._cal_shift_month(1)).pack(side="left")

        ttk.Separator(head, orient="vertical").pack(side="left", fill="y", padx=10)

        # szybkie przejście po roku/miesiącu (bez przycisków w komórkach)
        self.cb_year = ttk.Combobox(head, state="readonly", width=6, values=[str(y) for y in range(date.today().year-5, date.today().year+6)])
        self.cb_year.set(str(self.cal_year))
        self.cb_year.pack(side="left")
        self.cb_month = ttk.Combobox(head, state="readonly", width=10,
                                     values=["01","02","03","04","05","06","07","08","09","10","11","12"])
        self.cb_month.set(f"{self.cal_month:02d}")
        self.cb_month.pack(side="left", padx=6)
        ttk.Button(head, text="Idź", style="Soft.TButton", command=self._cal_goto).pack(side="left")
        ttk.Button(head, text="Dziś", style="Soft.TButton", command=self._cal_today).pack(side="right")

        self.cal_grid = ttk.Frame(card)
        self.cal_grid.pack(fill="x", pady=(10, 0))

        self.cal_legend = ttk.Label(page, text="", style="Muted.TLabel")
        self.cal_legend.pack(anchor="w", pady=(0, 8))

        self.cal_day_list = ScrollableFrame(page)
        self.cal_day_list.pack(fill="both", expand=True, pady=(6, 0))

        self._render_calendar()

    def refresh_calendar_page(self):
        if not hasattr(self, "lbl_blocks_cal"):
            return
        self.lbl_blocks_cal.configure(text=active_blocks_text())
        self._render_calendar()
        self._refresh_calendar_day_list()


    def _cal_today(self):
        self.cal_selected_date = date.today()
        self.cal_year = self.cal_selected_date.year
        self.cal_month = self.cal_selected_date.month
        if hasattr(self, "cb_year"):
            self.cb_year.set(str(self.cal_year))
        if hasattr(self, "cb_month"):
            self.cb_month.set(f"{self.cal_month:02d}")
        self._render_calendar()
        self._refresh_calendar_day_list()

    def _cal_goto(self):
        try:
            y = int(self.cb_year.get())
            m = int(self.cb_month.get())
            self.cal_year, self.cal_month = y, m
            self.cal_selected_date = date(self.cal_year, self.cal_month, 1)
            self._render_calendar()
            self._refresh_calendar_day_list()
        except Exception:
            messagebox.showerror("Kalendarz", "Nieprawidłowy rok/miesiąc.")

    def _cal_shift_month(self, delta: int):
        y, m = self.cal_year, self.cal_month
        m += delta
        while m < 1:
            m += 12
            y -= 1
        while m > 12:
            m -= 12
            y += 1
        self.cal_year, self.cal_month = y, m
        if hasattr(self, "cb_year"):
            self.cb_year.set(str(y))
        if hasattr(self, "cb_month"):
            self.cb_month.set(f"{m:02d}")
        self.cal_selected_date = date(y, m, 1)
        self._render_calendar()
        self._refresh_calendar_day_list()


    def _render_calendar(self):
        # prosty kalendarz: dni + kolorowe znaczniki leków (wg meds.color_hex)
        for w in self.cal_grid.winfo_children():
            w.destroy()

        y, m = self.cal_year, self.cal_month
        self.lbl_cal.configure(text=f"{y}-{m:02d}")

        colors = getattr(self, "theme_colors", {}) or {}
        bg = colors.get("card") or "#ffffff"
        fg = colors.get("fg") or "#111111"
        border = colors.get("border") or "#d0d0d0"
        off = colors.get("cal_off") or "#999"

        # nagłówki dni tygodnia
        headers = ["Pn", "Wt", "Śr", "Cz", "Pt", "So", "Nd"]
        head = ttk.Frame(self.cal_grid)
        head.pack(fill="x")
        for i, h in enumerate(headers):
            lab = tk.Label(head, text=h, width=4, bg=bg, fg=fg, relief="flat")
            lab.grid(row=0, column=i, padx=2, pady=(0, 2))
        for i in range(7):
            head.grid_columnconfigure(i, weight=1)

        grid = ttk.Frame(self.cal_grid)
        grid.pack(fill="x")

        month_weeks = calendar.monthcalendar(y, m)
        today = date.today()

        # cache orders dla miesiąca (dla szybkości)
        orders = db_all("""
            SELECT o.*, m.name AS med_name, m.med_type, m.is_active, m.color_hex
            FROM orders o
            JOIN meds m ON m.med_id=o.med_id
            WHERE o.patient_id=? AND m.is_active=1 AND m.med_type IN ('STAŁY','CZASOWY')
              AND o.status='AKTYWNE'
        """, (current_patient_id(),))

        # pomocniczo: lista kolorów dla dnia
        def colors_for_day(d: date):
            cols = []
            # stałe/czasowe dawki planowane tego dnia
            for o in orders:
                pdt = planned_dt_for_order(o, d)
                if not pdt:
                    continue
                if not order_is_active_at(o, pdt):
                    continue
                c = (o["color_hex"] or "").strip() or None
                if c and c not in cols:
                    cols.append(c)
            return cols[:4]  # max 4 znaczniki

        # klik w dzień
        def pick_day(d: date):
            self.cal_selected_date = d
            self._render_calendar()
            self._refresh_calendar_day_list()

        for r, week in enumerate(month_weeks):
            for c, daynum in enumerate(week):
                if daynum == 0:
                    cell = tk.Frame(grid, bg=bg, bd=1, relief="solid", highlightthickness=0)
                    cell.grid(row=r, column=c, padx=2, pady=2, sticky="nsew")
                    continue

                d = date(y, m, daynum)
                is_today = (d == today)
                is_sel = (d == self.cal_selected_date)

                cell_bg = bg
                if is_sel:
                    cell_bg = colors.get("panel") or bg

                cell = tk.Frame(grid, bg=cell_bg, bd=1, relief="solid", highlightthickness=0)
                cell.grid(row=r, column=c, padx=2, pady=2, sticky="nsew")

                top = tk.Frame(cell, bg=cell_bg)
                top.pack(fill="x")

                num_fg = fg if daynum else off
                if is_today:
                    num_fg = colors.get("note") or fg

                lbl = tk.Label(top, text=str(daynum), bg=cell_bg, fg=num_fg, padx=2)
                lbl.pack(side="left")

                # kolorowe znaczniki (leki)
                mark = tk.Frame(top, bg=cell_bg)
                mark.pack(side="right")
                cols = colors_for_day(d)
                for cc in cols:
                    dot = tk.Frame(mark, bg=cc, width=10, height=10, highlightbackground=border, highlightthickness=1)
                    dot.pack(side="right", padx=1, pady=2)

                # status: czy coś podane/pominięte tego dnia (stałe)
                any_done = False
                any_missed = False
                for o in orders:
                    pdt = planned_dt_for_order(o, d)
                    if not pdt or not order_is_active_at(o, pdt):
                        continue
                    adm = lekarz_exists_for_day_med(pdt, o["med_id"])
                    if adm and adm["status"] == "PODANO":
                        any_done = True
                    if adm and adm["status"] == "POMINIĘTO":
                        any_missed = True

                badge_txt = "✅" if any_done and not any_missed else ("⚠️" if any_missed else "")
                if badge_txt:
                    b = tk.Label(cell, text=badge_txt, bg=cell_bg, fg=fg)
                    b.pack(anchor="e", padx=2, pady=(0, 2))

                # bindowanie kliknięć
                for w in (cell, top, lbl, mark):
                    w.bind("<Button-1>", lambda e, dd=d: pick_day(dd))

        for i in range(7):
            grid.grid_columnconfigure(i, weight=1)

        # legenda
        self.cal_legend.configure(text="Kolory = leki (ustawisz w zakładce LEKI → Kolor). Kliknij dzień, aby zobaczyć plan poniżej.")

    def _refresh_calendar_day_list(self):
        # podgląd: co w planie tego dnia + PRN podane
        container = self.cal_day_list.inner
        for w in container.winfo_children():
            w.destroy()

        d = self.cal_selected_date
        ttk.Label(container, text=f"Dzień: {d.strftime('%Y-%m-%d')}", style="H1.TLabel").pack(anchor="w", pady=(0, 6))

        # planowane dawki (stałe + czasowe)
        orders = db_all("""
            SELECT o.*, m.name AS med_name, m.med_type, m.is_active
            FROM orders o
            JOIN meds m ON m.med_id=o.med_id
            WHERE o.patient_id=? AND m.is_active=1 AND m.med_type IN ('STAŁY','CZASOWY')
            ORDER BY o.priority ASC, o.order_id ASC
        """, (current_patient_id(),))
        items = []
        for o in orders:
            pdt = planned_dt_for_order(o, d)
            if not pdt:
                continue
            if not order_is_active_at(o, pdt):
                continue
            if o["status"] != "AKTYWNE":
                continue
            adm = lekarz_exists_for_day_med(pdt, o["med_id"])
            status = adm["status"] if adm else None
            items.append((pdt.strftime("%H:%M"), o["med_name"], o["dose_text"], status))

        if items:
            for hh, name, dose, st in items:
                chip = "✅" if st == "PODANO" else ("⛔" if st == "POMINIĘTO" else "⬜")
                ttk.Label(container, text=f"{chip} {hh}  •  {name}  •  {dose}", style="TLabel").pack(anchor="w", pady=1)
        else:
            ttk.Label(container, text="Brak planowanych dawek.", style="Muted.TLabel").pack(anchor="w", pady=(0, 6))

        # PRN podane w tym dniu
        t0 = datetime.combine(d, time(0, 0, 0))
        t1 = t0 + timedelta(days=1)
        prn = db_all("""
            SELECT ts, med_name, prn_mg, reason
            FROM administrations
            WHERE patient_id=? AND prn_mg IS NOT NULL AND status='PODANO'
              AND ts >= ? AND ts < ?
            ORDER BY ts ASC
        """, (current_patient_id(), t0.isoformat(timespec="seconds"), t1.isoformat(timespec="seconds")))
        if prn:
            ttk.Label(container, text="PRN podane:", style="H1.TLabel").pack(anchor="w", pady=(10, 4))
            for r in prn:
                hh = datetime.fromisoformat(r["ts"]).strftime("%H:%M")
                ttk.Label(container, text=f"🔵 {hh}  •  {r['med_name']}  •  {r['prn_mg']} mg  •  {r['reason']}",
                          style="TLabel").pack(anchor="w", pady=1)

    def build_today(self):
        page = ttk.Frame(self.tab_today, style="Page.TFrame")
        page.pack(fill="both", expand=True)

        top = ttk.Frame(page)
        top.pack(fill="x")
        ttk.Label(top, text="DZISIAJ", style="Title.TLabel").pack(side="left")
        ttk.Button(top, text="Odśwież", style="Soft.TButton", command=self.refresh_today).pack(side="right")

        self.render_patient_header(page)

        self.lbl_blocks = ttk.Label(page, text="", style="Danger.TLabel")
        self.lbl_blocks.pack(anchor="w", pady=(8, 10))

        self.today_list = ScrollableFrame(page)
        self.today_list.pack(fill="both", expand=True)

    def refresh_today(self):
        self.lbl_blocks.configure(text=active_blocks_text())
        self._refresh_today_into(self.today_list.inner)

    def _refresh_today_into(self, container):
        self._refresh_day_into(container, date.today())
    def _refresh_day_into(self, container, target_date: date):
        for w in container.winfo_children():
            w.destroy()

        now_dt = datetime.now()
        is_today = (target_date == date.today())

        orders = db_all("""
            SELECT o.*, m.name AS med_name, m.notes AS med_notes, m.critical, m.policy, m.drug_class, m.med_type
            FROM orders o
            JOIN meds m ON m.med_id=o.med_id
            WHERE o.patient_id=? AND m.is_active=1
            ORDER BY o.priority ASC, o.order_id ASC
        """, (current_patient_id(),))

        rows = []
        for o in orders:
            if o["med_type"] == "DORAŹNY":
                continue

            pdt = planned_dt_for_order(o, target_date)
            if not pdt:
                continue
            if not order_is_active_at(o, pdt):
                continue
            if o["policy"] == "ZABRONIONY":
                continue
            if is_class_blocked(o["drug_class"]):
                continue

            tit = titration_for_med(o["med_id"])
            dose_text = o["dose_text"]
            change_day = False
            if tit:
                dose_text = f"{titrated_mg_for_day(tit, target_date)} mg"
                change_day = is_change_day(tit, target_date)

            adm_row = lekarz_exists_for_day_med(pdt, o["med_id"])
            status = adm_row["status"] if adm_row else None

            blocked = False
            block_msg = ""
            window = int(o["window_min"])

            if is_today and status != "PODANO":
                delta_min = int((now_dt - pdt).total_seconds() // 60)
                if o["earliest_admin_time"]:
                    earliest = datetime.combine(target_date, parse_hhmm(o["earliest_admin_time"]))
                    if now_dt < earliest:
                        blocked = True
                        block_msg = f"Za wcześnie (od {o['earliest_admin_time']})"
                if o["latest_admin_time"]:
                    latest = datetime.combine(target_date, parse_hhmm(o["latest_admin_time"]))
                    if now_dt > latest:
                        blocked = True
                        block_msg = f"Za późno (do {o['latest_admin_time']})"

                if status is None and not blocked:
                    if -window < delta_min <= window:
                        chip = "🟨 W OKNIE"
                        chip_style = "Note.TLabel"
                    elif delta_min > window:
                        chip = "🟥 ZALEGŁE"
                        chip_style = "Danger.TLabel"
                    else:
                        chip = "⬜ PRZED CZASEM"
                        chip_style = "Muted.TLabel"
            else:
                chip = ""
                chip_style = "Muted.TLabel"

            if status == "PODANO":
                chip = "✅ PODANO"
                chip_style = "Good.TLabel"
            elif status == "POMINIĘTO":
                chip = "⛔ POMINIĘTO"
                chip_style = "Muted.TLabel"
            elif is_today and blocked:
                chip = "⛔ BLOKADA CZASU"
                chip_style = "Danger.TLabel"
            elif not is_today and status is None:
                chip = "⬜"
                chip_style = "Muted.TLabel"

            med_row = db_one("SELECT * FROM meds WHERE med_id=?", (o["med_id"],))
            badge = interactions_badge(med_row)
            slot = o["time_str"] or o["slot_label"] or "?"
            rows.append((o, pdt, status, chip, chip_style, badge, dose_text, blocked, block_msg, change_day, slot, window))

        if not rows:
            ttk.Label(container, text="Brak dawek na ten dzień.", style="Muted.TLabel").pack(anchor="w", pady=20)
            return

        for (o, pdt, status, chip, chip_style, badge, dose_text, blocked, block_msg, change_day, slot, window) in rows:
            card = ttk.Frame(container, style="Card.TFrame", padding=12)
            card.pack(fill="x", pady=6)

            left = ttk.Frame(card)
            left.grid(row=0, column=0, sticky="nsew")

            title = o["med_name"] + (f"  {badge}" if badge else "")
            ttk.Label(left, text=title, style="H1.TLabel").pack(anchor="w")
            ttk.Label(left, text=f"Plan: {pdt.strftime('%H:%M')}  •  Dawka: {dose_text}" + (f"  •  Okno ±{window} min" if is_today else ""),
                      style="Muted.TLabel").pack(anchor="w", pady=(4, 0))

            if change_day:
                ttk.Label(left, text="🟦 Dzień zmiany dawki (titracja)", style="Note.TLabel").pack(anchor="w", pady=(6, 0))
            if is_today and blocked and status is None and block_msg:
                ttk.Label(left, text=f"{block_msg}", style="Danger.TLabel").pack(anchor="w", pady=(6, 0))

            ttk.Label(left, text=chip, style=chip_style).pack(anchor="w", pady=(8, 0))

            right = ttk.Frame(card)
            right.grid(row=0, column=1, sticky="e")

            ttk.Button(right, text="Szczegóły", style="Soft.TButton",
                       command=lambda mid=o["med_id"]: show_med_details(self, mid)).pack(anchor="e", pady=2)

            can_click = is_today
            if status == "PODANO":
                ttk.Button(right, text="PODANO", style="Primary.TButton", state="disabled").pack(anchor="e", pady=2)
            else:
                ttk.Button(
                    right, text="PODANO", style="Primary.TButton",
                    state=("disabled" if (not can_click or blocked) else "normal"),
                    command=lambda o=o, pdt=pdt, slot=slot, dose=dose_text: self.give_scheduled(o, pdt, slot, dose)
                ).pack(anchor="e", pady=2)

            allow_skip = can_click and not (self.user and self.user.get("role") == ROLE_NURSE and int(o["critical"]) == 1)
            if allow_skip:
                ttk.Button(
                    right, text="Pominięto", style="Soft.TButton",
                    command=lambda o=o, pdt=pdt, slot=slot, dose=dose_text: self.skip_scheduled(o, pdt, slot, dose)
                ).pack(anchor="e", pady=2)
            elif can_click and self.user and self.user.get("role") == ROLE_NURSE and int(o["critical"]) == 1:
                ttk.Label(right, text="(krytyczny)", style="Muted.TLabel").pack(anchor="e", pady=(4, 0))

            card.columnconfigure(0, weight=1)


    def give_scheduled(self, order_row, planned_dt, slot, dose_text):
        db_exec("""
            INSERT INTO administrations(patient_id, ts, planned_dt, slot_or_time, med_id, med_name, dose_text, prn_mg, status, who_user_id, who_name, notes, reason)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (current_patient_id(), now_str(), planned_dt.isoformat(timespec="seconds"), slot, order_row["med_id"], order_row["med_name"],
              dose_text, None, "PODANO", self.user["user_id"], self.user["username"], None, None))
        self.refresh_all()

    def skip_scheduled(self, order_row, planned_dt, slot, dose_text):
        reasons = ["", "brak leku", "wymioty", "odmowa", "inne"]
        w = tk.Toplevel(self)
        w.title("Pominięto — powód")
        w.geometry("420x190")

        frm = ttk.Frame(w, style="Page.TFrame")
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text=order_row["med_name"], style="H1.TLabel").pack(anchor="w")
        ttk.Label(frm, text="Powód (opcjonalnie):", style="Muted.TLabel").pack(anchor="w", pady=(8, 4))

        cb = ttk.Combobox(frm, values=reasons, state="readonly")
        cb.current(0)
        cb.pack(fill="x")

        def ok():
            r = cb.get().strip() or None
            db_exec("""
                INSERT INTO administrations(patient_id, ts, planned_dt, slot_or_time, med_id, med_name, dose_text, prn_mg, status, who_user_id, who_name, notes, reason)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (current_patient_id(), now_str(), planned_dt.isoformat(timespec="seconds"), slot, order_row["med_id"], order_row["med_name"],
                  dose_text, None, "POMINIĘTO", self.user["user_id"], self.user["username"], None, r))
            w.destroy()
            self.refresh_all()

        row = ttk.Frame(frm)
        row.pack(fill="x", pady=12)
        ttk.Button(row, text="Anuluj", style="Soft.TButton", command=w.destroy).pack(side="right")
        ttk.Button(row, text="Zapisz", style="Primary.TButton", command=ok).pack(side="right", padx=8)

    # =================== PRN (shared) ===================
    def build_prn(self):
        page = ttk.Frame(self.tab_prn, style="Page.TFrame")
        page.pack(fill="both", expand=True)

        top = ttk.Frame(page)
        top.pack(fill="x")
        ttk.Label(top, text="Doraźne (PRN)", style="Title.TLabel").pack(side="left")
        ttk.Button(top, text="Odśwież", style="Soft.TButton", command=self.refresh_prn).pack(side="right")

        self.render_patient_header(page)

        self.prn_blocks = ttk.Label(page, text="", style="Danger.TLabel")
        self.prn_blocks.pack(anchor="w", pady=(8, 10))

        form = ttk.Frame(page)
        form.pack(fill="x")

        ttk.Label(form, text="Lek", style="Muted.TLabel").grid(row=0, column=0, sticky="w")
        self.cb_prn = ttk.Combobox(form, state="readonly", width=55)
        self.cb_prn.grid(row=1, column=0, sticky="w")

        ttk.Button(form, text="Szczegóły", style="Soft.TButton",
                   command=lambda: self._prn_details_combo(self.cb_prn)).grid(row=1, column=1, padx=8)

        ttk.Label(form, text="mg", style="Muted.TLabel").grid(row=0, column=2, sticky="w")
        self.sp_prn = tk.Spinbox(form, from_=0, to=0, increment=1, width=10)
        self.sp_prn.grid(row=1, column=2, sticky="w", padx=(0, 8))

        ttk.Label(page, text="Powód", style="Muted.TLabel").pack(anchor="w", pady=(10, 2))
        self.e_prn_reason1 = ttk.Entry(page, width=34)
        self.e_prn_reason1.pack(anchor="w")

        ttk.Label(page, text="Uwagi (opcjonalnie)", style="Muted.TLabel").pack(anchor="w", pady=(10, 2))
        self.e_prn_notes = ttk.Entry(page, width=70)
        self.e_prn_notes.pack(anchor="w")

        self.prn_limits = ttk.Label(page, text="", style="Muted.TLabel")
        self.prn_limits.pack(anchor="w", pady=(8, 0))

        ttk.Button(page, text="PODAJ PRN", style="Primary.TButton", command=self.give_prn).pack(anchor="w", pady=14)

        form.columnconfigure(0, weight=1)
        self.cb_prn.bind("<<ComboboxSelected>>", lambda e: self.update_prn_limits())

    def refresh_prn(self):
        self.prn_blocks.configure(text=active_blocks_text())
        self._refresh_prn_combo(self.cb_prn)
        self.update_prn_limits()

    def _refresh_prn_combo(self, combo: ttk.Combobox):
        items = []
        if self.user["role"] == ROLE_ADMIN and not getattr(self,"admin_view_as_doctor",False):
            self.tab_admin = ttk.Frame(self.nb)
            self.nb.add(self.tab_admin, text="ADMIN")
            self.build_admin()
            self.refresh_admin()
        elif self.user["role"] == ROLE_NURSE:
            rows = db_all("""
                SELECT m.med_id, m.name, m.policy, m.drug_class
                FROM prn_permissions p
                JOIN meds m ON m.med_id=p.med_id
                WHERE p.user_id=? AND p.is_active=1 AND m.is_active=1 AND m.med_type='DORAŹNY'
                ORDER BY m.name
            """, (self.user["user_id"],))
            for r in rows:
                if r["policy"] == "ZABRONIONY":
                    continue
                if is_class_blocked(r["drug_class"]):
                    continue
                items.append(f"{r['name']} ({r['med_id']})")
        else:
            rows = db_all("""
                SELECT med_id, name, policy, drug_class
                FROM meds
                WHERE is_active=1 AND med_type='DORAŹNY'
                ORDER BY name
            """)
            for r in rows:
                if r["policy"] == "ZABRONIONY":
                    continue
                if is_class_blocked(r["drug_class"]):
                    continue
                items.append(f"{r['name']} ({r['med_id']})")

        combo["values"] = items
        if items:
            combo.current(0)

    def selected_med_id(self, combo: ttk.Combobox):
        v = combo.get().strip()
        if "(" in v and v.endswith(")"):
            return v.split("(")[-1].replace(")", "").strip()
        return None

    def _prn_details_combo(self, combo: ttk.Combobox):
        mid = self.selected_med_id(combo)
        if mid:
            show_med_details(self, mid)

    def _set_prn_spinbox(self, sp: tk.Spinbox, mg_min: int, mg_max: int, mg_step: int, default_val: int | None = None):
        sp.config(from_=mg_min, to=mg_max, increment=max(1, mg_step))
        if default_val is None:
            default_val = mg_min
        sp.delete(0, "end")
        sp.insert(0, str(default_val))

    def update_prn_limits(self):
        mid = self.selected_med_id(self.cb_prn)
        if not mid:
            self.prn_limits.configure(text="")
            return

        m = db_one("SELECT * FROM meds WHERE med_id=?", (mid,))
        badge = interactions_badge(m)
        badge_txt = f"{badge}  " if badge else ""

        if self.user["role"] == ROLE_ADMIN and not getattr(self,"admin_view_as_doctor",False):
            self.tab_admin = ttk.Frame(self.nb)
            self.nb.add(self.tab_admin, text="ADMIN")
            self.build_admin()
            self.refresh_admin()
        elif self.user["role"] == ROLE_NURSE:
            p = db_one("""
                SELECT * FROM prn_permissions
                WHERE user_id=? AND med_id=? AND is_active=1
            """, (current_patient_id(), self.user["user_id"], mid))
            if not p:
                self.prn_limits.configure(text=f"{badge_txt}Brak uprawnień PRN.")
                return
            self._set_prn_spinbox(self.sp_prn, int(p["mg_min"]), int(p["mg_max"]), int(p["mg_step"]), int(p["mg_min"]))

            used = prn_sum_today(mid)
            last = prn_last_admin(mid)
            last_txt = ""
            if last:
                last_ts = datetime.fromisoformat(last["ts"])
                mins = int((datetime.now() - last_ts).total_seconds() // 60)
                last_txt = f" • ostatnio {last_ts.strftime('%H:%M')} ({mins} min)"
            self.prn_limits.configure(
                text=f"{badge_txt}Zakres {p['mg_min']}-{p['mg_max']} mg (step {p['mg_step']})"
                     f" • limit {p['max_mg_per_day']} mg/d • odstęp {p['min_interval_min']} min"
                     f" • dziś {used} mg{last_txt}"
            )
        else:
            # lekarz też ma limity w bazie (dla podglądu); domyślnie spinbox 1..1000 jeśli brak
            p = db_one("SELECT * FROM prn_permissions WHERE med_id=? AND is_active=1 ORDER BY prn_id DESC LIMIT 1", (mid,))
            if p:
                self._set_prn_spinbox(self.sp_prn, int(p["mg_min"]), int(p["mg_max"]), int(p["mg_step"]), int(p["mg_min"]))
            else:
                self._set_prn_spinbox(self.sp_prn, 1, 1000, 1, 1)
            self.prn_limits.configure(text=f"{badge_txt}Lekarz: podgląd PRN, podanie zapisze się w historii.")

    # nurse combined PRN widgets
    def _update_prn_limits_combo(self):
        mid = self.selected_med_id(self.cb_prn2)
        if not mid:
            self.lbl_prn_limits2.configure(text="")
            self.sp_prn_mg.config(from_=0, to=0, increment=1)
            return

        m = db_one("SELECT * FROM meds WHERE med_id=?", (mid,))
        badge = interactions_badge(m)
        badge_txt = f"{badge}  " if badge else ""

        p = db_one("""
            SELECT * FROM prn_permissions
            WHERE patient_id=? AND user_id=? AND med_id=? AND is_active=1
        """, (current_patient_id(), self.user["user_id"], mid))
        if not p:
            self.lbl_prn_limits2.configure(text=f"{badge_txt}Brak uprawnień PRN.")
            self.sp_prn_mg.config(from_=0, to=0, increment=1)
            return

        self._set_prn_spinbox(self.sp_prn_mg, int(p["mg_min"]), int(p["mg_max"]), int(p["mg_step"]), int(p["mg_min"]))

        used = prn_sum_today(mid)
        last = prn_last_admin(mid)
        last_txt = ""
        if last:
            last_ts = datetime.fromisoformat(last["ts"])
            mins = int((datetime.now() - last_ts).total_seconds() // 60)
            last_txt = f" • ostatnio {last_ts.strftime('%H:%M')} ({mins} min)"

        self.lbl_prn_limits2.configure(
            text=f"{badge_txt}Zakres {p['mg_min']}-{p['mg_max']} mg (step {p['mg_step']})"
                 f" • limit {p['max_mg_per_day']} mg/d • odstęp {p['min_interval_min']} min"
                 f" • dziś {used} mg{last_txt}"
        )

    def _give_prn_from_combo(self):
        # nurse-only page
        self._give_prn_internal(
            combo=self.cb_prn2,
            mg_getter=lambda: int(str(self.sp_prn_mg.get()).strip() or "0"),
            reason_getter=lambda: self.e_prn_reason.get().strip(),
            notes_getter=lambda: self.e_prn_notes2.get().strip() or None,
            clear_after=lambda: (self.e_prn_notes2.delete(0, "end"), self.e_prn_reason.delete(0, "end"))
        )

    def give_prn(self):
        self._give_prn_internal(
            combo=self.cb_prn,
            mg_getter=lambda: int(str(self.sp_prn.get()).strip() or "0"),
            reason_getter=lambda: self.e_prn_reason1.get().strip(),
            notes_getter=lambda: self.e_prn_notes.get().strip() or None,
            clear_after=lambda: (self.e_prn_notes.delete(0, "end"))
        )

    def _give_prn_internal(self, combo, mg_getter, reason_getter, notes_getter, clear_after):
        mid = self.selected_med_id(combo)
        if not mid:
            messagebox.showerror("PRN", "Wybierz lek.")
            return

        try:
            mg = int(mg_getter())
        except Exception:
            messagebox.showerror("PRN", "Mg musi być liczbą.")
            return
        if mg <= 0:
            messagebox.showerror("PRN", "Mg musi być > 0.")
            return

        reason = (reason_getter() or "").strip()
        if not reason:
            messagebox.showerror("PRN", "Wpisz powód.")
            return

        m = db_one("SELECT * FROM meds WHERE med_id=?", (mid,))
        if not m:
            messagebox.showerror("PRN", "Brak leku w bazie.")
            return
        if m["med_type"] != "DORAŹNY":
            messagebox.showerror("PRN", "Ten lek nie jest oznaczony jako DORAŹNY.")
            return
        if m["policy"] == "ZABRONIONY" or is_class_blocked(m["drug_class"]):
            messagebox.showerror("PRN", "Ten lek jest zbanowany / zablokowany w profilu.")
            return
        if m["policy"] == "TYLKO_LEKARZ" and self.user["role"] != ROLE_DOCTOR:
            messagebox.showerror("PRN", "Tylko lekarz może podać ten lek.")
            return

        # pielęgniarka: twarde limity z prn_permissions
        if self.user["role"] == ROLE_ADMIN and not getattr(self,"admin_view_as_doctor",False):
            self.tab_admin = ttk.Frame(self.nb)
            self.nb.add(self.tab_admin, text="ADMIN")
            self.build_admin()
            self.refresh_admin()
        elif self.user["role"] == ROLE_NURSE:
            p = db_one("""
                SELECT * FROM prn_permissions
                WHERE user_id=? AND med_id=? AND is_active=1
            """, (current_patient_id(), self.user["user_id"], mid))
            if not p:
                messagebox.showerror("PRN", "Brak uprawnień PRN.")
                return
            if mg < int(p["mg_min"]) or mg > int(p["mg_max"]):
                messagebox.showerror("PRN", "Poza zakresem mg na dawkę.")
                return
            # krok mg
            step = max(1, int(p["mg_step"]))
            if (mg - int(p["mg_min"])) % step != 0:
                messagebox.showerror("PRN", f"Nieprawidłowy krok dawki (step={step}).")
                return
            used = prn_sum_today(mid)
            if used + mg > int(p["max_mg_per_day"]):
                messagebox.showerror("PRN", "Przekroczysz limit dobowy.")
                return
            last = prn_last_admin(mid)
            if last:
                last_ts = datetime.fromisoformat(last["ts"])
                mins = int((datetime.now() - last_ts).total_seconds() // 60)
                if mins < int(p["min_interval_min"]):
                    messagebox.showerror("PRN", f"Za wcześnie. Min odstęp {p['min_interval_min']} min, minęło {mins}.")
                    return

        notes = notes_getter()
        db_exec("""
            INSERT INTO administrations(patient_id, ts, planned_dt, slot_or_time, med_id, med_name, dose_text, prn_mg, status, who_user_id, who_name, notes, reason)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (current_patient_id(), now_str(), None, "PRN", mid, m["name"], "", mg, "PODANO",
              self.user["user_id"], self.user["username"], notes, reason))

        clear_after()
        self.refresh_all()

    # =================== HISTORY ===================
    def build_history(self):
        page = ttk.Frame(self.tab_hist, style="Page.TFrame")
        page.pack(fill="both", expand=True)

        top = ttk.Frame(page)
        top.pack(fill="x")
        ttk.Label(top, text="Historia", style="Title.TLabel").pack(side="left")
        ttk.Button(top, text="Odśwież", style="Soft.TButton", command=self.refresh_history).pack(side="right")

        cols = ("ts", "status", "lek", "dawka", "plan", "kto", "powod")
        self.tree = ttk.Treeview(page, columns=cols, show="headings", height=18)
        headings = [("ts", "CZAS", 160), ("status", "STATUS", 110), ("lek", "LEK", 300),
                    ("dawka", "DAWKA", 120), ("plan", "PLAN", 160), ("kto", "KTO", 140), ("powod", "POWÓD", 220)]
        for key, title, w in headings:
            self.tree.heading(key, text=title)
            self.tree.column(key, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True, pady=10)

    def refresh_history(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        rows = db_all("SELECT * FROM administrations WHERE patient_id=? ORDER BY ts DESC LIMIT 800", (current_patient_id(),))
        for r in rows:
            ts = r["ts"].replace("T", " ")
            plan = "PRN" if not r["planned_dt"] else f"{datetime.fromisoformat(r['planned_dt']).strftime('%H:%M')} ({r['slot_or_time']})"
            dawka = f"{r['prn_mg']} mg" if r["prn_mg"] is not None else r["dose_text"]
            powod = r["reason"] or ""
            self.tree.insert("", "end", values=(ts, r["status"], r["med_name"], dawka, plan, r["who_name"], powod))

    # =================== LEKARZ (ustawienia) ===================
    def build_lekarz(self):
        page = ScrollableFrame(self.tab_lekarz)
        page.pack(fill="both", expand=True)

        content = page.inner


        self.lekarz_nb = ttk.Notebook(content)
        self.lekarz_nb.pack(fill="both", expand=True)

        self.ad_patient = ttk.Frame(self.lekarz_nb)
        self.ad_doctor = ttk.Frame(self.lekarz_nb)
        self.ad_blocks = ttk.Frame(self.lekarz_nb)
        self.ad_meds = ttk.Frame(self.lekarz_nb)
        self.ad_orders = ttk.Frame(self.lekarz_nb)
        self.ad_titr = ttk.Frame(self.lekarz_nb)
        self.ad_prn = ttk.Frame(self.lekarz_nb)
        self.ad_users = ttk.Frame(self.lekarz_nb)

        self.lekarz_nb.add(self.ad_patient, text="PACJENT")
        self.lekarz_nb.add(self.ad_doctor, text="LEKARZ")
        self.lekarz_nb.add(self.ad_orders, text="ZLECENIA")
        self.lekarz_nb.add(self.ad_prn, text="PRN LIMITY")
        self.lekarz_nb.add(self.ad_meds, text="LEKI")
        self.lekarz_nb.add(self.ad_blocks, text="BLOKADY")
        self.lekarz_nb.add(self.ad_titr, text="TITRACJE")
        self.lekarz_nb.add(self.ad_users, text="UŻYTKOWNICY")

        self.lekarz_patient_ui()
        self.lekarz_doctor_ui()
        self.lekarz_blocks_ui()
        self.lekarz_meds_ui()
        self.lekarz_orders_ui()
        self.lekarz_titr_ui()
        self.lekarz_prn_ui()
        self.lekarz_users_ui()

    def refresh_lekarz(self):
        self.lekarz_patient_refresh()
        self.lekarz_blocks_refresh()
        self.lekarz_meds_refresh()
        self.lekarz_orders_refresh()
        self.lekarz_titr_refresh()
        self.lekarz_prn_refresh()
        self.lekarz_users_refresh()

    # --- patient ---
    def lekarz_patient_ui(self):
        page = ttk.Frame(self.ad_patient, style="Page.TFrame")
        page.pack(fill="both", expand=True)

        ttk.Label(page, text="Profil pacjenta", style="Title.TLabel").pack(anchor="w")
        ttk.Label(page, text="Tu lekarz wpisuje dane pacjenta.",
                  style="Muted.TLabel").pack(anchor="w", pady=(2, 10))

        self.render_patient_header(page)

        # szybkie dodawanie pacjenta
        tools = ttk.Frame(page)
        tools.pack(fill="x", pady=(0, 8))
        ttk.Button(tools, text="Dodaj pacjenta", style="Soft.TButton", command=self._add_patient_dialog).pack(side="left")
        ttk.Button(tools, text="Zmień kolor pacjenta", style="Soft.TButton", command=self._pick_patient_color).pack(side="left", padx=8)

        form = ttk.Frame(page)
        form.pack(fill="x", pady=8)

        def row(label, width=45):
            r = ttk.Frame(form)
            r.pack(fill="x", pady=3)
            ttk.Label(r, text=label, style="Muted.TLabel", width=18).pack(side="left")
            e = ttk.Entry(r, width=width)
            e.pack(side="left", fill="x", expand=True)
            return e

        self.e_p_display = row("Nazwa (krótko)")
        self.e_p_full = row("Imię i nazwisko")
        self.e_p_pesel = row("PESEL")
        self.e_p_birth = row("Data ur. (YYYY-MM-DD)")
        self.e_p_addr = row("Adres")

        ttk.Label(page, text="Alergie", style="Muted.TLabel").pack(anchor="w", pady=(10, 2))
        self.t_p_all = tk.Text(page, height=3, wrap="word")
        self.t_p_all.pack(fill="x")

        ttk.Label(page, text="Choroby przewlekłe", style="Muted.TLabel").pack(anchor="w", pady=(10, 2))
        self.t_p_chron = tk.Text(page, height=3, wrap="word")
        self.t_p_chron.pack(fill="x")

        ttk.Label(page, text="Kontakt alarmowy", style="Muted.TLabel").pack(anchor="w", pady=(10, 2))
        self.e_p_em = ttk.Entry(page, width=70)
        self.e_p_em.pack(anchor="w")

        ttk.Label(page, text="Notatki lekarza (opc.)", style="Muted.TLabel").pack(anchor="w", pady=(10, 2))
        self.t_p_notes = tk.Text(page, height=3, wrap="word")
        self.t_p_notes.pack(fill="x")


        btns = ttk.Frame(page)
        btns.pack(fill="x", pady=12)
        ttk.Button(btns, text="Zapisz profil", style="Primary.TButton", command=self.lekarz_save_patient).pack(side="left")
        ttk.Button(btns, text="Odśwież", style="Soft.TButton", command=self.lekarz_patient_refresh).pack(side="left", padx=8)

        self.lekarz_patient_refresh()

    def lekarz_patient_refresh(self):
        pr = patient_row()
        self.e_p_display.delete(0, "end"); self.e_p_display.insert(0, pr["display_name"] or "")
        self.e_p_full.delete(0, "end"); self.e_p_full.insert(0, pr["full_name"] or "")
        self.e_p_pesel.delete(0, "end"); self.e_p_pesel.insert(0, pr["pesel"] or "")
        self.e_p_birth.delete(0, "end"); self.e_p_birth.insert(0, pr["birth_date"] or "")
        self.e_p_addr.delete(0, "end"); self.e_p_addr.insert(0, pr["address"] or "")

        def set_text(tw: tk.Text, v: str | None):
            tw.delete("1.0", "end")
            if v:
                tw.insert("1.0", v)

        set_text(self.t_p_all, pr["allergies"])
        set_text(self.t_p_chron, pr["chronic_conditions"])
        self.e_p_em.delete(0, "end"); self.e_p_em.insert(0, pr["emergency_contact"] or "")
        set_text(self.t_p_notes, pr["doctor_notes"])

    def lekarz_save_patient(self):
        display = self.e_p_display.get().strip() or "Pacjent"
        full = self.e_p_full.get().strip() or None
        pesel = self.e_p_pesel.get().strip() or None
        b = self.e_p_birth.get().strip() or None
        addr = self.e_p_addr.get().strip() or None

        if b:
            try:
                date.fromisoformat(b)
            except Exception:
                messagebox.showerror("Pacjent", "Data urodzenia: zły format (YYYY-MM-DD).")
                return

        allergies = self.t_p_all.get("1.0", "end").strip() or None
        chron = self.t_p_chron.get("1.0", "end").strip() or None
        em = self.e_p_em.get().strip() or None
        notes = self.t_p_notes.get("1.0", "end").strip() or None

        db_exec("""
            UPDATE patients
            SET display_name=?, full_name=?, pesel=?, birth_date=?, address=?,
                allergies=?, chronic_conditions=?, emergency_contact=?, doctor_notes=?,
                id_photo_path=?, updated_at=?
            WHERE patient_id=?
        """, (display, full, pesel, b, addr, allergies, chron, em, notes, None, now_str(), current_patient_id()))

        messagebox.showinfo("Pacjent", "Zapisano.")
        self.refresh_all()

    def _add_patient_dialog(self):
        win = tk.Toplevel(self)
        win.title("Dodaj pacjenta")
        win.geometry("420x240")

        frm = ttk.Frame(win, style="Page.TFrame")
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="Nowy pacjent", style="Title.TLabel").pack(anchor="w")
        ttk.Label(frm, text="Wpisz przynajmniej nazwę wyświetlaną.", style="Muted.TLabel").pack(anchor="w", pady=(2, 10))

        row1 = ttk.Frame(frm)
        row1.pack(fill="x", pady=6)
        ttk.Label(row1, text="Nazwa (wyświetlana)", style="Muted.TLabel").pack(anchor="w")
        e_disp = ttk.Entry(row1, width=40)
        e_disp.pack(anchor="w", fill="x")

        row2 = ttk.Frame(frm)
        row2.pack(fill="x", pady=6)
        ttk.Label(row2, text="Imię i nazwisko (opc.)", style="Muted.TLabel").pack(anchor="w")
        e_full = ttk.Entry(row2, width=40)
        e_full.pack(anchor="w", fill="x")

        btns = ttk.Frame(frm)
        btns.pack(fill="x", pady=(14, 0))

        def create():
            disp = e_disp.get().strip()
            if not disp:
                messagebox.showerror("Pacjent", "Podaj nazwę wyświetlaną.")
                return
            full = e_full.get().strip() or None
            db_exec(
                "INSERT INTO patients(display_name, full_name, created_at, updated_at) VALUES (?,?,?,?)",
                (disp, full, now_str(), now_str())
            )
            new_id = db_one("SELECT MAX(patient_id) AS m FROM patients")["m"]
            set_current_patient_id(int(new_id))
            try:
                win.destroy()
            except Exception:
                pass
            self.refresh_all()

        ttk.Button(btns, text="Utwórz", style="Primary.TButton", command=create).pack(side="right")
        ttk.Button(btns, text="Anuluj", style="Soft.TButton", command=win.destroy).pack(side="right", padx=8)

    def _pick_patient_color(self):
        pr = patient_row()
        initial = pr["color_hex"] or "#4f46e5"
        c = colorchooser.askcolor(initialcolor=initial)[1]
        if not c:
            return
        db_exec("UPDATE patients SET color_hex=?, updated_at=? WHERE patient_id=?", (c, now_str(), current_patient_id()))
        self.refresh_all()


    def lekarz_doctor_ui(self):
        page = ttk.Frame(self.ad_doctor, style="Page.TFrame")
        page.pack(fill="both", expand=True)

        ttk.Label(page, text="Dane lekarza", style="Title.TLabel").pack(anchor="w")
        ttk.Label(page, text="Te dane pojawią się w nagłówku (np. wydruki / opis).", style="Muted.TLabel").pack(anchor="w", pady=(2, 10))

        form = ttk.Frame(page)
        form.pack(fill="x", pady=6)

        def row(label, width=50):
            r = ttk.Frame(form)
            r.pack(fill="x", pady=4)
            ttk.Label(r, text=label, width=18, style="Muted.TLabel").pack(side="left")
            e = ttk.Entry(r, width=width)
            e.pack(side="left", fill="x", expand=True)
            return e

        self.e_d_full = row("Imię i nazwisko")
        self.e_d_pwz = row("PWZ (opc.)", 20)
        self.e_d_phone = row("Telefon (opc.)", 20)
        self.e_d_clinic = row("Placówka (opc.)", 50)

        ttk.Label(form, text="Uwagi (opc.)", style="Muted.TLabel").pack(anchor="w", pady=(10, 2))
        self.t_d_notes = tk.Text(form, height=5, wrap="word")
        self.t_d_notes.pack(fill="x")

        btns = ttk.Frame(page)
        btns.pack(fill="x", pady=(10, 0))
        ttk.Button(btns, text="Zapisz", style="Primary.TButton", command=self.lekarz_save_doctor).pack(side="left")
        ttk.Button(btns, text="Odśwież", style="Soft.TButton", command=self.lekarz_doctor_refresh).pack(side="left", padx=8)

        self.lekarz_doctor_refresh()

    def lekarz_doctor_refresh(self):
        d = db_one("SELECT * FROM doctor_profile WHERE doctor_id=1")
        if not d:
            return
        self.e_d_full.delete(0, "end"); self.e_d_full.insert(0, d["full_name"] or "")
        self.e_d_pwz.delete(0, "end"); self.e_d_pwz.insert(0, d["pwz"] or "")
        self.e_d_phone.delete(0, "end"); self.e_d_phone.insert(0, d["phone"] or "")
        self.e_d_clinic.delete(0, "end"); self.e_d_clinic.insert(0, d["clinic"] or "")
        self.t_d_notes.delete("1.0", "end"); self.t_d_notes.insert("1.0", d["notes"] or "")

    def lekarz_save_doctor(self):
        full = self.e_d_full.get().strip() or "Lekarz"
        pwz = self.e_d_pwz.get().strip() or None
        phone = self.e_d_phone.get().strip() or None
        clinic = self.e_d_clinic.get().strip() or None
        notes = self.t_d_notes.get("1.0", "end").strip() or None

        db_exec("""
            UPDATE doctor_profile
            SET full_name=?, pwz=?, phone=?, clinic=?, notes=?, updated_at=?
            WHERE doctor_id=1
        """, (full, pwz, phone, clinic, notes, now_str()))

        messagebox.showinfo("Lekarz", "Zapisano.")
        self.refresh_all()

    # --- blocks ---
    def lekarz_blocks_ui(self):
        page = ttk.Frame(self.ad_blocks, style="Page.TFrame")
        page.pack(fill="both", expand=True)

        ttk.Label(page, text="Blokady profilu", style="Title.TLabel").pack(anchor="w")
        ttk.Label(page, text="Np. BENZODIAZEPINY. Blokada działa globalnie (DZISIAJ i PRN).",
                  style="Muted.TLabel").pack(anchor="w", pady=(2, 10))

        self.blocks_tree = ttk.Treeview(page, columns=("id","value","status","reason","created"), show="headings", height=10)
        for c,t,w in [("id","ID",60),("value","WARTOŚĆ",220),("status","STATUS",110),("reason","POWÓD",280),("created","UTWORZONO",220)]:
            self.blocks_tree.heading(c, text=t)
            self.blocks_tree.column(c, width=w, anchor="w")
        self.blocks_tree.pack(fill="x")

        form = ttk.Frame(page)
        form.pack(fill="x", pady=12)

        ttk.Label(form, text="Dodaj klasę:", style="Muted.TLabel").grid(row=0, column=0, sticky="w")
        self.e_cls = ttk.Entry(form, width=25); self.e_cls.grid(row=1, column=0, sticky="w")
        ttk.Label(form, text="Powód:", style="Muted.TLabel").grid(row=0, column=1, sticky="w", padx=(12,0))
        self.e_cls_reason = ttk.Entry(form, width=40); self.e_cls_reason.grid(row=1, column=1, sticky="w", padx=(12,0))
        ttk.Button(form, text="Dodaj", style="Primary.TButton", command=self.lekarz_add_block).grid(row=1, column=2, padx=12)

        form2 = ttk.Frame(page)
        form2.pack(fill="x", pady=(0, 10))
        ttk.Label(form2, text="Zdejmij ID:", style="Muted.TLabel").grid(row=0, column=0, sticky="w")
        self.e_bid = ttk.Entry(form2, width=10); self.e_bid.grid(row=1, column=0, sticky="w")
        ttk.Label(form2, text="Powód zdjęcia:", style="Muted.TLabel").grid(row=0, column=1, sticky="w", padx=(12,0))
        self.e_lift_reason = ttk.Entry(form2, width=40); self.e_lift_reason.grid(row=1, column=1, sticky="w", padx=(12,0))
        ttk.Button(form2, text="Zdejmij", style="Soft.TButton", command=self.lekarz_lift_block).grid(row=1, column=2, padx=12)

        ttk.Button(page, text="Odśwież", style="Soft.TButton", command=self.lekarz_blocks_refresh).pack(anchor="w")

    def lekarz_blocks_refresh(self):
        for i in self.blocks_tree.get_children():
            self.blocks_tree.delete(i)
        rows = db_all("SELECT block_id, block_value, status, reason, created_at FROM blocks WHERE patient_id=? ORDER BY block_id DESC", (current_patient_id(),))
        for r in rows:
            self.blocks_tree.insert("", "end", values=(r["block_id"], r["block_value"], r["status"], r["reason"] or "", r["created_at"]))

    def lekarz_add_block(self):
        cls = self.e_cls.get().strip().upper()
        reason = self.e_cls_reason.get().strip() or None
        if not cls:
            messagebox.showerror("Blokady", "Podaj klasę.")
            return
        db_exec("""
            INSERT INTO blocks(patient_id, block_type, block_value, status, reason, created_at)
            VALUES (?,'KLASA',?,'AKTYWNA',?,?)
        """, (current_patient_id(), cls, reason, now_str()))
        self.e_cls.delete(0, "end")
        self.e_cls_reason.delete(0, "end")
        self.refresh_all()

    def lekarz_lift_block(self):
        try:
            bid = int(self.e_bid.get().strip())
        except ValueError:
            messagebox.showerror("Blokady", "Podaj poprawne ID.")
            return
        lr = self.e_lift_reason.get().strip() or None
        db_exec("""
            UPDATE blocks
            SET status='ZDJĘTA', lifted_at=?, lifted_by=?, lift_reason=?
            WHERE block_id=?
        """, (current_patient_id(), now_str(), self.user["user_id"], lr, bid))
        self.e_bid.delete(0, "end")
        self.e_lift_reason.delete(0, "end")
        self.refresh_all()

    # --- meds ---
    def lekarz_meds_ui(self):
        page = ttk.Frame(self.ad_meds, style="Page.TFrame")
        page.pack(fill="both", expand=True)

        ttk.Label(page, text="Leki", style="Title.TLabel").pack(anchor="w")
        ttk.Label(page, text="Lekarz wpisuje pełne dane leków. Pielęgniarka tylko podaje/odhacza.",
                  style="Muted.TLabel").pack(anchor="w", pady=(2, 10))
        topbtns = ttk.Frame(page)
        topbtns.pack(fill="x", pady=(0, 10))
        ttk.Button(topbtns, text="Import bazy leków (URPL CSV)", style="Soft.TButton", command=self.import_drugs_catalog).pack(side="left")
        src = get_setting("drugs_catalog_source_date", "")
        imp = get_setting("drugs_catalog_imported_at", "")
        if src or imp:
            ttk.Label(topbtns, text=f"Słownik: {src or 'brak daty'}  •  import: {imp or 'brak'}", style="Muted.TLabel").pack(side="left", padx=12)


        self.meds_tree = ttk.Treeview(page, columns=("id","name","type","policy","class","active"), show="headings", height=8)
        for c,t,w in [("id","ID",120),("name","NAZWA",260),("type","TYP",120),("policy","POLICY",120),("class","KLASA",180),("active","AKT",60)]:
            self.meds_tree.heading(c, text=t)
            self.meds_tree.column(c, width=w, anchor="w")
        self.meds_tree.pack(fill="x")
        self.meds_tree.bind("<<TreeviewSelect>>", lambda e: self.lekarz_meds_load_selected())

        form = ttk.Frame(page)
        form.pack(fill="both", expand=True, pady=10)

        def line(label, row, width=38):
            ttk.Label(form, text=label, style="Muted.TLabel").grid(row=row*2, column=0, sticky="w", pady=(6, 0))
            e = ttk.Entry(form, width=width)
            e.grid(row=row*2+1, column=0, sticky="w")
            return e

        self.e_mid = line("Lek_ID (np. L001)", 0)
        self.e_mname = line("Nazwa", 1)
        self.e_form = line("Forma", 2)
        self.e_defdose = line("Domyślna dawka (tekst)", 3)
        self.e_class = line("Klasa (opc.)", 4)
        self.e_group = line("Grupa zamienników (opc.)", 5)
        self.e_max = line("Max / zasady (tekst)", 6)

        right = ttk.Frame(form)
        right.grid(row=0, column=1, rowspan=14, sticky="n", padx=18)

        ttk.Label(right, text="Typ", style="Muted.TLabel").pack(anchor="w")
        self.cb_mtype = ttk.Combobox(right, values=["STAŁY", "CZASOWY", "DORAŹNY"], state="readonly", width=18)
        self.cb_mtype.set("STAŁY")
        self.cb_mtype.pack(anchor="w", pady=(0, 8))

        ttk.Label(right, text="Policy", style="Muted.TLabel").pack(anchor="w")
        self.cb_policy = ttk.Combobox(right, values=["DOZWOLONY", "TYLKO_LEKARZ", "ZABRONIONY"], state="readonly", width=18)
        self.cb_policy.set("DOZWOLONY")
        self.cb_policy.pack(anchor="w", pady=(0, 10))


        ttk.Label(right, text="Kolor leku (#RRGGBB)", style="Muted.TLabel").pack(anchor="w")
        color_row = ttk.Frame(right)
        color_row.pack(anchor="w", pady=(0, 10), fill="x")
        self.e_color_hex = ttk.Entry(color_row, width=12)
        self.e_color_hex.pack(side="left")
        ttk.Button(color_row, text="Wybierz", style="Soft.TButton",
                   command=lambda: self.pick_color_into(self.e_color_hex)).pack(side="left", padx=6)
        ttk.Button(color_row, text="Auto", style="Soft.TButton",
                   command=lambda: (self.e_color_hex.delete(0, "end"), None)).pack(side="left")

        self.v_active = tk.IntVar(value=1)
        self.v_can_stop = tk.IntVar(value=1)
        self.v_critical = tk.IntVar(value=0)
        self.v_reqdoc = tk.IntVar(value=0)

        ttk.Checkbutton(right, text="Aktywny", variable=self.v_active).pack(anchor="w")
        ttk.Checkbutton(right, text="Można odstawić", variable=self.v_can_stop).pack(anchor="w")
        ttk.Checkbutton(right, text="Krytyczny", variable=self.v_critical).pack(anchor="w")
        ttk.Checkbutton(right, text="Wymaga lekarza do wstrzymania", variable=self.v_reqdoc).pack(anchor="w", pady=(0, 10))

        def area(parent, title):
            ttk.Label(parent, text=title, style="Muted.TLabel").grid(sticky="w")
            t = tk.Text(parent, height=3, width=74, wrap="word")
            t.grid(sticky="we", pady=(2, 8))
            return t

        ttk.Separator(form, orient="horizontal").grid(row=14, column=0, columnspan=2, sticky="we", pady=8)

        self.t_notes = area(form, "Instrukcje (np. z jedzeniem)")
        self.t_mech = area(form, "Jak działa")
        self.t_caut = area(form, "Przeciwwskazania / ostrzeżenia")
        self.t_extra = area(form, "Dodatkowe")

        ttk.Label(form, text="Interakcje (1/2/3)", style="H1.TLabel").grid(sticky="w", pady=(4,2))
        self.t_i1 = area(form, f"{ICON_1} Poziom 1")
        self.t_i2 = area(form, f"{ICON_2} Poziom 2")
        self.t_i3 = area(form, f"{ICON_3} Poziom 3")

        btns = ttk.Frame(page)
        btns.pack(fill="x", pady=(0, 8))
        ttk.Button(btns, text="Zapisz lek", style="Primary.TButton", command=self.lekarz_save_med).pack(side="left")
        ttk.Button(btns, text="Odśwież", style="Soft.TButton", command=self.lekarz_meds_refresh).pack(side="left", padx=8)

        form.columnconfigure(0, weight=1)

    def lekarz_meds_refresh(self):
        for i in self.meds_tree.get_children():
            self.meds_tree.delete(i)
        rows = db_all("SELECT med_id, name, med_type, policy, drug_class, is_active FROM meds ORDER BY name")
        for r in rows:
            self.meds_tree.insert("", "end", values=(r["med_id"], r["name"], r["med_type"], r["policy"], r["drug_class"] or "", r["is_active"]))


    def lekarz_meds_load_selected(self):
        sel = self.meds_tree.selection()
        if not sel:
            return
        vals = self.meds_tree.item(sel[0], "values")
        if not vals:
            return
        med_id = vals[0]
        r = db_one("SELECT * FROM meds WHERE med_id=?", (med_id,))
        if not r:
            return
        # pola tekstowe
        self.e_mid.delete(0, "end"); self.e_mid.insert(0, r["med_id"] or "")
        self.e_mname.delete(0, "end"); self.e_mname.insert(0, r["name"] or "")
        self.e_form.delete(0, "end"); self.e_form.insert(0, r["form"] or "")
        self.e_defdose.delete(0, "end"); self.e_defdose.insert(0, r["default_dose_text"] or "")
        self.e_class.delete(0, "end"); self.e_class.insert(0, r["drug_class"] or "")
        self.e_group.delete(0, "end"); self.e_group.insert(0, r["drug_group"] or "")
        self.e_max.delete(0, "end"); self.e_max.insert(0, r["max_dose_text"] or "")

        # combosy / checkboxy
        self.cb_mtype.set(r["med_type"] or "STAŁY")
        self.cb_policy.set(r["policy"] or "DOZWOLONY")
        self.v_active.set(int(r["is_active"] or 0))
        self.v_can_stop.set(int(r["can_stop"] or 0))
        self.v_critical.set(int(r["critical"] or 0))
        self.v_reqdoc.set(int(r["requires_doctor_to_hold"] or 0))

        # kolor
        if hasattr(self, "e_color_hex"):
            self.e_color_hex.delete(0, "end")
            if r["color_hex"]:
                self.e_color_hex.insert(0, str(r["color_hex"]).lower())

        # pola tekstowe wielolinijkowe
        def set_text(tw: tk.Text, v):
            tw.delete("1.0", "end")
            if v:
                tw.insert("1.0", v)

        set_text(self.t_notes, r["notes"])
        set_text(self.t_mech, r["mechanism"])
        set_text(self.t_caut, r["contraindications"])
        set_text(self.t_extra, r["extra_info"])
        set_text(self.t_i1, r["interactions_lvl1"])
        set_text(self.t_i2, r["interactions_lvl2"])
        set_text(self.t_i3, r["interactions_lvl3"])

    def lekarz_save_med(self):
        mid = self.e_mid.get().strip().upper()
        name = self.e_mname.get().strip()
        if not mid or not name:
            messagebox.showerror("LEKI", "Podaj Lek_ID i Nazwę.")
            return


        # kolor (opcjonalnie)
        if hasattr(self, "e_color_hex"):
            cv = self.e_color_hex.get().strip().lower()
            if cv and not (cv.startswith("#") and len(cv) == 7 and all(ch in "0123456789abcdef" for ch in cv[1:])):
                messagebox.showerror("LEKI", "Kolor ma być w formacie #RRGGBB (np. #a0c4ff).")
                return

        def get_text(t: tk.Text):
            v = t.get("1.0", "end").strip()
            return v if v else None

        db_exec("""
            INSERT INTO meds(
                med_id, name, color_hex, form, default_dose_text, notes, is_active,
                med_type, can_stop, critical, requires_doctor_to_hold,
                policy, drug_class, drug_group,
                max_dose_text, mechanism, contraindications, storage, extra_info,
                interactions_lvl1, interactions_lvl2, interactions_lvl3
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(med_id) DO UPDATE SET
                name=excluded.name,
                color_hex=excluded.color_hex,
                form=excluded.form,
                default_dose_text=excluded.default_dose_text,
                notes=excluded.notes,
                is_active=excluded.is_active,
                med_type=excluded.med_type,
                can_stop=excluded.can_stop,
                critical=excluded.critical,
                requires_doctor_to_hold=excluded.requires_doctor_to_hold,
                policy=excluded.policy,
                drug_class=excluded.drug_class,
                drug_group=excluded.drug_group,
                max_dose_text=excluded.max_dose_text,
                mechanism=excluded.mechanism,
                contraindications=excluded.contraindications,
                storage=excluded.storage,
                extra_info=excluded.extra_info,
                interactions_lvl1=excluded.interactions_lvl1,
                interactions_lvl2=excluded.interactions_lvl2,
                interactions_lvl3=excluded.interactions_lvl3
        """, (
            mid, name,
            (self.e_color_hex.get().strip().lower() if hasattr(self,'e_color_hex') and self.e_color_hex.get().strip() else None),
            self.e_form.get().strip() or None,
            self.e_defdose.get().strip() or "",
            get_text(self.t_notes),
            int(self.v_active.get()),
            self.cb_mtype.get(),
            int(self.v_can_stop.get()),
            int(self.v_critical.get()),
            int(self.v_reqdoc.get()),
            self.cb_policy.get(),
            (self.e_class.get().strip().upper() or None),
            (self.e_group.get().strip().upper() or None),
            (self.e_max.get().strip() or None),
            get_text(self.t_mech),
            get_text(self.t_caut),
            None,
            get_text(self.t_extra),
            get_text(self.t_i1),
            get_text(self.t_i2),
            get_text(self.t_i3),
        ))
        messagebox.showinfo("LEKI", "Zapisano.")
        self.refresh_all()

    # --- orders ---
    def lekarz_orders_ui(self):
        page = ttk.Frame(self.ad_orders, style="Page.TFrame")
        page.pack(fill="both", expand=True)

        ttk.Label(page, text="Zlecenia", style="Title.TLabel").pack(anchor="w")
        ttk.Label(page, text="Zlecenia dotyczą tylko leków STAŁY/CZASOWY (DORAŹNY idzie przez PRN).",
                  style="Muted.TLabel").pack(anchor="w", pady=(2, 10))

        self.orders_tree = ttk.Treeview(page, columns=("id","lek","dawka","typ","pora","godz","okno","prio","status","cut"), show="headings", height=10)
        for c,t,w in [("id","ID",60),("lek","LEK",260),("dawka","DAWKA",110),("typ","TYP",90),("pora","PORA",90),("godz","GODZ",70),
                      ("okno","OKNO",80),("prio","P",40),("status","STATUS",110),("cut","CUTOFF",210)]:
            self.orders_tree.heading(c, text=t)
            self.orders_tree.column(c, width=w, anchor="w")
        self.orders_tree.pack(fill="x")

        form = ttk.Frame(page)
        form.pack(fill="x", pady=12)

        ttk.Label(form, text="Lek", style="Muted.TLabel").grid(row=0, column=0, sticky="w")
        self.cb_omed = ttk.Combobox(form, state="normal", width=45)
        self.cb_omed.grid(row=1, column=0, sticky="w")

        def _on_med_type(_e=None):
            try:
                vals = self._catalog_suggest(self.cb_omed.get())
                if vals:
                    self.cb_omed["values"] = vals
            except Exception:
                pass
        self.cb_omed.bind("<KeyRelease>", _on_med_type)
        self.cb_omed.bind("<Down>", lambda _e: self.cb_omed.event_generate("<Button-1>"))


        ttk.Label(form, text="Dawka", style="Muted.TLabel").grid(row=0, column=1, sticky="w", padx=(10,0))
        self.e_odose = ttk.Entry(form, width=18)
        self.e_odose.grid(row=1, column=1, sticky="w", padx=(10,0))

        ttk.Label(form, text="Pora", style="Muted.TLabel").grid(row=0, column=2, sticky="w", padx=(10,0))
        self.cb_oslot = ttk.Combobox(form, values=list(DEFAULT_SLOTS.keys()), state="readonly", width=10)
        self.cb_oslot.set("RANO")
        self.cb_oslot.grid(row=1, column=2, sticky="w", padx=(10,0))

        ttk.Label(form, text="Godzina (opc.)", style="Muted.TLabel").grid(row=0, column=3, sticky="w", padx=(10,0))
        self.e_otime = ttk.Entry(form, width=10)
        self.e_otime.grid(row=1, column=3, sticky="w", padx=(10,0))

        ttk.Label(form, text="Okno (min)", style="Muted.TLabel").grid(row=0, column=4, sticky="w", padx=(10,0))
        self.e_owin = ttk.Entry(form, width=8)
        self.e_owin.insert(0, "60")
        self.e_owin.grid(row=1, column=4, sticky="w", padx=(10,0))

        ttk.Label(form, text="Priorytet", style="Muted.TLabel").grid(row=0, column=5, sticky="w", padx=(10,0))
        self.cb_oprio = ttk.Combobox(form, values=["1","2","3"], state="readonly", width=6)
        self.cb_oprio.set("2")
        self.cb_oprio.grid(row=1, column=5, sticky="w", padx=(10,0))

        ttk.Label(form, text="Earliest", style="Muted.TLabel").grid(row=2, column=0, sticky="w", pady=(10,0))
        self.e_oear = ttk.Entry(form, width=10); self.e_oear.grid(row=3, column=0, sticky="w")
        ttk.Label(form, text="Latest", style="Muted.TLabel").grid(row=2, column=1, sticky="w", pady=(10,0))
        self.e_olat = ttk.Entry(form, width=10); self.e_olat.grid(row=3, column=1, sticky="w")

        ttk.Button(form, text="Dodaj zlecenie", style="Primary.TButton", command=self.lekarz_add_order).grid(row=3, column=5, sticky="e")

        form2 = ttk.Frame(page)
        form2.pack(fill="x", pady=(0, 8))
        ttk.Label(form2, text="Zmień status (ID):", style="Muted.TLabel").pack(side="left")
        self.e_oid = ttk.Entry(form2, width=8); self.e_oid.pack(side="left", padx=6)
        self.cb_ostat = ttk.Combobox(form2, values=["AKTYWNE","WSTRZYMANE","ZAKOŃCZONE"], state="readonly", width=12)
        self.cb_ostat.set("WSTRZYMANE")
        self.cb_ostat.pack(side="left", padx=6)
        self.e_owhy = ttk.Entry(form2, width=30); self.e_owhy.pack(side="left", padx=6)
        ttk.Button(form2, text="Zapisz", style="Soft.TButton", command=self.lekarz_set_order_status).pack(side="left")

        ttk.Button(page, text="Odśwież", style="Soft.TButton", command=self.lekarz_orders_refresh).pack(anchor="w")

    def lekarz_orders_refresh(self):
        for i in self.orders_tree.get_children():
            self.orders_tree.delete(i)

        rows = db_all("""
            SELECT o.*, m.name AS med_name, m.med_type
            FROM orders o JOIN meds m ON m.med_id=o.med_id
            WHERE o.patient_id=?
            ORDER BY o.order_id DESC
        """, (current_patient_id(),))
        for r in rows:
            cut = ""
            if r["earliest_admin_time"]:
                cut += f"od {r['earliest_admin_time']} "
            if r["latest_admin_time"]:
                cut += f"do {r['latest_admin_time']}"
            self.orders_tree.insert("", "end", values=(
                r["order_id"], r["med_name"], r["dose_text"], r["med_type"], r["slot_label"] or "", r["time_str"] or "",
                r["window_min"], r["priority"], r["status"], cut.strip()
            ))

        # tylko STAŁY/CZASOWY do wyboru
        meds = db_all("SELECT med_id, name, med_type FROM meds WHERE is_active=1 AND med_type IN ('STAŁY','CZASOWY') ORDER BY name")
        self.cb_omed["values"] = [f"{m['name']} ({m['med_id']})" for m in meds]
        if meds and not self.cb_omed.get():
            self.cb_omed.current(0)

    def lekarz_add_order(self):
        v = self.cb_omed.get().strip()
        if not v:
            messagebox.showerror("ZLECENIA", "Wybierz lek.")
            return
        # 1) jeśli wybrano lek z listy (format: "Nazwa (ID)") — bierz ID
        mid = None
        if "(" in v and v.endswith(")") and v.rfind("(") < v.rfind(")"):
            cand = v.split("(")[-1].replace(")", "").strip()
            # prosta heurystyka: ID jest krótkie (w starym UI)
            if 1 <= len(cand) <= 40:
                mid = cand

        # 2) inaczej traktuj to jako wpis z URPL (label z podpowiedzi)
        if not mid:
            mid = self._ensure_med_from_catalog_label(v)

        if not mid:
            messagebox.showerror("ZLECENIA", "Nie rozpoznano leku.")
            return

        # dawka: jeśli puste, a w label jest „| 50 mg …” to podpowiedz
        dose = self.e_odose.get().strip()
        if not dose and "|" in v:
            try:
                dose_part = v.split("|")[1].strip()
                if dose_part and len(dose_part) <= 32:
                    dose = dose_part
                    self.e_odose.insert(0, dose)
            except Exception:
                pass
        if not dose:
            messagebox.showerror("ZLECENIA", "Podaj dawkę.")
            return

        slot = self.cb_oslot.get().strip() or None
        tstr = self.e_otime.get().strip() or None

        try:
            w = int(self.e_owin.get().strip())
        except ValueError:
            messagebox.showerror("ZLECENIA", "Okno musi być liczbą.")
            return
        prio = int(self.cb_oprio.get().strip() or "2")
        ear = self.e_oear.get().strip() or None
        lat = self.e_olat.get().strip() or None

        for x in (tstr, ear, lat):
            if x:
                try:
                    parse_hhmm(x)
                except Exception:
                    messagebox.showerror("ZLECENIA", f"Zły format HH:MM: {x}")
                    return

        db_exec("""
            INSERT INTO orders(patient_id, med_id, dose_text, slot_label, time_str, days_rule, window_min, priority,
                               effective_from, effective_to, status, created_by, reason, created_at,
                               earliest_admin_time, latest_admin_time)
            VALUES (?,?,?,?,?, 'codziennie', ?, ?, ?, NULL, 'AKTYWNE', ?, NULL, ?, ?, ?)
        """, (current_patient_id(), mid, dose, slot, tstr, w, prio,
              datetime.combine(date.today(), time(0,0)).isoformat(timespec="seconds"),
              self.user["user_id"], now_str(), ear, lat))

        self.e_odose.delete(0, "end")
        self.e_otime.delete(0, "end")
        self.e_oear.delete(0, "end")
        self.e_olat.delete(0, "end")
        self.refresh_all()

    def lekarz_set_order_status(self):
        try:
            oid = int(self.e_oid.get().strip())
        except ValueError:
            messagebox.showerror("ZLECENIA", "Podaj ID.")
            return
        status = self.cb_ostat.get().strip()
        why = self.e_owhy.get().strip() or None
        db_exec("UPDATE orders SET status=?, reason=? WHERE order_id=?", (status, why, oid))
        self.e_oid.delete(0, "end")
        self.e_owhy.delete(0, "end")
        self.refresh_all()

    # --- titrations ---
    def lekarz_titr_ui(self):
        page = ttk.Frame(self.ad_titr, style="Page.TFrame")
        page.pack(fill="both", expand=True)

        ttk.Label(page, text="Titracje", style="Title.TLabel").pack(anchor="w")
        ttk.Label(page, text="Np. +1 mg co 7 dni do max. DZISIAJ podświetla dzień zmiany dawki.",
                  style="Muted.TLabel").pack(anchor="w", pady=(2, 10))

        self.titr_tree = ttk.Treeview(page, columns=("id","med","start","startmg","stepmg","days","max","active"), show="headings", height=10)
        for c,t,w in [("id","ID",60),("med","LEK",260),("start","START",110),("startmg","START mg",90),
                      ("stepmg","+mg",70),("days","dni",60),("max","MAX",70),("active","AKT",60)]:
            self.titr_tree.heading(c, text=t)
            self.titr_tree.column(c, width=w, anchor="w")
        self.titr_tree.pack(fill="x")

        form = ttk.Frame(page)
        form.pack(fill="x", pady=12)

        ttk.Label(form, text="Lek", style="Muted.TLabel").grid(row=0, column=0, sticky="w")
        self.cb_tmed = ttk.Combobox(form, state="readonly", width=45)
        self.cb_tmed.grid(row=1, column=0, sticky="w")

        ttk.Label(form, text="Start (YYYY-MM-DD)", style="Muted.TLabel").grid(row=0, column=1, sticky="w", padx=(10,0))
        self.e_tstart = ttk.Entry(form, width=14)
        self.e_tstart.insert(0, date.today().isoformat())
        self.e_tstart.grid(row=1, column=1, sticky="w", padx=(10,0))

        def small(label, col):
            ttk.Label(form, text=label, style="Muted.TLabel").grid(row=0, column=col, sticky="w", padx=(10,0))
            e = ttk.Entry(form, width=8)
            e.grid(row=1, column=col, sticky="w", padx=(10,0))
            return e

        self.e_smg = small("Start mg", 2)
        self.e_step = small("+mg", 3)
        self.e_days = small("co ile dni", 4)
        self.e_maxmg = small("Max mg", 5)

        ttk.Button(form, text="Zapisz", style="Primary.TButton", command=self.lekarz_save_titr).grid(row=1, column=6, padx=10)
        ttk.Button(page, text="Odśwież", style="Soft.TButton", command=self.lekarz_titr_refresh).pack(anchor="w")

    def lekarz_titr_refresh(self):
        for i in self.titr_tree.get_children():
            self.titr_tree.delete(i)
        rows = db_all("""
            SELECT t.*, m.name AS med_name
            FROM titrations t JOIN meds m ON m.med_id=t.med_id
            ORDER BY t.titration_id DESC
        """, (current_patient_id(),))
        for r in rows:
            self.titr_tree.insert("", "end", values=(
                r["titration_id"], r["med_name"], r["start_date"], r["start_mg"], r["step_mg"], r["step_days"], r["max_mg"], r["is_active"]
            ))

        meds = db_all("SELECT med_id, name FROM meds WHERE is_active=1 ORDER BY name")
        self.cb_tmed["values"] = [f"{m['name']} ({m['med_id']})" for m in meds]
        if meds and not self.cb_tmed.get():
            self.cb_tmed.current(0)

    def lekarz_save_titr(self):
        v = self.cb_tmed.get().strip()
        if not v:
            messagebox.showerror("TITRACJE", "Wybierz lek.")
            return
        mid = v.split("(")[-1].replace(")", "").strip()
        try:
            sd = date.fromisoformat(self.e_tstart.get().strip())
            smg = int(self.e_smg.get().strip())
            step = int(self.e_step.get().strip())
            days = int(self.e_days.get().strip())
            mx = int(self.e_maxmg.get().strip())
        except Exception:
            messagebox.showerror("TITRACJE", "Błędne dane (format/liczby).")
            return

        db_exec("""
            INSERT INTO titrations(med_id, start_date, start_mg, step_mg, step_days, max_mg, notes, is_active, created_at)
            VALUES (?,?,?,?,?,?,NULL,1,?)
            ON CONFLICT(med_id) DO UPDATE SET
                start_date=excluded.start_date,
                start_mg=excluded.start_mg,
                step_mg=excluded.step_mg,
                step_days=excluded.step_days,
                max_mg=excluded.max_mg,
                is_active=1
        """, (mid, sd.isoformat(), smg, step, days, mx, now_str()))
        self.refresh_all()

    # --- PRN limits (doctor sets for nurse) ---
    def lekarz_prn_ui(self):
        page = ttk.Frame(self.ad_prn, style="Page.TFrame")
        page.pack(fill="both", expand=True)

        ttk.Label(page, text="Limity PRN dla pielęgniarki", style="Title.TLabel").pack(anchor="w")
        ttk.Label(page, text="Lekarz ustala listę dozwolonych PRN + max dawki. Pielęgniarka tylko klika i podaje.",
                  style="Muted.TLabel").pack(anchor="w", pady=(2, 10))

        self.prn_tree = ttk.Treeview(page, columns=("id","nurse","med","min","max","step","day","int","active"), show="headings", height=10)
        for c,t,w in [("id","ID",60),("nurse","PIELĘG.",140),("med","LEK",220),("min","min",60),("max","max",60),
                      ("step","step",60),("day","mg/d",70),("int","odstęp",80),("active","AKT",60)]:
            self.prn_tree.heading(c, text=t)
            self.prn_tree.column(c, width=w, anchor="w")
        self.prn_tree.pack(fill="x")

        form = ttk.Frame(page)
        form.pack(fill="x", pady=12)

        ttk.Label(form, text="Pielęgniarka", style="Muted.TLabel").grid(row=0, column=0, sticky="w")
        self.cb_nurse = ttk.Combobox(form, state="readonly", width=20)
        self.cb_nurse.grid(row=1, column=0, sticky="w")

        ttk.Label(form, text="Lek PRN", style="Muted.TLabel").grid(row=0, column=1, sticky="w", padx=(10,0))
        self.cb_prnmed = ttk.Combobox(form, state="readonly", width=35)
        self.cb_prnmed.grid(row=1, column=1, sticky="w", padx=(10,0))

        def small(label, col, default=""):
            ttk.Label(form, text=label, style="Muted.TLabel").grid(row=0, column=col, sticky="w", padx=(10,0))
            e = ttk.Entry(form, width=8)
            e.grid(row=1, column=col, sticky="w", padx=(10,0))
            if default:
                e.insert(0, default)
            return e

        self.e_pmin = small("mg min", 2)
        self.e_pmax = small("mg max", 3)
        self.e_pstep = small("mg step", 4, "1")
        self.e_pday = small("max mg/d", 5)
        self.e_pint = small("odstęp min", 6)

        ttk.Button(form, text="Zapisz", style="Primary.TButton", command=self.lekarz_save_prn_perm).grid(row=1, column=7, padx=10)
        ttk.Button(page, text="Odśwież", style="Soft.TButton", command=self.lekarz_prn_refresh).pack(anchor="w")

    def lekarz_prn_refresh(self):
        for i in self.prn_tree.get_children():
            self.prn_tree.delete(i)

        rows = db_all("""
            SELECT p.prn_id, u.username AS nurse, m.name AS med, p.mg_min, p.mg_max, p.mg_step, p.max_mg_per_day, p.min_interval_min, p.is_active
            FROM prn_permissions p
            JOIN users u ON u.user_id=p.user_id
            JOIN meds m ON m.med_id=p.med_id
            ORDER BY p.prn_id DESC
        """, (current_patient_id(),))
        for r in rows:
            self.prn_tree.insert("", "end", values=(
                r["prn_id"], r["nurse"], r["med"], r["mg_min"], r["mg_max"], r["mg_step"],
                r["max_mg_per_day"], r["min_interval_min"], r["is_active"]
            ))

        nurses = db_all("SELECT user_id, username FROM users WHERE role=? AND is_active=1 ORDER BY username", (ROLE_NURSE,))
        self.cb_nurse["values"] = [f"{n['username']} ({n['user_id']})" for n in nurses]
        if nurses and not self.cb_nurse.get():
            self.cb_nurse.current(0)

        meds = db_all("SELECT med_id, name FROM meds WHERE is_active=1 AND med_type='DORAŹNY' ORDER BY name")
        self.cb_prnmed["values"] = [f"{m['name']} ({m['med_id']})" for m in meds]
        if meds and not self.cb_prnmed.get():
            self.cb_prnmed.current(0)

    def lekarz_save_prn_perm(self):
        nv = self.cb_nurse.get().strip()
        mv = self.cb_prnmed.get().strip()
        if not nv or not mv:
            messagebox.showerror("PRN", "Wybierz pielęgniarkę i lek.")
            return
        nurse_id = int(nv.split("(")[-1].replace(")", "").strip())
        med_id = mv.split("(")[-1].replace(")", "").strip()

        try:
            mgmin = int(self.e_pmin.get().strip())
            mgmax = int(self.e_pmax.get().strip())
            step = int(self.e_pstep.get().strip() or "1")
            day = int(self.e_pday.get().strip())
            interval = int(self.e_pint.get().strip())
        except ValueError:
            messagebox.showerror("PRN", "Podaj liczby.")
            return
        if mgmin > mgmax:
            messagebox.showerror("PRN", "mg_min > mg_max")
            return
        if step <= 0:
            messagebox.showerror("PRN", "mg_step musi być > 0.")
            return

        existing = db_one("""
            SELECT prn_id FROM prn_permissions
            WHERE user_id=? AND med_id=? AND is_active=1
        """, (current_patient_id(), nurse_id, med_id))
        if existing:
            db_exec("""
                UPDATE prn_permissions
                SET mg_min=?, mg_max=?, mg_step=?, max_mg_per_day=?, min_interval_min=?
                WHERE prn_id=?
            """, (mgmin, mgmax, step, day, interval, existing["prn_id"]))
        else:
            db_exec("""
                INSERT INTO prn_permissions(patient_id, user_id, med_id, mg_min, mg_max, mg_step, max_mg_per_day, min_interval_min, created_at)
                VALUES (?,?,?,?,?,?,?,?)
            """, (current_patient_id(), nurse_id, med_id, mgmin, mgmax, step, day, interval, now_str()))

        self.e_pmin.delete(0, "end"); self.e_pmax.delete(0, "end")
        self.e_pstep.delete(0, "end"); self.e_pstep.insert(0, "1")
        self.e_pday.delete(0, "end"); self.e_pint.delete(0, "end")
        self.refresh_all()



    # --- użytkownicy (lekarz) ---
    def lekarz_users_ui(self):
        page = ttk.Frame(self.ad_users, style="Page.TFrame")
        page.pack(fill="both", expand=True)

        ttk.Label(page, text="Użytkownicy", style="Title.TLabel").pack(anchor="w")
        ttk.Label(page, text="Profile z rolami i hasłami. Administrator dodaje lekarzy i pielęgniarki; lekarz dodaje tylko pielęgniarki.",
                  style="Muted.TLabel").pack(anchor="w", pady=(2, 10))

        self.users_tree = ttk.Treeview(page, columns=("id","login","rola","imie","tel","aktywny"), show="headings", height=7)
        for c,t,w in [("id","ID",60),("login","LOGIN",160),("rola","ROLA",140),("imie","IMIĘ I NAZWISKO",240),("tel","TEL",160),("aktywny","AKT",70)]:
            self.users_tree.heading(c, text=t)
            self.users_tree.column(c, width=w, anchor="w")
        self.users_tree.pack(fill="x")

        form = ttk.Frame(page)
        form.pack(fill="x", pady=12)

        row1 = ttk.Frame(form); row1.pack(fill="x", pady=4)
        ttk.Label(row1, text="Login", style="Muted.TLabel", width=16).pack(side="left")
        self.e_u_login = ttk.Entry(row1, width=30); self.e_u_login.pack(side="left", padx=(0,12))

        ttk.Label(row1, text="Rola", style="Muted.TLabel").pack(side="left")
        self.cb_u_role = ttk.Combobox(row1, values=self._allowed_roles_for_creator(), state="readonly", width=18)
        self.cb_u_role.set(ROLE_NURSE)
        self.cb_u_role.pack(side="left", padx=(8,0))

        row2 = ttk.Frame(form); row2.pack(fill="x", pady=4)
        ttk.Label(row2, text="Imię i nazw.", style="Muted.TLabel", width=16).pack(side="left")
        self.e_u_full = ttk.Entry(row2, width=50); self.e_u_full.pack(side="left", fill="x", expand=True)

        row3 = ttk.Frame(form); row3.pack(fill="x", pady=4)
        ttk.Label(row3, text="Telefon", style="Muted.TLabel", width=16).pack(side="left")
        self.e_u_phone = ttk.Entry(row3, width=24); self.e_u_phone.pack(side="left")

        row4 = ttk.Frame(form); row4.pack(fill="x", pady=4)
        ttk.Label(row4, text="Hasło (opc.)", style="Muted.TLabel", width=16).pack(side="left")
        self.e_u_pass = ttk.Entry(row4, width=24, show="•"); self.e_u_pass.pack(side="left")
        ttk.Label(row4, text="(puste = bez zmian)", style="Muted.TLabel").pack(side="left", padx=(10,0))

        ttk.Label(form, text="Notatki (opc.)", style="Muted.TLabel").pack(anchor="w", pady=(6, 2))
        self.t_u_notes = tk.Text(form, height=3, wrap="word")
        self.t_u_notes.pack(fill="x")

        self.v_u_active = tk.IntVar(value=1)
        ttk.Checkbutton(form, text="Aktywny", variable=self.v_u_active).pack(anchor="w", pady=(6, 0))

        btns = ttk.Frame(page)
        btns.pack(fill="x", pady=(8, 0))
        ttk.Button(btns, text="Zapisz", style="Primary.TButton", command=self.lekarz_save_user).pack(side="left")
        ttk.Button(btns, text="Odśwież", style="Soft.TButton", command=self.lekarz_users_refresh).pack(side="left", padx=8)

        self.lekarz_users_refresh()

    def lekarz_users_refresh(self):
        if not hasattr(self, "users_tree"):
            return
        for i in self.users_tree.get_children():
            self.users_tree.delete(i)
        rows = db_all("SELECT * FROM users ORDER BY role, username")
        for r in rows:
            self.users_tree.insert("", "end", values=(
                r["user_id"], r["username"], r["role"],
                r["full_name"] or "", r["phone"] or "", r["is_active"]
            ))

    def lekarz_save_user(self):
        login = self.e_u_login.get().strip().lower()
        role = self.cb_u_role.get().strip()
        full = self.e_u_full.get().strip() or None
        phone = self.e_u_phone.get().strip() or None
        notes = self.t_u_notes.get("1.0", "end").strip() or None
        active = int(self.v_u_active.get())

        allowed = self._allowed_roles_for_creator()
        if not login or role not in allowed:
            messagebox.showerror("Użytkownicy", "Brak uprawnień do tej roli lub brak danych.")
            return

        db_exec("""
            INSERT INTO users(username, role, is_active, created_at, full_name, phone, notes)
            VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(username) DO UPDATE SET
                role=excluded.role,
                is_active=excluded.is_active,
                full_name=excluded.full_name,
                phone=excluded.phone,
                notes=excluded.notes
        """, (login, role, active, now_str(), full, phone, notes))

        # ustaw/zmień hasło jeśli podane
        new_pw = self.e_u_pass.get().strip() if hasattr(self, "e_u_pass") else ""
        if new_pw:
            ph, ps = hash_password(new_pw)
            db_exec("UPDATE users SET password_hash=?, password_salt=?, updated_at=? WHERE username=?",
                    (ph, ps, now_str(), login))
            self.e_u_pass.delete(0, "end")


        messagebox.showinfo("Użytkownicy", "Zapisano.")
        self.lekarz_users_refresh()


    # =================== FIX: brakujące akcje UI (leki/kolory) ===================
    def pick_color_into(self, entry_widget: ttk.Entry):
        """Wybór koloru do pola #RRGGBB (bezpiecznie)."""
        try:
            c = colorchooser.askcolor(parent=self, title="Wybierz kolor leku")
            if c and c[1]:
                entry_widget.delete(0, "end")
                entry_widget.insert(0, c[1])
        except Exception:
            # nic nie rób
            return

    def lekarz_save_med(self):
        """Zapis/aktualizacja definicji leku (ustala lekarz)."""
        # pola podstawowe
        mid = (getattr(self, "e_mid", None).get().strip() if hasattr(self, "e_mid") else "")
        name = (getattr(self, "e_mname", None).get().strip() if hasattr(self, "e_mname") else "")
        if not mid or not name:
            messagebox.showerror("LEKI", "Podaj Lek_ID oraz Nazwę.")
            return

        form = getattr(self, "e_form", None).get().strip() if hasattr(self, "e_form") else ""
        default_dose = getattr(self, "e_default_dose", None).get().strip() if hasattr(self, "e_default_dose") else ""
        drug_class = getattr(self, "e_class", None).get().strip() if hasattr(self, "e_class") else ""
        drug_group = getattr(self, "e_generics", None).get().strip() if hasattr(self, "e_generics") else ""
        max_dose_text = getattr(self, "e_maxdose", None).get().strip() if hasattr(self, "e_maxdose") else ""

        # wybory + flagi
        med_type = getattr(self, "cb_mtype", None).get().strip() if hasattr(self, "cb_mtype") else "STAŁY"
        policy = getattr(self, "cb_policy", None).get().strip() if hasattr(self, "cb_policy") else "DOZWOLONY"
        color_hex = getattr(self, "e_color_hex", None).get().strip() if hasattr(self, "e_color_hex") else ""
        if color_hex == "":
            color_hex = None

        is_active = int(getattr(self, "v_active", tk.IntVar(value=1)).get())
        can_stop = int(getattr(self, "v_can_stop", tk.IntVar(value=1)).get())
        critical = int(getattr(self, "v_critical", tk.IntVar(value=0)).get())
        reqdoc = int(getattr(self, "v_reqdoc", tk.IntVar(value=0)).get())

        # teksty długie
        def _t(widget_name: str) -> str:
            w = getattr(self, widget_name, None)
            if not w:
                return ""
            try:
                return w.get("1.0", "end").strip()
            except Exception:
                return ""

        notes = _t("t_notes")
        mechanism = _t("t_mech")
        contraindications = _t("t_caut")
        extra_info = _t("t_extra")
        i1 = _t("t_i1")
        i2 = _t("t_i2")
        i3 = _t("t_i3")

        # zapis
        db_exec("""
            INSERT INTO meds(
                med_id, name, form, default_dose_text, notes,
                is_active, med_type, can_stop, critical, requires_doctor_to_hold,
                policy, drug_class, drug_group, max_dose_text,
                mechanism, contraindications, extra_info, interactions_lvl1, interactions_lvl2, interactions_lvl3,
                color_hex
            )
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(med_id) DO UPDATE SET
                name=excluded.name,
                form=excluded.form,
                default_dose_text=excluded.default_dose_text,
                notes=excluded.notes,
                is_active=excluded.is_active,
                med_type=excluded.med_type,
                can_stop=excluded.can_stop,
                critical=excluded.critical,
                requires_doctor_to_hold=excluded.requires_doctor_to_hold,
                policy=excluded.policy,
                drug_class=excluded.drug_class,
                drug_group=excluded.drug_group,
                max_dose_text=excluded.max_dose_text,
                mechanism=excluded.mechanism,
                contraindications=excluded.contraindications,
                extra_info=excluded.extra_info,
                interactions_lvl1=excluded.interactions_lvl1,
                interactions_lvl2=excluded.interactions_lvl2,
                interactions_lvl3=excluded.interactions_lvl3,
                color_hex=excluded.color_hex
        """, (
            mid, name, form, default_dose, notes,
            is_active, med_type, can_stop, critical, reqdoc,
            policy, drug_class, drug_group, max_dose_text,
            mechanism, contraindications, extra_info, i1, i2, i3,
            color_hex
        ))

        messagebox.showinfo("LEKI", "Zapisano lek.")
        try:
            self.lekarz_meds_refresh()
        except Exception:
            pass
        try:
            self.refresh_all()
        except Exception:
            pass


