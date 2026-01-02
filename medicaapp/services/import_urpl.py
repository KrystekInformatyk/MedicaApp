from __future__ import annotations
import csv
import os
import re

from ..db import connect, set_setting
from ..utils import now_str

def import_urpl_csv(fp: str) -> dict:
    """Importuje CSV URPL do drugs_catalog (replace). Zwraca meta."""
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
            # URPL bywa w CSV z ; jako delimiterem
            reader = csv.DictReader(f, delimiter=";")
            def g(row, *keys):
                for k in keys:
                    if k in row and row[k] not in (None, ""):
                        return row[k]
                return None

            buf = []
            n = 0
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
                n += 1
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
    return {"source_date": source_date, "imported_at": imported_at, "rows_seen": n}
