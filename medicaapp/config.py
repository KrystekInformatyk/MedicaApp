from __future__ import annotations
from pathlib import Path

APP_NAME = "MedicaApp"

# katalog projektu (tam gdzie jest main.py)
BASE_DIR = Path(__file__).resolve().parents[1]

DB_PATH = BASE_DIR / "emar.db"
LOG_PATH = BASE_DIR / "medicaapp.log"

# nazwa pliku URPL zwykle zawiera te fragmenty:
URPL_HINTS = ["rejestr_produktow_leczniczych", "produktow_leczniczych", "rejestr produktów leczniczych"]
