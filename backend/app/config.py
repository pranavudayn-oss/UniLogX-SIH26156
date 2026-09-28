from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
DB_PATH = os.getenv("UNILOGX_DB", str(BASE_DIR / "unilogx.db"))
RAW_LOG_DIR = DATA_DIR / "raw_logs"
NORMALIZED_LOG_DIR = DATA_DIR / "normalized_logs"
QUARANTINE_DIR = DATA_DIR / "quarantine"
EXPORT_DIR = DATA_DIR / "exports"

for directory in (RAW_LOG_DIR, NORMALIZED_LOG_DIR, QUARANTINE_DIR, EXPORT_DIR):
    directory.mkdir(parents=True, exist_ok=True)
