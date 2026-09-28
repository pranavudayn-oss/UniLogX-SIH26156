import json
from pathlib import Path
from typing import Optional, Tuple, Union
from datetime import datetime
from ..config import RAW_LOG_DIR, NORMALIZED_LOG_DIR, DATA_DIR
from ..utils.hash_utils import sha256_text
from ..utils.file_utils import safe_filename
from ..utils.timestamp_utils import now_iso


def build_raw_log_path(
    ingestion_id: str,
    timestamp_or_date: Optional[str] = None,
    filename: str = "raw.log",
) -> Tuple[Path, str]:
    """
    Builds a deterministic, partitioned filesystem path and a clean relative logical path:
        <RAW_LOG_DIR>/YYYY/MM/DD/<ingestion_id>/<filename>
    
    Returns:
        (absolute_path: Path, relative_logical_path: str)
    """
    date_str = None
    if timestamp_or_date:
        # Extract YYYY, MM, DD from ISO or date string (e.g. 2026-09-27 or 2026-09-27T12:00:00)
        cleaned = timestamp_or_date.strip().replace("/", "-")
        parts = cleaned.split("T")[0].split(" ")[0].split("-")
        if len(parts) >= 3 and len(parts[0]) == 4 and len(parts[1]) in (1, 2) and len(parts[2]) in (1, 2):
            year = parts[0]
            month = f"{int(parts[1]):02d}"
            day = f"{int(parts[2]):02d}"
            date_str = (year, month, day)

    if not date_str:
        now = datetime.utcnow()
        date_str = (f"{now.year:04d}", f"{now.month:02d}", f"{now.day:02d}")

    year, month, day = date_str
    clean_name = safe_filename(filename) if filename else "raw.log"
    clean_ingest = safe_filename(ingestion_id) if ingestion_id else "default"

    # Destination directory structure: YYYY/MM/DD/<ingestion_id>/
    sub_dir = Path(year) / month / day / clean_ingest
    abs_path = RAW_LOG_DIR / sub_dir / clean_name

    # Relative logical path for clean, non-sensitive display and DB storage
    rel_path = f"raw_logs/{year}/{month}/{day}/{clean_ingest}/{clean_name}"
    return abs_path, rel_path


def store_raw_log(
    content: Union[bytes, str],
    ingestion_id: str,
    filename: str = "raw.log",
    timestamp_or_date: Optional[str] = None,
) -> Tuple[Path, str, str]:
    """
    Stores unmodified raw log content into the organized directory structure.
    Guarantees byte-for-byte / character-for-character raw evidence integrity.
    
    Returns:
        (absolute_path, relative_logical_path, raw_hash)
    """
    if isinstance(content, str):
        raw_bytes = content.encode("utf-8")
        raw_text = content
    else:
        raw_bytes = content
        raw_text = content.decode("utf-8", errors="replace")

    raw_hash = sha256_text(raw_text)
    abs_path, rel_path = build_raw_log_path(
        ingestion_id=ingestion_id,
        timestamp_or_date=timestamp_or_date,
        filename=filename,
    )

    abs_path.parent.mkdir(parents=True, exist_ok=True)
    abs_path.write_bytes(raw_bytes)

    return abs_path, rel_path, raw_hash


def get_raw_log(path_or_relative: Union[str, Path]) -> Optional[bytes]:
    """
    Retrieves raw log bytes given either an absolute path or a relative storage path.
    """
    p = Path(path_or_relative)
    if not p.is_absolute():
        p = DATA_DIR / p
    if p.exists() and p.is_file():
        return p.read_bytes()
    return None


def get_raw_log_text(path_or_relative: Union[str, Path]) -> Optional[str]:
    """
    Retrieves raw log text content.
    """
    data = get_raw_log(path_or_relative)
    if data is not None:
        return data.decode("utf-8", errors="replace")
    return None


def raw_log_exists(path_or_relative: Union[str, Path]) -> bool:
    """
    Checks if raw log file exists on disk.
    """
    p = Path(path_or_relative)
    if not p.is_absolute():
        p = DATA_DIR / p
    return p.exists() and p.is_file()


def write_normalized(filename: str, events: list[dict]) -> Path:
    """
    Maintains existing normalized log storage functionality.
    """
    path = NORMALIZED_LOG_DIR / f"{filename}.json"
    path.write_text(json.dumps(events, indent=2, default=str), encoding="utf-8")
    return path
