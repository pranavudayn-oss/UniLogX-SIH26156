import csv
import io
import json
from pathlib import Path
from typing import List

def read_text_lines(content: bytes, filename: str = "") -> List[str]:
    text = content.decode("utf-8", errors="replace")
    lower_name = filename.lower()

    # JSON Array handling
    if lower_name.endswith(".json") or text.strip().startswith("["):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return [json.dumps(item) if isinstance(item, (dict, list)) else str(item) for item in parsed]
            elif isinstance(parsed, dict):
                return [json.dumps(parsed)]
        except Exception:
            pass

    # CSV handling
    if lower_name.endswith(".csv"):
        try:
            reader = csv.DictReader(io.StringIO(text))
            lines = []
            for row in reader:
                pairs = []
                for k, v in row.items():
                    if k is not None and v is not None and str(v).strip():
                        val = str(v).strip()
                        if " " in val:
                            pairs.append(f'{k}="{val}"')
                        else:
                            pairs.append(f'{k}={val}')
                if pairs:
                    lines.append(" ".join(pairs))
            if lines:
                return lines
        except Exception:
            pass

    return text.splitlines()

