from __future__ import annotations

import os
from typing import Optional

_reader = None
_db_path: str | None = None


def get_country_code(ip: str) -> Optional[str]:
    """Return ISO 3166-1 alpha-2 country code for an IP, or None if unavailable."""
    global _reader, _db_path

    path = os.environ.get("GEOIP_DB_PATH", "")
    if not path or not os.path.exists(path):
        return None

    try:
        import maxminddb
    except ImportError:
        return None

    if _reader is None or _db_path != path:
        if _reader is not None:
            _reader.close()
        _reader = maxminddb.open_database(path)
        _db_path = path

    try:
        record = _reader.get(ip)
        if record is None:
            return None
        return record.get("country", {}).get("iso_code")
    except Exception:
        return None
