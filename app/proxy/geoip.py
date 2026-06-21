from __future__ import annotations

import base64
import logging
import os
import tarfile
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

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


def geoip_db_status(db_path: str) -> dict:
    """Return status dict for the GeoIP database file.

    Keys: present (bool), size_mb (int|None), mtime (datetime|None).
    """
    p = Path(db_path) if db_path else None
    if p and p.exists():
        stat = p.stat()
        return {
            "present": True,
            "size_mb": stat.st_size // 1_048_576,
            "mtime": datetime.fromtimestamp(stat.st_mtime),
        }
    return {"present": False, "size_mb": None, "mtime": None}


def read_maxmind_credentials() -> tuple[str, str]:
    """Read and decrypt MaxMind credentials from AppConfig.

    Returns (account_id, license_key) — both empty strings on any failure,
    including when WARDNODE_SECRET_KEY is not set (EncryptionNotConfigured).
    """
    try:
        from app.models import AppConfig
        from app.encryption import decrypt_secret, EncryptionNotConfigured

        enc_id = AppConfig.get("maxmind_account_id")
        enc_key = AppConfig.get("maxmind_license_key")
        account_id = (decrypt_secret(enc_id) or "") if enc_id else ""
        license_key = (decrypt_secret(enc_key) or "") if enc_key else ""
        return account_id, license_key
    except Exception:
        return "", ""


def download_geoip_db(db_path: str, account_id: str, license_key: str) -> tuple[bool, str]:
    """Download GeoLite2-Country from MaxMind and write it to *db_path*.

    Returns ``(ok, message)``.  Writes atomically via a ``.part`` temp file
    so a failed download never leaves a corrupt database in place.
    Resets the module-level ``_reader`` so the next ``get_country_code()``
    call opens the fresh file without a process restart.
    """
    global _reader, _db_path

    db = Path(db_path)
    db.parent.mkdir(parents=True, exist_ok=True)
    tar_path = db.parent / "GeoLite2-Country.tar.gz"
    part_path = Path(str(db) + ".part")

    url = "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz"
    credentials = base64.b64encode(f"{account_id}:{license_key}".encode()).decode()

    try:
        # MaxMind returns 302 → Cloudflare R2 presigned URL; capture it without following.
        class _CaptureRedirect(urllib.request.HTTPRedirectHandler):
            def http_error_302(self, req, fp, code, msg, headers):
                raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)
            http_error_301 = http_error_302
            http_error_303 = http_error_302
            http_error_307 = http_error_302
            http_error_308 = http_error_302

        no_redirect_opener = urllib.request.build_opener(_CaptureRedirect())
        req = urllib.request.Request(url, headers={"Authorization": f"Basic {credentials}"})
        try:
            no_redirect_opener.open(req, timeout=30)
            download_url = url
        except urllib.error.HTTPError as redir_exc:
            if redir_exc.code in (301, 302, 303, 307, 308):
                download_url = redir_exc.headers.get("Location")
                if not download_url:
                    return False, "MaxMind redirect sin Location header."
            else:
                body = ""
                try:
                    body = redir_exc.read().decode(errors="replace")[:200]
                except Exception:
                    pass
                return False, f"MaxMind respondió HTTP {redir_exc.code} {redir_exc.reason}. {body}".strip()

        # R2 presigned URLs may contain literal spaces
        download_url = download_url.replace(" ", "%20")
        with urllib.request.urlopen(download_url, timeout=120) as resp:
            tar_path.write_bytes(resp.read())

        with tarfile.open(tar_path) as tf:
            mmdb_member = next(m for m in tf.getmembers() if m.name.endswith(".mmdb"))
            with tf.extractfile(mmdb_member) as src:
                part_path.write_bytes(src.read())

        # Atomic replace — never leaves a partial file as the live DB
        part_path.replace(db)
        tar_path.unlink(missing_ok=True)

        # Reset the cached reader so the next lookup opens the new file
        if _reader is not None:
            try:
                _reader.close()
            except Exception:
                pass
            _reader = None
            _db_path = None

        size_mb = db.stat().st_size // 1_048_576
        return True, f"GeoLite2-Country descargada correctamente ({size_mb} MB)."

    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode(errors="replace")[:200]
        except Exception:
            pass
        _cleanup(tar_path, part_path)
        return False, f"MaxMind respondió HTTP {exc.code} {exc.reason}. {body}".strip()
    except StopIteration:
        _cleanup(tar_path, part_path)
        return False, "No se encontró el archivo .mmdb en el tar.gz de MaxMind."
    except Exception as exc:
        _cleanup(tar_path, part_path)
        return False, f"No se pudo descargar GeoLite2-Country: {exc}"


def _cleanup(*paths: Path) -> None:
    for p in paths:
        try:
            if p.exists():
                p.unlink()
        except Exception:
            pass
