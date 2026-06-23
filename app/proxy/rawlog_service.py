"""Lógica de gestión de archivos de log crudo ModSecurity: prune, archivado
cifrado opcional pre-prune, listado y descarga segura.

Patrón análogo a app/backup/service.py pero para archives de raw logs.
"""

import logging
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pyzipper
from flask import current_app
from sqlalchemy.exc import SQLAlchemyError

from app.audit.helpers import log_audit
from app.extensions import db
from app.models import AppConfig, ModSecRawLog

log = logging.getLogger(__name__)

# Nombre estricto: también valida entradas de download/delete (anti traversal).
RAWLOG_ARCHIVE_NAME_RE = re.compile(r"^wardnode-modsec-log-\d{8}-\d{6}\.zip$")


def rawlog_archive_dir() -> Path:
    """Directorio de almacenamiento de archives (crea si no existe)."""
    d = Path(os.environ.get("WARDNODE_RAWLOG_ARCHIVE_DIR", "/app/data/log-archives"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def list_log_archives() -> list[dict]:
    """Lista archives NDJSON cifrados, ordenados descendente por mtime."""
    out = []
    for p in rawlog_archive_dir().glob("wardnode-modsec-log-*.zip"):
        if not RAWLOG_ARCHIVE_NAME_RE.match(p.name):
            continue
        st = p.stat()
        out.append({
            "name": p.name,
            "size_bytes": st.st_size,
            "mtime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc),
        })
    return sorted(out, key=lambda a: a["name"], reverse=True)


def resolve_log_archive_path(name: str) -> Path:
    """Valida nombre contra regex anti-traversal y verifica que existe.

    Lanza ValueError si el nombre es inválido, FileNotFoundError si no existe.
    """
    if not RAWLOG_ARCHIVE_NAME_RE.match(name):
        raise ValueError(f"nombre de archive inválido: {name!r}")
    path = rawlog_archive_dir() / name
    if not path.is_file():
        raise FileNotFoundError(f"el archive no existe: {name}")
    return path


def prune_and_archive(now: datetime) -> dict:
    """Poda filas antiguas de ModSecRawLog, opcionalmente archivando primero.

    Retorna un dict con:
      archived_rows  — filas incluidas en el zip (0 si no se archivó)
      deleted_rows   — filas borradas de la BD
      archive_file   — nombre del zip creado, o None
      skipped_reason — None si todo fue bien; string con el motivo si se saltó
    """
    try:
        retention_days = int(AppConfig.get("modsec_rawlog_retention_days") or "30")
    except (TypeError, ValueError):
        retention_days = 30

    cutoff = now - timedelta(days=retention_days)
    do_backup = AppConfig.get("modsec_rawlog_backup_before_prune") == "1"

    archive_file: str | None = None
    archived_rows: int = 0

    if do_backup:
        password = AppConfig.get_secret("modsec_rawlog_zip_password")
        if not password:
            log_audit(
                "rawlog.prune",
                resource_type="rawlog",
                severity="warning",
                status="failure",
                detail={
                    "reason": "backup_enabled_but_no_password",
                    "cutoff": cutoff.isoformat(),
                },
            )
            return {
                "archived_rows": 0,
                "deleted_rows": 0,
                "archive_file": None,
                "skipped_reason": "backup_enabled_but_no_password",
            }

        rows = (
            db.session.query(ModSecRawLog)
            .filter(ModSecRawLog.created_at < cutoff)
            .order_by(ModSecRawLog.created_at)
            .all()
        )

        if rows:
            name = f"wardnode-modsec-log-{now.strftime('%Y%m%d-%H%M%S')}.zip"
            final_path = rawlog_archive_dir() / name
            part_path = rawlog_archive_dir() / (name + ".part")
            try:
                with pyzipper.AESZipFile(
                    part_path,
                    "w",
                    compression=pyzipper.ZIP_DEFLATED,
                    encryption=pyzipper.WZ_AES,
                ) as zf:
                    zf.setpassword(password.encode())
                    zf.writestr(
                        "modsec-raw-log.ndjson",
                        "\n".join(r.raw_json for r in rows),
                    )
                os.replace(part_path, final_path)
            except Exception as exc:
                if part_path.exists():
                    part_path.unlink(missing_ok=True)
                log.error("rawlog: fallo escribiendo archive zip: %s", exc)
                log_audit(
                    "rawlog.archive",
                    resource_type="rawlog_archive",
                    severity="error",
                    status="failure",
                    detail={
                        "error": f"{type(exc).__name__}: {exc}"[:500],
                        "cutoff": cutoff.isoformat(),
                    },
                )
                raise
            finally:
                if part_path.exists():
                    part_path.unlink(missing_ok=True)

            archived_rows = len(rows)
            archive_file = name
            log_audit(
                "rawlog.archive",
                resource_type="rawlog_archive",
                resource_name=name,
                status="success",
                detail={
                    "rows": archived_rows,
                    "cutoff": cutoff.isoformat(),
                },
            )

    # Borrar filas antiguas.
    try:
        deleted = (
            db.session.query(ModSecRawLog)
            .filter(ModSecRawLog.created_at < cutoff)
            .delete(synchronize_session=False)
        )
        db.session.commit()
    except SQLAlchemyError as exc:
        db.session.rollback()
        log.error("rawlog: fallo borrando filas antiguas: %s", exc)
        log_audit(
            "rawlog.prune",
            resource_type="rawlog",
            severity="error",
            status="failure",
            detail={
                "error": f"{type(exc).__name__}: {exc}"[:500],
                "cutoff": cutoff.isoformat(),
            },
        )
        raise

    log_audit(
        "rawlog.prune",
        resource_type="rawlog",
        status="success",
        detail={
            "retention_days": retention_days,
            "cutoff": cutoff.isoformat(),
            "archived_rows": archived_rows,
            "deleted_rows": deleted,
            "archive_file": archive_file,
        },
    )

    # Guardar timestamp de la última poda.
    AppConfig.set("modsec_rawlog_last_prune_at", now.isoformat())

    return {
        "archived_rows": archived_rows,
        "deleted_rows": deleted,
        "archive_file": archive_file,
        "skipped_reason": None,
    }
