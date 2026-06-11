"""Worker programado del módulo de backup.

Thread daemon (mismo patrón que app/soc/worker.py) que ejecuta un backup
diario a la hora configurada (backup_hour, hora del servidor en UTC).
En PostgreSQL con gunicorn multi-worker, un advisory lock (815002 — el SOC
usa 815001) garantiza que un solo proceso ejecute el backup.
"""

import logging
import threading
import time
from datetime import datetime, timezone

from sqlalchemy import text

log = logging.getLogger(__name__)

BACKUP_ADVISORY_LOCK_KEY = 815002

_TICK_SECONDS = 60
_BOOT_DELAY_SECONDS = 90
_ERROR_BACKOFF_SECONDS = 60


def is_backup_due(now: datetime, backup_hour: int, last_run_at: datetime | None) -> bool:
    """¿Toca ejecutar el backup diario? (función pura, testeable).

    Toca si ya pasó la hora configurada y el último intento no es de hoy.
    Robusto ante reinicios: si el proceso estuvo caído a la hora exacta,
    ejecuta en el primer tick posterior dentro del mismo día.
    """
    if now.hour < backup_hour:
        return False
    if last_run_at is None:
        return True
    return last_run_at.date() < now.date()


def _read_last_run():
    from app.models import AppConfig

    raw = AppConfig.get("backup_last_run_at") or ""
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _persist_outcome(now: datetime, status: str) -> None:
    from app.extensions import db
    from app.models import AppConfig

    AppConfig.set("backup_last_run_at", now.isoformat())
    AppConfig.set("backup_last_status", status[:300])
    db.session.commit()


def _send_result_email(result, error_msg: str | None) -> None:
    """Email post-backup: adjunto si cabe, aviso si excede, alerta si falló."""
    from app.email import send_email, smtp_configured
    from app.models import AppConfig

    if (AppConfig.get("backup_email_enabled") or "0") != "1":
        return
    to_raw = AppConfig.get("backup_email_to") or ""
    to_emails = [e.strip() for e in to_raw.split(",") if e.strip()]
    if not to_emails or not smtp_configured():
        return

    try:
        max_mb = int(AppConfig.get("backup_email_max_mb") or 20)
    except (TypeError, ValueError):
        max_mb = 20

    try:
        if error_msg is not None:
            send_email(
                to_emails, "WardNode backup FALLÓ",
                f"El backup programado falló:\n\n{error_msg}\n\n"
                "Revisa la bitácora de auditoría para más detalle.",
            )
            return

        size_mb = result.size_bytes / 1024**2
        components = "\n".join(f"- {k}: {v}" for k, v in result.components.items())
        body = (
            f"Backup programado generado correctamente.\n\n"
            f"Archivo: {result.path.name}\n"
            f"Tamaño: {size_mb:.1f} MB\n\n"
            f"Componentes:\n{components}\n\n"
            "Recuerda: el zip requiere su contraseña y la restauración exige "
            "conservar WARDNODE_SECRET_KEY aparte."
        )
        if size_mb <= max_mb:
            send_email(
                to_emails, f"WardNode backup OK — {result.path.name}", body,
                attachments=[(result.path.name, result.path.read_bytes(),
                              "application/zip")],
            )
        else:
            send_email(
                to_emails, f"WardNode backup OK (sin adjunto) — {result.path.name}",
                body + f"\n\nEl archivo excede el límite de adjunto ({max_mb} MB); "
                       "descárgalo desde la página de Backups.",
            )
    except Exception as exc:
        log.warning("backup-worker: fallo enviando email (%s)", type(exc).__name__)
        from app.audit.helpers import log_audit

        log_audit("backup.email", resource_type="backup", severity="warning",
                  status="failure", detail={"error": type(exc).__name__})


def _run_backup_and_notify(now: datetime) -> None:
    from app.backup.service import BackupError, create_backup

    result, error_msg = None, None
    try:
        result = create_backup(reason="scheduled")
        _persist_outcome(now, "ok")
    except BackupError as exc:
        error_msg = str(exc)
        # Persistir también el fallo: no martillear un backup roto cada tick.
        _persist_outcome(now, f"error: {error_msg}")
    _send_result_email(result, error_msg)


def _run_locked(app, now: datetime, backup_hour: int) -> None:
    from app.extensions import db

    if db.engine.dialect.name == "postgresql":
        conn = db.engine.connect()
        try:
            got = conn.execute(
                text("SELECT pg_try_advisory_lock(:key)"),
                {"key": BACKUP_ADVISORY_LOCK_KEY},
            ).scalar()
            if not got:
                return  # otro worker gunicorn lo está ejecutando
            try:
                # Re-check bajo el lock: otro proceso pudo completarlo entre
                # el chequeo inicial y la adquisición del lock.
                if is_backup_due(now, backup_hour, _read_last_run()):
                    _run_backup_and_notify(now)
            finally:
                conn.execute(
                    text("SELECT pg_advisory_unlock(:key)"),
                    {"key": BACKUP_ADVISORY_LOCK_KEY},
                )
        finally:
            conn.close()
    else:
        _run_backup_and_notify(now)


def _backup_loop(app) -> None:
    time.sleep(_BOOT_DELAY_SECONDS)
    while True:
        time.sleep(_TICK_SECONDS)
        try:
            with app.app_context():
                from app.models import AppConfig

                if (AppConfig.get("backup_enabled") or "0") != "1":
                    continue
                try:
                    backup_hour = int(AppConfig.get("backup_hour") or 3)
                except (TypeError, ValueError):
                    backup_hour = 3
                backup_hour = max(0, min(23, backup_hour))

                now = datetime.now(timezone.utc)
                if not is_backup_due(now, backup_hour, _read_last_run()):
                    continue
                _run_locked(app, now, backup_hour)
        except Exception as exc:
            log.warning("backup-worker: error en ciclo (%s), reintento en %ss",
                        type(exc).__name__, _ERROR_BACKOFF_SECONDS)
            try:
                with app.app_context():
                    from app.extensions import db
                    db.session.rollback()
            except Exception:
                pass
            time.sleep(_ERROR_BACKOFF_SECONDS)


def start_backup_thread(app) -> threading.Thread | None:
    """Arranca el worker de backups. No arranca en tests."""
    if app.config.get("TESTING"):
        return None

    t = threading.Thread(target=_backup_loop, args=(app,), name="backup-worker", daemon=True)
    t.start()
    log.info("backup-worker: thread iniciado (backup diario programado)")
    return t
