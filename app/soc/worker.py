"""Worker periódico del módulo SOC.

Thread daemon (patrón start_ingest_thread de app/proxy/ingest.py) que ejecuta
run_detection_cycle() cada soc_worker_interval_min minutos. En PostgreSQL con
gunicorn multi-worker, un advisory lock garantiza que solo un proceso ejecute
el ciclo; en SQLite (dev single-process) se ejecuta directo.
"""

import logging
import threading
import time

from sqlalchemy import text

log = logging.getLogger(__name__)

# Clave fija arbitraria del proyecto para pg_advisory_lock.
SOC_ADVISORY_LOCK_KEY = 815001

_TICK_SECONDS = 15
_BOOT_DELAY_SECONDS = 60
_ERROR_BACKOFF_SECONDS = 30
DEFAULT_INTERVAL_MINUTES = 5


def _cycle_and_retrain() -> None:
    """Ciclo de detección + reentrenamiento ML + reporte diario (bajo el lock)."""
    from app.soc.services import run_detection_cycle

    run_detection_cycle()
    # Reentrenamiento ML time-gated (Fase 5). Import lazy + degradación con
    # gracia si scikit-learn no está instalado (maybe_retrain nunca lanza).
    try:
        from app.soc import ml

        ml.maybe_retrain()
    except ImportError:
        pass
    # Reporte estadístico diario: el advisory lock garantiza que solo un
    # proceso gunicorn ejecute el gate horario. maybe_send_daily_report()
    # es best-effort y nunca lanza.
    from app.soc.daily_report import maybe_send_daily_report

    maybe_send_daily_report()


def _run_cycle_locked(app) -> None:
    """Ejecuta el ciclo de detección con lock multi-worker si aplica."""
    from app.extensions import db

    if db.engine.dialect.name == "postgresql":
        conn = db.engine.connect()
        try:
            got = conn.execute(
                text("SELECT pg_try_advisory_lock(:key)"),
                {"key": SOC_ADVISORY_LOCK_KEY},
            ).scalar()
            if not got:
                return  # otro worker gunicorn ya ejecuta el ciclo
            try:
                _cycle_and_retrain()
            finally:
                conn.execute(
                    text("SELECT pg_advisory_unlock(:key)"),
                    {"key": SOC_ADVISORY_LOCK_KEY},
                )
        finally:
            conn.close()
    else:
        # SQLite: dev single-process, sin advisory locks.
        _cycle_and_retrain()


def _soc_loop(app) -> None:
    time.sleep(_BOOT_DELAY_SECONDS)
    last_run = 0.0
    mitre_sync_attempted = False  # sync inicial CTI: una sola vez por proceso
    while True:
        time.sleep(_TICK_SECONDS)
        try:
            with app.app_context():
                from app.models import AppConfig

                if AppConfig.get("module_soc_enabled") != "1":
                    continue  # thread ocioso: activable sin reiniciar

                # Sync inicial MITRE CTI si la tabla está vacía (una vez).
                if not mitre_sync_attempted:
                    mitre_sync_attempted = True
                    from app.soc.mitre_cti import is_table_empty, sync_mitre_attack

                    if is_table_empty():
                        log.info("soc-worker: tabla MITRE vacía — sync inicial CTI")
                        sync_mitre_attack(force=False)

                try:
                    interval_min = int(
                        AppConfig.get("soc_worker_interval_min") or DEFAULT_INTERVAL_MINUTES
                    )
                except (TypeError, ValueError):
                    interval_min = DEFAULT_INTERVAL_MINUTES
                interval_min = max(1, min(60, interval_min))

                if time.monotonic() - last_run < interval_min * 60:
                    continue
                last_run = time.monotonic()

                _run_cycle_locked(app)
        except Exception as exc:
            log.warning("soc-worker: error en ciclo (%s), reintento en %ss",
                        type(exc).__name__, _ERROR_BACKOFF_SECONDS)
            try:
                with app.app_context():
                    from app.extensions import db
                    db.session.rollback()
            except Exception:
                pass
            time.sleep(_ERROR_BACKOFF_SECONDS)


def start_soc_thread(app) -> threading.Thread | None:
    """Arranca el worker SOC. No arranca en tests."""
    if app.config.get("TESTING"):
        return None

    t = threading.Thread(target=_soc_loop, args=(app,), name="soc-worker", daemon=True)
    t.start()
    log.info("soc-worker: thread iniciado (ciclo de detección periódico)")
    return t
