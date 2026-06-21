"""Monitor de puertos Docker expuestos.

Thread daemon (mismo patrón que backup/worker.py) que verifica periódicamente si
hay puertos Docker publicados hacia el exterior sin protección iptables. Si detecta
puertos expuestos, envía un email de alerta a los admins cada 6 horas mientras el
problema persista. Cuando los puertos quedan protegidos, limpia el timestamp para
que una exposición posterior dispare alerta inmediata.

Requiere módulo WF activo (module_wf_enabled == "1") y SMTP configurado.
Advisory lock PostgreSQL: 815003 (SOC=815001, backup=815002).
"""

import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

log = logging.getLogger(__name__)

_ADVISORY_LOCK_KEY = 815003
_TICK_SECONDS = 60
_BOOT_DELAY_SECONDS = 45
_ERROR_BACKOFF_SECONDS = 60
_ALERT_INTERVAL_HOURS = 6


def _read_last_alert() -> datetime | None:
    from app.models import AppConfig

    raw = AppConfig.get("port_monitor_last_alert_at") or ""
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _clear_last_alert() -> None:
    from app.extensions import db
    from app.models import AppConfig

    if AppConfig.get("port_monitor_last_alert_at"):
        AppConfig.set("port_monitor_last_alert_at", "")
        db.session.commit()


def _save_last_alert(now: datetime) -> None:
    from app.extensions import db
    from app.models import AppConfig

    AppConfig.set("port_monitor_last_alert_at", now.isoformat())
    db.session.commit()


def _admin_emails() -> list[str]:
    from app.models import ROLE_ADMIN, User

    return [u.email for u in User.query.filter_by(role=ROLE_ADMIN).all()]


def _send_alert(exposed: list[dict], now: datetime) -> None:
    from app.audit.helpers import log_audit
    from app.email import send_email, smtp_configured

    if not smtp_configured():
        return

    to_emails = _admin_emails()
    if not to_emails:
        return

    port_lines = "\n".join(
        f"  • {p['host_port']}/{p['proto']}  →  {p['container']}"
        for p in exposed
    )

    body = (
        "WardNode ha detectado puertos Docker publicados públicamente "
        "sin protección iptables.\n\n"
        f"Puertos expuestos ({len(exposed)}):\n"
        f"{port_lines}\n\n"
        "Acción requerida:\n"
        "  Panel → Módulos → WardNode WF → sección «Puertos Docker»\n"
        "  y haz clic en «Bloquear» sobre cada puerto expuesto.\n\n"
        "Esta alerta se repetirá cada 6 horas mientras los puertos "
        "permanezcan sin protección."
    )

    try:
        send_email(
            to_emails,
            f"WardNode: {len(exposed)} puerto(s) Docker expuesto(s) sin protección",
            body,
        )
        _save_last_alert(now)
        log_audit(
            "port_monitor.alert",
            resource_type="port",
            severity="warning",
            detail={"exposed_count": len(exposed),
                    "ports": [f"{p['host_port']}/{p['proto']}" for p in exposed]},
        )
        log.warning("port-monitor: alerta enviada — %d puerto(s) expuesto(s)", len(exposed))
    except Exception as exc:
        log.warning("port-monitor: fallo al enviar alerta (%s)", type(exc).__name__)


def _get_exposed_ports() -> list[dict]:
    """Consulta el agente WF y filtra puertos accesibles desde el exterior sin bloqueo iptables."""
    from app.modules.socket_client import send_command

    result = send_command("list_docker_ports", timeout=20)
    if not result.get("ok"):
        return []
    return [
        p for p in (result.get("ports") or [])
        if not p.get("loopback_only") and not p.get("blocked")
    ]


def _should_alert(now: datetime) -> bool:
    last = _read_last_alert()
    if last is None:
        return True
    return (now - last) >= timedelta(hours=_ALERT_INTERVAL_HOURS)


def _run_check(now: datetime) -> None:
    from app.models import AppConfig

    if AppConfig.get("module_wf_enabled") != "1":
        return

    exposed = _get_exposed_ports()

    if not exposed:
        _clear_last_alert()
        return

    if _should_alert(now):
        _send_alert(exposed, now)


def _run_locked(now: datetime) -> None:
    from app.extensions import db

    if db.engine.dialect.name == "postgresql":
        conn = db.engine.connect()
        try:
            got = conn.execute(
                text("SELECT pg_try_advisory_lock(:key)"),
                {"key": _ADVISORY_LOCK_KEY},
            ).scalar()
            if not got:
                return
            try:
                _run_check(now)
            finally:
                conn.execute(
                    text("SELECT pg_advisory_unlock(:key)"),
                    {"key": _ADVISORY_LOCK_KEY},
                )
        finally:
            conn.close()
    else:
        _run_check(now)


def _monitor_loop(app) -> None:
    time.sleep(_BOOT_DELAY_SECONDS)
    while True:
        time.sleep(_TICK_SECONDS)
        try:
            with app.app_context():
                _run_locked(datetime.now(timezone.utc))
        except Exception as exc:
            log.warning(
                "port-monitor: error en ciclo (%s), reintento en %ss",
                type(exc).__name__,
                _ERROR_BACKOFF_SECONDS,
            )
            try:
                with app.app_context():
                    from app.extensions import db

                    db.session.rollback()
            except Exception:
                pass
            time.sleep(_ERROR_BACKOFF_SECONDS)


def start_port_monitor_thread(app) -> threading.Thread | None:
    """Arranca el monitor de puertos expuestos. No arranca en tests."""
    if app.config.get("TESTING"):
        return None

    t = threading.Thread(
        target=_monitor_loop, args=(app,), name="port-monitor", daemon=True
    )
    t.start()
    log.info("port-monitor: thread iniciado (monitoreo de puertos Docker expuestos)")
    return t
