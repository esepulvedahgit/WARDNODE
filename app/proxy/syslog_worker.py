"""Worker de reenvío syslog — lee modsec_raw_log y audit_log y los envía RFC5424.

Thread daemon (mismo patrón que rawlog_worker.py) que se despierta cada
_TICK_SECONDS y reenvía las filas nuevas desde la última posición del cursor.

Advisory lock 815005 — SOC=815001, backup=815002, port_monitor=815003, rawlog=815004.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from datetime import datetime, timezone

from flask import current_app
from sqlalchemy import func, text

from app.extensions import db
from app.models import AppConfig, AuditLog, ModSecRawLog
from app.proxy.syslog_forwarder import (
    FACILITY_CODES,
    SyslogSender,
    build_rfc5424,
    format_audit_message,
    format_modsec_message,
    severity_from_audit,
    severity_from_modsec,
)

log = logging.getLogger(__name__)

SYSLOG_ADVISORY_LOCK_KEY = 815005

_TICK_SECONDS       = 10
_BOOT_DELAY_SECONDS = 30
_ERROR_BACKOFF      = 30
_BATCH_SIZE         = 500


# ── Helpers de AppConfig ──────────────────────────────────────────────────────

def _get_cursor(key: str) -> int:
    """Lee un cursor de AppConfig (entero); None si no existe."""
    raw = AppConfig.get(key)
    if raw is None:
        return -1   # -1 = no inicializado
    try:
        return int(raw)
    except (ValueError, TypeError):
        return 0


def _set_cursor(key: str, value: int) -> None:
    AppConfig.set(key, str(value))


def _bootstrap_cursor(key: str, model) -> int:
    """Inicializa el cursor al MAX(id) actual.

    Semántica: solo reenviar eventos nuevos desde que se activó el forwarder,
    nunca el histórico.
    """
    max_id = db.session.query(func.max(model.id)).scalar() or 0
    _set_cursor(key, max_id)
    db.session.commit()
    log.info("syslog-forwarder: cursor %s bootstrapped a %d", key, max_id)
    return max_id


# ── Construcción de frames ────────────────────────────────────────────────────

def _build_modsec_frame(row: ModSecRawLog, facility: int) -> str:
    try:
        import json as _json
        raw_dict = _json.loads(row.raw_json)
        sev = severity_from_modsec(raw_dict)
    except Exception:
        sev = 4  # warning

    ts = row.created_at
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)

    return build_rfc5424(
        facility  = facility,
        severity  = sev,
        timestamp = ts,
        hostname  = "wardnode",
        appname   = "wardnode",
        procid    = str(row.id),
        msgid     = "WAF",
        message   = format_modsec_message(row.raw_json),
    )


def _build_audit_frame(row: AuditLog, facility: int) -> str:
    sev = severity_from_audit(row.severity)

    ts = row.created_at
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)

    return build_rfc5424(
        facility  = facility,
        severity  = sev,
        timestamp = ts,
        hostname  = "wardnode",
        appname   = "wardnode",
        procid    = str(row.id),
        msgid     = "AUDIT",
        message   = format_audit_message(row),
    )


# ── Lógica principal de un tick ───────────────────────────────────────────────

def _run_tick(facility_code: int, host: str, port: int, protocol: str, sources: list[str]) -> None:
    """Ejecuta un tick: envía las filas nuevas de cada fuente activa.

    Semántica at-least-once: el cursor solo avanza si el batch completo
    se envió sin error.
    """
    sent_total = int(AppConfig.get("syslog_sent_total") or "0")
    last_error: str | None = None

    with SyslogSender(host, port, protocol) as sender:

        # ── Fuente WAF: modsec_raw_log ───────────────────────────────────
        if "modsecurity" in sources:
            cursor_key = "syslog_cursor_modsec_id"
            cursor = _get_cursor(cursor_key)

            if cursor == -1:
                # Primera activación: bootstrapear (no reenviar histórico)
                cursor = _bootstrap_cursor(cursor_key, ModSecRawLog)

            rows = (
                ModSecRawLog.query
                .filter(ModSecRawLog.id > cursor)
                .order_by(ModSecRawLog.id.asc())
                .limit(_BATCH_SIZE)
                .all()
            )

            if rows:
                try:
                    for row in rows:
                        sender.send(_build_modsec_frame(row, facility_code))
                    new_cursor = rows[-1].id
                    _set_cursor(cursor_key, new_cursor)
                    sent_total += len(rows)
                    log.debug(
                        "syslog-forwarder: enviados %d eventos WAF (cursor → %d)",
                        len(rows), new_cursor,
                    )
                except (OSError, socket.error) as exc:
                    last_error = f"WAF send error: {exc}"
                    log.warning("syslog-forwarder: %s", last_error)

        # ── Fuente Auditoría: audit_log ───────────────────────────────────
        if "audit" in sources:
            cursor_key = "syslog_cursor_audit_id"
            cursor = _get_cursor(cursor_key)

            if cursor == -1:
                cursor = _bootstrap_cursor(cursor_key, AuditLog)

            rows = (
                AuditLog.query
                .filter(AuditLog.id > cursor)
                .order_by(AuditLog.id.asc())
                .limit(_BATCH_SIZE)
                .all()
            )

            if rows:
                try:
                    for row in rows:
                        sender.send(_build_audit_frame(row, facility_code))
                    new_cursor = rows[-1].id
                    _set_cursor(cursor_key, new_cursor)
                    sent_total += len(rows)
                    log.debug(
                        "syslog-forwarder: enviados %d eventos de auditoría (cursor → %d)",
                        len(rows), new_cursor,
                    )
                except (OSError, socket.error) as exc:
                    last_error = f"Audit send error: {exc}"
                    log.warning("syslog-forwarder: %s", last_error)

    # ── Actualizar telemetría ─────────────────────────────────────────────────
    AppConfig.set("syslog_sent_total", str(sent_total))
    if last_error:
        AppConfig.set("syslog_last_error", last_error)
    else:
        AppConfig.set("syslog_last_error", "")
        AppConfig.set(
            "syslog_last_sent_at",
            datetime.now(timezone.utc).isoformat(),
        )
    db.session.commit()


def _run_locked_body(app) -> None:
    """Ejecuta un tick si el forwarder está habilitado. Bajo advisory lock."""
    enabled = AppConfig.get("syslog_enabled") == "1"
    if not enabled:
        return

    host = (AppConfig.get("syslog_host") or "").strip()
    if not host:
        return

    try:
        port = int(AppConfig.get("syslog_port") or "514")
        if not (1 <= port <= 65535):
            port = 514
    except (ValueError, TypeError):
        port = 514

    protocol = AppConfig.get("syslog_protocol") or "udp"
    if protocol not in ("udp", "tcp"):
        protocol = "udp"

    facility_name = AppConfig.get("syslog_facility") or "local7"
    facility_code = FACILITY_CODES.get(facility_name, 23)

    sources_raw = AppConfig.get("syslog_sources") or "modsecurity,audit"
    sources = [s.strip() for s in sources_raw.split(",") if s.strip()]

    try:
        _run_tick(facility_code, host, port, protocol, sources)
    except Exception as exc:
        log.warning("syslog-forwarder: error en tick: %s", exc)
        try:
            AppConfig.set("syslog_last_error", str(exc))
            db.session.commit()
        except Exception:
            db.session.rollback()


def _run_locked(app) -> None:
    """Obtiene advisory lock PostgreSQL y ejecuta el cuerpo del tick."""
    if db.engine.dialect.name == "postgresql":
        conn = db.engine.connect()
        try:
            got = conn.execute(
                text("SELECT pg_try_advisory_lock(:key)"),
                {"key": SYSLOG_ADVISORY_LOCK_KEY},
            ).scalar()
            if not got:
                return  # otro worker gunicorn lo está ejecutando
            try:
                _run_locked_body(app)
            finally:
                conn.execute(
                    text("SELECT pg_advisory_unlock(:key)"),
                    {"key": SYSLOG_ADVISORY_LOCK_KEY},
                )
        finally:
            conn.close()
    else:
        # SQLite en dev/test — ejecutar sin lock
        _run_locked_body(app)


def _syslog_loop(app) -> None:
    time.sleep(_BOOT_DELAY_SECONDS)
    while True:
        try:
            with app.app_context():
                _run_locked(app)
        except Exception as exc:
            log.warning(
                "syslog-forwarder: unhandled error: %s, reintento en %ss",
                exc, _ERROR_BACKOFF,
            )
            time.sleep(_ERROR_BACKOFF)
            continue
        time.sleep(_TICK_SECONDS)


def start_syslog_thread(app) -> threading.Thread | None:
    """Arranca el hilo daemon de reenvío syslog.

    Retorna None en modo TESTING (evita efectos secundarios).
    En PostgreSQL usa advisory lock 815005 para single-writer bajo gunicorn.
    """
    if app.config.get("TESTING"):
        return None
    t = threading.Thread(target=_syslog_loop, args=(app,), name="syslog-forwarder", daemon=True)
    t.start()
    log.info("syslog-forwarder: hilo iniciado (reenvío cada %ds)", _TICK_SECONDS)
    return t
