"""Motor SOAR: bloqueo automático de IPs de incidentes SOC.

maybe_block_incidents() es invocado por services.run_detection_cycle tras el
análisis LLM y la notificación de alertas. Sigue el mismo contrato best-effort
que alerts.notify_incidents: NUNCA lanza excepciones ni interrumpe el ciclo.

Flujo de decisión por incidente:
  1. SOAR habilitado (soc_soar_enabled == "1")
  2. Método disponible (módulo ddos o wf activo y operacional)
  3. Severidad >= soc_soar_min_severity (default "high")
  4. IP pública (no banear rangos privados/Docker/loopback)
  5. is_ban_safe() pasa las 5 guardas de seguridad
  6. Anti-repetición: no rebanear la misma IP si ya está bloqueada en la
     ventana SOAR_BLOCK_LOOKBACK (default 6 h)
  7. Ejecutar el bloqueo (crowdsec -> control.ban_ip / ufw -> socket_client)
  8. Marcar incident.blocked* + commit + log_audit + send_block_notification

Razon del ban CrowdSec: "soc-incident-<id>" — aparece en el panel de
decisiones de CrowdSec como origen SOC y cumple el regex ^[\\w\\-]{1,64}$.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from app.audit.helpers import log_audit
from app.extensions import db
from app.models import AppConfig, SocIncident
from app.soc.detect import _SEV_ORDER
from app.soc.enrich import is_public_ip

log = logging.getLogger(__name__)

# Ventana anti-repetición: si la misma IP ya fue bloqueada por SOAR en las
# últimas N horas, no se vuelve a banear (evita saturar CrowdSec / UFW).
SOAR_BLOCK_LOOKBACK = timedelta(hours=6)

# Regex para validar la duración del ban CrowdSec (mismo que en ddos/routes.py)
import re
_DURATION_RE = re.compile(r"^\d+[smhd]$")
_REASON_RE = re.compile(r"^[\w\-]{1,64}$")


def maybe_block_incidents(created: list[SocIncident]) -> None:
    """Evalúa y bloquea las IPs de incidentes nuevos elegibles. Nunca lanza.

    Guards: soc_soar_enabled, método disponible, severidad, IP pública,
    is_ban_safe, anti-repetición.
    """
    if not created:
        return
    if AppConfig.get("soc_soar_enabled") != "1":
        return

    method = AppConfig.get("soc_soar_method") or "crowdsec"

    # ── Gate de disponibilidad del método ─────────────────────────────────
    if method == "crowdsec":
        if AppConfig.get("module_ddos_enabled") != "1":
            log.info("soar: método crowdsec seleccionado pero módulo ddos desactivado — skip")
            return
    elif method == "ufw":
        if AppConfig.get("module_wf_enabled") != "1":
            log.info("soar: método ufw seleccionado pero módulo wf desactivado — skip")
            return
        # Verificar que UFW esté realmente operacional (activo + default deny)
        try:
            from app.modules.socket_client import ufw_is_operational
            if not ufw_is_operational():
                log.info("soar: ufw no está operacional — skip")
                return
        except Exception:
            log.info("soar: no se pudo verificar estado de UFW — skip")
            return
    else:
        log.warning("soar: método desconocido '%s' — skip", method)
        return

    # ── Umbrales de config ─────────────────────────────────────────────────
    min_severity = AppConfig.get("soc_soar_min_severity") or "high"
    duration = AppConfig.get("soc_soar_duration") or "24h"
    if not _DURATION_RE.match(duration):
        duration = "24h"

    now = datetime.now(timezone.utc)

    for incident in created:
        try:
            _evaluate_and_block(incident, method, min_severity, duration, now)
        except Exception:
            log.exception(
                "soar: error inesperado evaluando incidente %s — se continúa con el siguiente",
                incident.id,
            )
            try:
                db.session.rollback()
            except Exception:
                pass


def _evaluate_and_block(
    incident: SocIncident,
    method: str,
    min_severity: str,
    duration: str,
    now: datetime,
) -> None:
    """Evalúa un incidente y ejecuta el bloqueo si aplica."""
    ip = incident.source_ip

    # ── Guard 1: umbral de severidad ──────────────────────────────────────
    if _SEV_ORDER.get(incident.severity, 0) < _SEV_ORDER.get(min_severity, 2):
        return

    # ── Guard 2: IP pública ───────────────────────────────────────────────
    if not is_public_ip(ip):
        log.debug("soar: %s es IP privada/reservada — skip", ip)
        return

    # ── Guard 3: is_ban_safe (5 capas anti-autobloqueo) ───────────────────
    from app.ddos.safety import is_ban_safe
    safe, motivo = is_ban_safe(ip, request_ip="")
    if not safe:
        log.info("soar: %s rechazada por is_ban_safe: %s", ip, motivo)
        return

    # ── Guard 4: anti-repetición — misma IP ya bloqueada por SOAR en la ventana
    threshold = now - SOAR_BLOCK_LOOKBACK
    already = SocIncident.query.filter(
        SocIncident.source_ip == ip,
        SocIncident.id != incident.id,
        SocIncident.blocked.is_(True),
        SocIncident.blocked_at.isnot(None),
        SocIncident.blocked_at >= threshold,
    ).first()
    if already is not None:
        log.debug(
            "soar: %s ya fue bloqueada por SOAR en incidente %s (< %s h) — skip",
            ip, already.id, SOAR_BLOCK_LOOKBACK.seconds // 3600,
        )
        return

    # ── Ejecutar bloqueo ──────────────────────────────────────────────────
    blocked_until = None
    if method == "crowdsec":
        reason = f"soc-incident-{incident.id}"
        # Asegurar que la razón cumple el regex (siempre cumple con id entero)
        if not _REASON_RE.match(reason):
            reason = "soc-auto-block"
        from app.ddos.control import ban_ip
        ok, error_msg = ban_ip(ip, duration=duration, reason=reason)
        if not ok:
            log.warning("soar: CrowdSec ban falló para %s (incidente %s): %s",
                        ip, incident.id, error_msg)
            return
        # Calcular expiración aproximada para trazabilidad
        blocked_until = _parse_duration_to_dt(now, duration)
    elif method == "ufw":
        from app.modules.socket_client import send_command, valid_ip
        if not valid_ip(ip):
            log.warning("soar: IP %s no pasa valid_ip() para UFW — skip", ip)
            return
        try:
            result = send_command("deny_ip", ip=ip)
            if not (result or {}).get("ok"):
                log.warning("soar: UFW deny_ip falló para %s: %s", ip, result)
                return
        except Exception as exc:
            log.warning("soar: excepción al enviar deny_ip para %s: %s", ip, exc)
            return

    # ── Persistir trazabilidad ────────────────────────────────────────────
    incident.blocked = True
    incident.blocked_at = now
    incident.blocked_method = method
    incident.blocked_until = blocked_until
    db.session.commit()

    log_audit(
        "soc.incident.blocked",
        resource_type="soc_incident",
        resource_name=ip,
        severity="warning",
        status="success",
        detail={
            "incident_id": incident.id,
            "method": method,
            "duration": duration if method == "crowdsec" else "permanent",
            "severity": incident.severity,
            "score": incident.score,
        },
    )
    log.info("soar: IP %s bloqueada via %s (incidente %s)", ip, method, incident.id)

    # ── Notificación del bloqueo ──────────────────────────────────────────
    try:
        from app.soc import alerts
        alerts.send_block_notification(incident)
    except Exception:
        log.exception("soar: fallo enviando notificación de bloqueo para incidente %s",
                      incident.id)


def _parse_duration_to_dt(now: datetime, duration: str) -> datetime | None:
    """Convierte "24h", "7d", "30m" etc. a datetime futuro. Devuelve None si falla."""
    try:
        unit = duration[-1]
        value = int(duration[:-1])
        delta_map = {"s": timedelta(seconds=value), "m": timedelta(minutes=value),
                     "h": timedelta(hours=value), "d": timedelta(days=value)}
        delta = delta_map.get(unit)
        return now + delta if delta else None
    except (ValueError, IndexError):
        return None
