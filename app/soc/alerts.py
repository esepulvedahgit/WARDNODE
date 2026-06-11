"""Alertas SOC (Fase 4): email + Telegram con umbral de severidad y cooldown.

notify_incidents() es invocado por services.run_detection_cycle tras el análisis
LLM (para incluir el summary si existe). Cada canal es best-effort: un fallo de
red/SMTP no rompe el ciclo ni bloquea el otro canal.

SEGURIDAD:
- El bot token de Telegram se lee cifrado (AppConfig.get_secret) y JAMÁS aparece
  en logs, mensajes de error ni registros de auditoría — solo type(exc).__name__.
- El chat_id se valida con regex antes de usarse.
- El contenido de la alerta es mínimo (minimización de datos): id, IP, severidad,
  score, dominio, conteo y summary del LLM. Nunca paths de ataque ni payloads —
  el email/Telegram puede viajar en claro.
"""

import json
import logging
import re
from datetime import datetime, timedelta, timezone

from app.audit.helpers import log_audit
from app.extensions import db
from app.models import AppConfig, SocIncident
from app.soc.detect import _SEV_ORDER

log = logging.getLogger(__name__)

ALERT_COOLDOWN_MIN_DEFAULT = 60
_TELEGRAM_TIMEOUT = 10.0
_CHAT_ID_RE = re.compile(r"^-?\d{1,20}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_MAX_RECIPIENTS = 10


def _alert_recipients(config_key: str = "soc_alert_email_to") -> list[str]:
    """Emails destino desde config_key (CSV), validados y capados."""
    raw = AppConfig.get(config_key) or ""
    out = []
    for part in raw.split(","):
        email = part.strip()
        if email and _EMAIL_RE.match(email):
            out.append(email)
        if len(out) >= _MAX_RECIPIENTS:
            break
    return out


def _incident_summary(incident: SocIncident) -> str:
    """Summary del análisis LLM más reciente, si existe (best-effort)."""
    if not incident.analyses:
        return ""
    try:
        return json.loads(incident.analyses[0].payload).get("summary", "") or ""
    except (json.JSONDecodeError, TypeError):
        return ""


def _build_message(incident: SocIncident) -> str:
    """Texto de la alerta — solo metadatos del incidente, sin payloads."""
    lines = [
        f"Incidente SOC #{incident.id} [{incident.severity.upper()}]",
        f"IP atacante: {incident.source_ip}",
    ]
    if incident.domain:
        lines.append(f"Dominio: {incident.domain}")
    lines.append(f"Eventos: {incident.event_count} · score {incident.score:.0f}/100")
    if incident.ml_score is not None:
        lines.append(f"Score ML (anomalía): {incident.ml_score:.0f}/100")
    if incident.abuse_score is not None:
        lines.append(f"AbuseIPDB: {incident.abuse_score}/100")
    summary = _incident_summary(incident)
    if summary:
        lines.append("")
        lines.append(f"Análisis IA: {summary}")
    base_url = (AppConfig.get("soc_alert_base_url") or "").rstrip("/")
    lines.append("")
    lines.append(f"Detalle: {base_url}/soc/incidente/{incident.id}")
    return "\n".join(lines)


def _send_email_alert(incident: SocIncident, message: str) -> bool:
    """Envía la alerta por email. Retorna True si se envió."""
    from app.email import send_soc_alert_email, smtp_configured

    if not smtp_configured():
        return False
    recipients = _alert_recipients()
    if not recipients:
        return False
    try:
        send_soc_alert_email(
            recipients,
            f"[WardNode SOC] Incidente #{incident.id} {incident.severity}"
            f" — {incident.source_ip}",
            message,
        )
        return True
    except Exception as exc:
        log.warning("soc/alerts: email falló para incidente %s: %s",
                    incident.id, type(exc).__name__)
        return False


def _send_telegram_alert(incident: SocIncident, message: str) -> bool:
    """Envía la alerta por Telegram. Retorna True si se envió.

    El token jamás se loggea — solo el tipo de excepción ante fallo.
    """
    from app.encryption import EncryptionNotConfigured

    try:
        token = AppConfig.get_secret("soc_alert_telegram_token")
    except EncryptionNotConfigured:
        return False
    chat_id = (AppConfig.get("soc_alert_telegram_chat_id") or "").strip()
    if not token or not _CHAT_ID_RE.match(chat_id):
        return False

    import httpx

    try:
        resp = httpx.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": message},
            timeout=_TELEGRAM_TIMEOUT,
        )
        resp.raise_for_status()
        return True
    except httpx.HTTPError as exc:
        # Nunca incluir exc completo: la URL contiene el token.
        log.warning("soc/alerts: telegram falló para incidente %s: %s",
                    incident.id, type(exc).__name__)
        return False


def send_review_email(incident: SocIncident) -> bool:
    """Correo con la revisión humana de un incidente (comentario obligatorio).

    Invocado por soc/routes.py:set_estado al marcar "revisado". Best-effort:
    retorna False sin lanzar si SMTP no está configurado, no hay destinatarios
    o el envío falla — la revisión ya quedó guardada y jamás se revierte.
    Mismo principio de minimización de datos que _build_message.
    """
    from app.email import send_soc_alert_email, smtp_configured

    if not smtp_configured():
        return False
    recipients = _alert_recipients()
    if not recipients:
        return False

    reviewer = incident.reviewer.email if incident.reviewer else "desconocido"
    reviewed_at = (
        incident.reviewed_at.strftime("%Y-%m-%d %H:%M UTC")
        if incident.reviewed_at
        else "—"
    )
    lines = [
        f"Incidente SOC #{incident.id} marcado como REVISADO",
        "",
        f"IP atacante: {incident.source_ip}",
    ]
    if incident.domain:
        lines.append(f"Dominio: {incident.domain}")
    lines.append(f"Severidad: {incident.severity} · score {incident.score:.0f}/100")
    lines.append(f"Eventos: {incident.event_count}")
    lines.append("")
    lines.append(f"Revisado por: {reviewer}")
    lines.append(f"Fecha de revisión: {reviewed_at}")
    lines.append(f"Comentario de la revisión: {incident.review_comment or '—'}")
    base_url = (AppConfig.get("soc_alert_base_url") or "").rstrip("/")
    lines.append("")
    lines.append(f"Detalle: {base_url}/soc/incidente/{incident.id}")

    try:
        send_soc_alert_email(
            recipients,
            f"[WardNode SOC] Revisión incidente #{incident.id} — {incident.source_ip}",
            "\n".join(lines),
        )
        return True
    except Exception as exc:
        log.warning("soc/alerts: email de revisión falló para incidente %s: %s",
                    incident.id, type(exc).__name__)
        return False


def _in_cooldown(incident: SocIncident, cooldown_min: int) -> bool:
    """True si otra alerta de la misma IP se envió dentro del cooldown."""
    threshold = datetime.now(timezone.utc) - timedelta(minutes=cooldown_min)
    recent = SocIncident.query.filter(
        SocIncident.source_ip == incident.source_ip,
        SocIncident.id != incident.id,
        SocIncident.alerted_at.isnot(None),
        SocIncident.alerted_at >= threshold,
    ).first()
    return recent is not None


def notify_incidents(incidents: list[SocIncident]) -> None:
    """Alerta los incidentes elegibles por email y/o Telegram. Nunca lanza.

    Guards: soc_alerts_enabled, severidad >= soc_alert_min_severity, cooldown
    por IP (anti-spam). Marca alerted_at solo si al menos un canal envió.
    """
    if AppConfig.get("soc_alerts_enabled") != "1":
        return

    min_severity = AppConfig.get("soc_alert_min_severity") or "high"
    try:
        cooldown_min = int(
            AppConfig.get("soc_alert_cooldown_min") or ALERT_COOLDOWN_MIN_DEFAULT
        )
    except (TypeError, ValueError):
        cooldown_min = ALERT_COOLDOWN_MIN_DEFAULT
    cooldown_min = max(5, min(1440, cooldown_min))

    for incident in incidents:
        try:
            if _SEV_ORDER.get(incident.severity, 0) < _SEV_ORDER.get(min_severity, 2):
                continue
            if _in_cooldown(incident, cooldown_min):
                continue

            message = _build_message(incident)
            channels = []
            if _send_email_alert(incident, message):
                channels.append("email")
            if _send_telegram_alert(incident, message):
                channels.append("telegram")

            if channels:
                incident.alerted_at = datetime.now(timezone.utc)
                db.session.commit()
                log_audit(
                    "soc.alert.sent",
                    resource_type="soc_incident",
                    resource_name=str(incident.id),
                    severity="warning",
                    detail={"channels": channels, "severity": incident.severity},
                )
            else:
                log_audit(
                    "soc.alert.failed",
                    resource_type="soc_incident",
                    resource_name=str(incident.id),
                    status="failure",
                    detail={"reason": "ningún canal disponible o todos fallaron"},
                )
        except Exception as exc:
            log.warning("soc/alerts: fallo inesperado alertando incidente %s: %s",
                        incident.id, type(exc).__name__)
            db.session.rollback()
