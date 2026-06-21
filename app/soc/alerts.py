"""Alertas SOC (Fase 4): email + Telegram con umbral de severidad y cooldown.

notify_incidents() es invocado por services.run_detection_cycle tras el análisis
LLM (para incluir el summary si existe). Cada canal es best-effort: un fallo de
red/SMTP no rompe el ciclo ni bloquea el otro canal.

SEGURIDAD:
- El bot token de Telegram se lee cifrado (AppConfig.get_secret) y JAMÁS aparece
  en logs, mensajes de error ni registros de auditoría — solo type(exc).__name__.
- El chat_id se valida con regex antes de usarse.
- El contenido de la alerta sigue el principio de minimización de datos: se incluyen
  metadatos analíticos (scores, MITRE, hipótesis, recomendaciones, análisis IA) pero
  NUNCA valores crudos de IoCs (paths, URLs, user-agents) — el email/Telegram puede
  viajar en claro o a través de servidores de terceros.
"""

import html as _html
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

_SEV_EMOJI = {
    "critical": "🚨",
    "high": "🔴",
    "medium": "🟡",
    "low": "🟢",
}


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


def _incident_payload(incident: SocIncident) -> dict:
    """Payload del análisis LLM más reciente sin el campo iocs (minimización de datos).

    Retorna un dict con todos los campos analíticos útiles:
    summary, explanation, severity_suggested, confidence, hypotheses,
    recommendations, mitre_techniques. Nunca iocs.
    Retorna {} si no hay análisis o el JSON es inválido.
    """
    if not incident.analyses:
        return {}
    try:
        raw = json.loads(incident.analyses[0].payload)
    except (json.JSONDecodeError, TypeError):
        return {}
    # Excluir iocs — pueden contener paths/URLs de ataque
    return {k: v for k, v in raw.items() if k != "iocs"}


def _incident_summary(incident: SocIncident) -> str:
    """Summary del análisis LLM más reciente, si existe (best-effort)."""
    return _incident_payload(incident).get("summary", "") or ""


def _mitre_combined(incident: SocIncident, payload: dict) -> list[dict]:
    """Lista MITRE deduplicada: unión de mapeo CRS del incidente + técnicas del LLM.

    Cada elemento: {id, name, tactic}. Los IDs del LLM ya fueron validados contra
    ^T\\d{4}(\\.\\d{3})?$ por schema._coerce_mitre antes de persistirse.
    """
    seen: set[str] = set()
    result: list[dict] = []

    # 1. Mapeo CRS estático del incidente
    try:
        crs_list = json.loads(incident.mitre) if incident.mitre else []
    except (json.JSONDecodeError, TypeError):
        crs_list = []
    for t in crs_list:
        tid = t.get("id", "")
        if tid and tid not in seen:
            seen.add(tid)
            result.append({"id": tid, "name": t.get("name", ""), "tactic": t.get("tactic", "")})

    # 2. Técnicas del análisis LLM (si las hay)
    for t in payload.get("mitre_techniques", []):
        tid = t.get("id", "")
        if tid and tid not in seen:
            seen.add(tid)
            result.append({"id": tid, "name": t.get("name", ""), "tactic": t.get("tactic", "")})

    return result


def _build_alert_context(incident: SocIncident) -> dict:
    """Arma el contexto completo para renderizar las plantillas de alerta.

    Excluye iocs del payload para no filtrar paths/URLs en canales no cifrados.
    """
    payload = _incident_payload(incident)
    base_url = (AppConfig.get("soc_alert_base_url") or "").rstrip("/")
    return {
        "incident": incident,
        "payload": payload,
        "mitre_combined": _mitre_combined(incident, payload),
        "base_url": base_url,
    }


def _build_message(incident: SocIncident) -> str:
    """Texto plano enriquecido de la alerta — parte text/plain del correo y fallback."""
    from flask import render_template

    ctx = _build_alert_context(incident)
    try:
        return render_template("soc/email/incident_alert.txt", **ctx)
    except Exception:
        # Fallback minimalista si la plantilla falla
        lines = [
            f"Incidente SOC #{incident.id} [{incident.severity.upper()}]",
            f"IP atacante: {incident.source_ip}",
        ]
        if incident.domain:
            lines.append(f"Dominio: {incident.domain}")
        lines.append(f"Eventos: {incident.event_count} · score {incident.score:.0f}/100")
        summary = _incident_summary(incident)
        if summary:
            lines += ["", f"Análisis IA: {summary}"]
        base_url = ctx["base_url"]
        if base_url:
            lines += ["", f"Detalle: {base_url}/soc/incidente/{incident.id}"]
        return "\n".join(lines)


def _build_telegram_message(incident: SocIncident, ctx: dict) -> str:
    """Mensaje HTML para Telegram (parse_mode=HTML).

    Usa solo tags soportados por la Bot API: <b>, <i>, <code>, <a>.
    Escapa todos los valores de usuario con html.escape() para evitar
    romper el parseo. No incluye IoCs.
    """
    sev = incident.severity.lower()
    emoji = _SEV_EMOJI.get(sev, "⚠")
    sev_upper = incident.severity.upper()
    ip_esc = _html.escape(incident.source_ip)
    payload = ctx.get("payload", {})
    base_url = ctx.get("base_url", "")
    mitre = ctx.get("mitre_combined", [])

    lines = [
        f"{emoji} <b>Incidente SOC #{incident.id} — {sev_upper}</b>",
        "",
        f"🌐 <b>IP origen:</b> <code>{ip_esc}</code>",
    ]
    if incident.domain:
        lines.append(f"🏠 <b>Dominio:</b> <code>{_html.escape(incident.domain)}</code>")
    lines.append(
        f"⏱ <b>Ventana:</b> <code>{incident.window_start.strftime('%Y-%m-%d %H:%M')}"
        f" → {incident.window_end.strftime('%H:%M')} UTC</code>"
    )
    lines.append(f"📋 <b>Eventos WAF:</b> {incident.event_count}  ·  <b>Estado:</b> {incident.status}")
    lines.append("")

    # Scores
    lines.append(f"📊 <b>Score heurístico:</b> {incident.score:.0f}/100")
    if incident.ml_score is not None:
        lines.append(f"🧠 <b>Score ML (anomalía):</b> {incident.ml_score:.0f}/100")
    if incident.abuse_score is not None:
        abuse_warn = " ⚠" if incident.abuse_score >= 75 else ""
        lines.append(f"🔎 <b>AbuseIPDB:</b> {incident.abuse_score}/100{abuse_warn}")

    # Análisis IA
    summary = payload.get("summary", "")
    if summary:
        lines += ["", f"🤖 <b>Análisis IA:</b>"]
        lines.append(_html.escape(summary))
        confidence = payload.get("confidence")
        sev_sug = payload.get("severity_suggested", "")
        if sev_sug or confidence is not None:
            conf_str = f"confianza {confidence}%" if confidence is not None else ""
            sev_str = f"sev. sugerida: {sev_sug}" if sev_sug else ""
            meta = "  ·  ".join(filter(None, [sev_str, conf_str]))
            if meta:
                lines.append(f"<i>{meta}</i>")

    # Recomendaciones (sin IoCs)
    recs = payload.get("recommendations", [])
    if recs:
        lines += ["", "✅ <b>Recomendaciones:</b>"]
        for rec in recs[:3]:  # máximo 3 para no saturar
            prio = rec.get("priority", "media").upper()
            text_esc = _html.escape(rec.get("text", ""))
            lines.append(f"  [{prio}] {text_esc}")

    # MITRE
    if mitre:
        lines += ["", "🛡 <b>MITRE ATT&amp;CK:</b>"]
        for t in mitre[:5]:  # máximo 5
            name_esc = _html.escape(t.get("name", ""))
            tactic = t.get("tactic", "")
            tactic_str = f" ({_html.escape(tactic)})" if tactic else ""
            lines.append(f"  • <code>{t['id']}</code> {name_esc}{tactic_str}")

    return "\n".join(lines)


def _send_email_alert(incident: SocIncident, message: str) -> bool:
    """Envía la alerta por email con HTML enriquecido. Retorna True si se envió."""
    from app.email import send_soc_alert_email, smtp_configured
    from flask import render_template

    if not smtp_configured():
        return False
    recipients = _alert_recipients()
    if not recipients:
        return False
    try:
        ctx = _build_alert_context(incident)
        try:
            html_body = render_template("soc/email/incident_alert.html", **ctx)
        except Exception:
            html_body = None
        send_soc_alert_email(
            recipients,
            f"[WardNode SOC] Incidente #{incident.id} {incident.severity}"
            f" — {incident.source_ip}",
            message,
            html_body=html_body,
        )
        return True
    except Exception as exc:
        log.warning("soc/alerts: email falló para incidente %s: %s",
                    incident.id, type(exc).__name__)
        return False


def _send_telegram_alert(incident: SocIncident, message: str) -> bool:
    """Envía la alerta por Telegram con formato HTML enriquecido. Retorna True si se envió.

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

    ctx = _build_alert_context(incident)
    tg_text = _build_telegram_message(incident, ctx)
    base_url = ctx.get("base_url", "")

    payload: dict = {
        "chat_id": chat_id,
        "text": tg_text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    if base_url:
        payload["reply_markup"] = {
            "inline_keyboard": [[
                {
                    "text": "🔍 Ver detalle",
                    "url": f"{base_url}/soc/incidente/{incident.id}",
                }
            ]]
        }

    try:
        resp = httpx.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json=payload,
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
    from flask import render_template

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
    base_url = (AppConfig.get("soc_alert_base_url") or "").rstrip("/")
    ctx = {
        "incident": incident,
        "reviewer": reviewer,
        "reviewed_at": reviewed_at,
        "base_url": base_url,
    }

    try:
        plain_body = render_template("soc/email/incident_review.txt", **ctx)
    except Exception:
        # Fallback minimalista si la plantilla falla
        lines = [
            f"Incidente SOC #{incident.id} marcado como REVISADO",
            "",
            f"IP atacante: {incident.source_ip}",
        ]
        if incident.domain:
            lines.append(f"Dominio: {incident.domain}")
        lines.append(f"Severidad: {incident.severity} · score {incident.score:.0f}/100")
        lines.append(f"Eventos: {incident.event_count}")
        lines += [
            "",
            f"Revisado por: {reviewer}",
            f"Fecha de revisión: {reviewed_at}",
            f"Comentario de la revisión: {incident.review_comment or '—'}",
        ]
        if base_url:
            lines += ["", f"Detalle: {base_url}/soc/incidente/{incident.id}"]
        plain_body = "\n".join(lines)

    try:
        html_body = render_template("soc/email/incident_review.html", **ctx)
    except Exception:
        html_body = None

    try:
        send_soc_alert_email(
            recipients,
            f"[WardNode SOC] Revisión incidente #{incident.id} — {incident.source_ip}",
            plain_body,
            html_body=html_body,
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
