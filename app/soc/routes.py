import csv
import io
import json
import re
from datetime import datetime, timedelta, timezone

from flask import Response, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user
from sqlalchemy import func

from app.audit.helpers import log_audit
from app.auth.decorators import roles_required
from app.encryption import EncryptionNotConfigured, encrypt_secret
from app.extensions import db, limiter
from app.models import (
    AppConfig,
    MitreAttackTechnique,
    ROLE_ADMIN,
    ROLE_OPERATOR,
    ROLE_READER,
    SocAnalysis,
    SocIncident,
    SocMlModel,
)
from app.soc import bp
from app.soc.llm.router import DEFAULT_MODELS
from app.soc.schema import EMPTY_ANALYSIS

_SEVERITIES = ("low", "medium", "high", "critical")
_PROVIDERS = ("openrouter", "anthropic", "openai", "deepseek", "gemini")
_STATUSES = ("nuevo", "revisado", "descartado", "confirmado")

_KEY_FIELDS = {
    "openrouter_key": "soc_openrouter_api_key",
    "anthropic_key": "soc_anthropic_api_key",
    "openai_key": "soc_openai_api_key",
    "deepseek_key": "soc_deepseek_api_key",
    "gemini_key": "soc_gemini_api_key",
    "abuseipdb_key": "soc_abuseipdb_api_key",
    "telegram_token": "soc_alert_telegram_token",
}

_CHAT_ID_RE = re.compile(r"^-?\d{1,20}$")

# Keys API organizadas por sección del formulario.
_SECTION_KEYS: dict[str, list[str]] = {
    "llm": ["openrouter_key", "anthropic_key", "openai_key", "deepseek_key", "gemini_key"],
    "threat_intel": ["abuseipdb_key"],
    "alerts": ["telegram_token"],
    "detection": [],
    "daily_report": [],
}


def _save_section_keys(section: str, changed: list[str]) -> bool:
    """Guarda las API keys cifradas de la sección indicada.

    Devuelve False si falta WARDNODE_SECRET_KEY (ya emite flash).
    """
    for field in _SECTION_KEYS.get(section, []):
        config_key = _KEY_FIELDS[field]
        raw = (request.form.get(field) or "").strip()
        if not raw:
            continue
        try:
            current_masked = _mask(AppConfig.get_secret(config_key))
        except EncryptionNotConfigured:
            current_masked = ""
        if raw == current_masked:
            continue  # el usuario reenvió la máscara mostrada — no tocar
        try:
            AppConfig.set(config_key, encrypt_secret(raw), encrypted=True)
            changed.append(field)
        except EncryptionNotConfigured:
            flash(
                "No se pudo guardar la API key: WARDNODE_SECRET_KEY no está configurada.",
                "danger",
            )
            return False
    return True


def _save_llm(changed: list[str]) -> bool:
    provider = request.form.get("provider", "")
    if provider in _PROVIDERS and provider != (AppConfig.get("soc_llm_provider") or "openrouter"):
        AppConfig.set("soc_llm_provider", provider)
        changed.append("provider")

    model = (request.form.get("model") or "").strip()[:120]
    if model != (AppConfig.get("soc_llm_model") or ""):
        AppConfig.set("soc_llm_model", model)
        changed.append("model")

    optin = "1" if request.form.get("optin") else "0"
    if optin != (AppConfig.get("soc_data_optin") or "0"):
        AppConfig.set("soc_data_optin", optin)
        changed.append("optin")

    return _save_section_keys("llm", changed)


def _save_threat_intel(changed: list[str]) -> bool:
    return _save_section_keys("threat_intel", changed)


def _save_alerts(changed: list[str]) -> bool:
    alerts_enabled = "1" if request.form.get("alerts_enabled") else "0"
    if alerts_enabled != (AppConfig.get("soc_alerts_enabled") or "0"):
        AppConfig.set("soc_alerts_enabled", alerts_enabled)
        changed.append("alerts_enabled")

    alert_min_severity = request.form.get("alert_min_severity", "")
    if alert_min_severity in _SEVERITIES and alert_min_severity != (
        AppConfig.get("soc_alert_min_severity") or "high"
    ):
        AppConfig.set("soc_alert_min_severity", alert_min_severity)
        changed.append("alert_min_severity")

    alert_email_to = (request.form.get("alert_email_to") or "").strip()[:500]
    sanitized_emails = ",".join(
        e.strip() for e in alert_email_to.split(",")
        if e.strip() and re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", e.strip())
    )
    if sanitized_emails != (AppConfig.get("soc_alert_email_to") or ""):
        AppConfig.set("soc_alert_email_to", sanitized_emails)
        changed.append("alert_email_to")

    chat_id = (request.form.get("alert_telegram_chat_id") or "").strip()
    if chat_id == "" or _CHAT_ID_RE.match(chat_id):
        if chat_id != (AppConfig.get("soc_alert_telegram_chat_id") or ""):
            AppConfig.set("soc_alert_telegram_chat_id", chat_id)
            changed.append("alert_telegram_chat_id")

    try:
        alert_cooldown = max(5, min(1440, int(request.form.get("alert_cooldown", "60"))))
    except (TypeError, ValueError):
        alert_cooldown = 60
    if str(alert_cooldown) != (AppConfig.get("soc_alert_cooldown_min") or "60"):
        AppConfig.set("soc_alert_cooldown_min", str(alert_cooldown))
        changed.append("alert_cooldown")

    return _save_section_keys("alerts", changed)


def _save_detection(changed: list[str]) -> bool:
    min_severity = request.form.get("min_severity", "")
    if min_severity in _SEVERITIES and min_severity != (
        AppConfig.get("soc_analyze_min_severity") or "medium"
    ):
        AppConfig.set("soc_analyze_min_severity", min_severity)
        changed.append("min_severity")

    try:
        interval = max(1, min(60, int(request.form.get("interval", "5"))))
    except (TypeError, ValueError):
        interval = 5
    if str(interval) != (AppConfig.get("soc_worker_interval_min") or "5"):
        AppConfig.set("soc_worker_interval_min", str(interval))
        changed.append("interval")

    ml_enabled = "1" if request.form.get("ml_enabled") else "0"
    if ml_enabled != (AppConfig.get("soc_ml_enabled") or "0"):
        AppConfig.set("soc_ml_enabled", ml_enabled)
        changed.append("ml_enabled")

    try:
        ml_retrain = max(1, min(168, int(request.form.get("ml_retrain_hours", "24"))))
    except (TypeError, ValueError):
        ml_retrain = 24
    if str(ml_retrain) != (AppConfig.get("soc_ml_retrain_hours") or "24"):
        AppConfig.set("soc_ml_retrain_hours", str(ml_retrain))
        changed.append("ml_retrain_hours")

    return True


def _save_daily_report(changed: list[str]) -> bool:
    daily_report_enabled = "1" if request.form.get("daily_report_enabled") else "0"
    if daily_report_enabled != (AppConfig.get("soc_daily_report_enabled") or "0"):
        AppConfig.set("soc_daily_report_enabled", daily_report_enabled)
        changed.append("daily_report_enabled")

    daily_report_email_to = (request.form.get("daily_report_email_to") or "").strip()[:500]
    sanitized_dr_emails = ",".join(
        e.strip() for e in daily_report_email_to.split(",")
        if e.strip() and re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", e.strip())
    )
    if sanitized_dr_emails != (AppConfig.get("soc_daily_report_email_to") or ""):
        AppConfig.set("soc_daily_report_email_to", sanitized_dr_emails)
        changed.append("daily_report_email_to")

    try:
        daily_report_hour = max(0, min(23, int(request.form.get("daily_report_hour", "8"))))
    except (TypeError, ValueError):
        daily_report_hour = 8
    if str(daily_report_hour) != (AppConfig.get("soc_daily_report_hour") or "8"):
        AppConfig.set("soc_daily_report_hour", str(daily_report_hour))
        changed.append("daily_report_hour")

    return True


_SAVE_HANDLERS = {
    "llm": _save_llm,
    "threat_intel": _save_threat_intel,
    "alerts": _save_alerts,
    "detection": _save_detection,
    "daily_report": _save_daily_report,
}

# Secciones cuyo formulario vive en una pestaña con id distinto al `section`.
# Sin este mapeo el redirect aterriza en ?tab=llm / ?tab=threat_intel, que no
# coincide con ningún tab-pane, dejando el contenido vacío.
_SECTION_TO_TAB = {"llm": "ia", "threat_intel": "detection"}


def _soc_required():
    """Returns None if access is allowed, otherwise a redirect response."""
    if AppConfig.get("module_soc_enabled") != "1":
        return redirect(url_for("modules.index"))
    return None


def _mask(value: str | None) -> str:
    if not value:
        return ""
    return ("*" * max(0, len(value) - 4)) + value[-4:]


def _parse_date(value: str):
    try:
        return datetime.strptime(value, "%Y-%m-%d")
    except (ValueError, TypeError):
        return None


def _filtered_incidents_query(args):
    q = SocIncident.query
    estado = args.get("estado", "").strip()
    severidad = args.get("severidad", "").strip()
    if estado in _STATUSES:
        q = q.filter(SocIncident.status == estado)
    if severidad in _SEVERITIES:
        q = q.filter(SocIncident.severity == severidad)
    if (desde := _parse_date(args.get("desde", ""))):
        q = q.filter(SocIncident.created_at >= desde)
    if (hasta := _parse_date(args.get("hasta", ""))):
        q = q.filter(SocIncident.created_at < hasta + timedelta(days=1))
    return q.order_by(SocIncident.created_at.desc())


@bp.get("/")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER)
def index():
    if (r := _soc_required()):
        return r

    now = datetime.now(timezone.utc)
    since_24h = now - timedelta(hours=24)
    since_7d = now - timedelta(days=7)

    # ── KPI cards ─────────────────────────────────────────────────
    open_count = SocIncident.query.filter_by(status="nuevo").count()
    high_24h = SocIncident.query.filter(
        SocIncident.created_at >= since_24h,
        SocIncident.severity.in_(("high", "critical")),
    ).count()
    unique_ips_7d = (
        db.session.query(func.count(func.distinct(SocIncident.source_ip)))
        .filter(SocIncident.created_at >= since_7d)
        .scalar()
    )
    total_7d = SocIncident.query.filter(SocIncident.created_at >= since_7d).count()
    analyzed_7d = (
        db.session.query(func.count(func.distinct(SocAnalysis.incident_id)))
        .join(SocIncident, SocAnalysis.incident_id == SocIncident.id)
        .filter(SocIncident.created_at >= since_7d)
        .scalar()
    )
    analyzed_pct = round(100 * analyzed_7d / total_7d) if total_7d else 0

    # ── Timeline 14 días por severidad ────────────────────────────
    tl_labels, tl_low_med, tl_high, tl_critical = [], [], [], []
    for i in range(13, -1, -1):
        day_start = (now - timedelta(days=i)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        day_end = day_start + timedelta(days=1)
        tl_labels.append(day_start.strftime("%d/%m"))
        rows = (
            db.session.query(SocIncident.severity, func.count())
            .filter(SocIncident.created_at >= day_start, SocIncident.created_at < day_end)
            .group_by(SocIncident.severity)
            .all()
        )
        counts = dict(rows)
        tl_low_med.append(counts.get("low", 0) + counts.get("medium", 0))
        tl_high.append(counts.get("high", 0))
        tl_critical.append(counts.get("critical", 0))

    # ── Donut por severidad (7 días) ──────────────────────────────
    sev_rows = (
        db.session.query(SocIncident.severity, func.count())
        .filter(SocIncident.created_at >= since_7d)
        .group_by(SocIncident.severity)
        .all()
    )
    sev_counts = dict(sev_rows)
    sev_labels = [s for s in ("critical", "high", "medium", "low") if sev_counts.get(s)]
    sev_values = [sev_counts[s] for s in sev_labels]

    # ── Feed: últimos incidentes con su análisis (si existe) ───────
    feed = (
        SocIncident.query.order_by(SocIncident.created_at.desc()).limit(10).all()
    )
    summaries = {}
    for incident in feed:
        if incident.analyses:
            try:
                summaries[incident.id] = json.loads(incident.analyses[0].payload).get(
                    "summary", ""
                )
            except (json.JSONDecodeError, TypeError):
                summaries[incident.id] = ""

    return render_template(
        "soc/index.html",
        open_count=open_count,
        high_24h=high_24h,
        unique_ips_7d=unique_ips_7d,
        analyzed_pct=analyzed_pct,
        tl_labels=tl_labels,
        tl_low_med=tl_low_med,
        tl_high=tl_high,
        tl_critical=tl_critical,
        sev_labels=sev_labels,
        sev_values=sev_values,
        feed=feed,
        summaries=summaries,
    )


@bp.get("/bitacora")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER)
def bitacora():
    if (r := _soc_required()):
        return r

    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1
    per_page = 50

    q = _filtered_incidents_query(request.args)
    total_rows = q.count()
    incidents = q.offset((page - 1) * per_page).limit(per_page).all()
    total_pages = max(1, (total_rows + per_page - 1) // per_page)

    return render_template(
        "soc/bitacora.html",
        incidents=incidents,
        total_rows=total_rows,
        total_pages=total_pages,
        page=page,
        estado=request.args.get("estado", "").strip(),
        severidad=request.args.get("severidad", "").strip(),
        desde=request.args.get("desde", "").strip(),
        hasta=request.args.get("hasta", "").strip(),
    )


@bp.get("/bitacora/export")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER)
def bitacora_export():
    if (r := _soc_required()):
        return r

    incidents = _filtered_incidents_query(request.args).limit(10_000).all()

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "fecha_utc", "ip", "dominio", "eventos", "score",
                "severidad", "estado", "abuse_score", "revisado_por", "revisado_en"])
    for i in incidents:
        w.writerow([
            i.id,
            i.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            i.source_ip,
            i.domain or "",
            i.event_count,
            i.score,
            i.severity,
            i.status,
            i.abuse_score if i.abuse_score is not None else "",
            i.reviewer.email if i.reviewer else "",
            i.reviewed_at.strftime("%Y-%m-%d %H:%M:%S") if i.reviewed_at else "",
        ])

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=wardnode_soc_{ts}.csv"},
    )


@bp.get("/incidente/<int:incident_id>")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER)
def detalle(incident_id: int):
    if (r := _soc_required()):
        return r

    incident = SocIncident.query.get_or_404(incident_id)
    analysis = (
        SocAnalysis.query.filter_by(incident_id=incident.id)
        .order_by(SocAnalysis.created_at.desc())
        .first()
    )

    payload = dict(EMPTY_ANALYSIS)
    if analysis is not None:
        if analysis.read_at is None:
            analysis.read_at = datetime.now(timezone.utc)
            db.session.commit()
        try:
            payload = json.loads(analysis.payload)
        except (json.JSONDecodeError, TypeError):
            payload = dict(EMPTY_ANALYSIS)

    try:
        mitre = json.loads(incident.mitre) if incident.mitre else []
    except (json.JSONDecodeError, TypeError):
        mitre = []

    return render_template(
        "soc/detalle.html",
        incident=incident,
        analysis=analysis,
        payload=payload,
        mitre=mitre,
        optin=AppConfig.get("soc_data_optin") == "1",
    )


@bp.post("/incidente/<int:incident_id>/estado")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
def set_estado(incident_id: int):
    if (r := _soc_required()):
        return r

    incident = SocIncident.query.get_or_404(incident_id)
    estado = request.form.get("estado", "")
    if estado not in _STATUSES:
        return "Estado inválido", 400

    # La revisión humana exige evidencia escrita (refuerzo server-side del
    # required del modal — el flujo de los demás estados no cambia).
    comment = (request.form.get("comment") or "").strip()[:1000]
    if estado == "revisado" and not comment:
        flash("La revisión requiere un comentario.", "warning")
        return redirect(request.referrer or url_for("soc.bitacora"))

    incident.status = estado
    if estado == "nuevo":
        incident.reviewed_by = None
        incident.reviewed_at = None
        incident.review_comment = None
    else:
        incident.reviewed_by = current_user.id
        incident.reviewed_at = datetime.now(timezone.utc)
        if estado == "revisado":
            incident.review_comment = comment
    db.session.commit()

    detail = {"estado": estado, "ip": incident.source_ip}
    if estado == "revisado":
        detail["comment"] = comment
    log_audit(
        "soc.incident.status",
        resource_type="soc_incident",
        resource_name=str(incident.id),
        detail=detail,
    )

    email_failed = False
    if estado == "revisado":
        from app.soc import alerts

        email_failed = not alerts.send_review_email(incident)

    flash(f"Incidente #{incident.id} marcado como {estado}.", "success")
    if email_failed:
        flash(
            "Revisión guardada; el correo de notificación no pudo enviarse "
            "(SMTP no configurado, sin destinatarios o fallo de envío).",
            "info",
        )
    return redirect(request.referrer or url_for("soc.bitacora"))


@bp.post("/incidente/<int:incident_id>/analizar")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("10 per hour")
def analizar(incident_id: int):
    """Análisis IA retroactivo bajo demanda. Corre en la petición web,
    fuera del ciclo del worker (no consume sus caps ni toca el advisory lock)."""
    if (r := _soc_required()):
        return r

    incident = SocIncident.query.get_or_404(incident_id)
    reason = (request.form.get("reason") or "").strip()[:200]

    if AppConfig.get("soc_data_optin") != "1":
        flash(
            "El consentimiento de envío de datos al proveedor LLM no está activado — "
            "actívalo en Configuración.",
            "warning",
        )
        return redirect(url_for("soc.detalle", incident_id=incident.id))

    # Enriquecimiento retroactivo: incidentes creados sin key AbuseIPDB
    # disponible quedaron con abuse_score=None. get_abuse_info ya valida
    # IP pública, cache y key internamente.
    enrich_detail = {}
    if incident.abuse_score is None:
        from app.soc import enrich
        from app.soc.services import _bump_severity

        abuse = enrich.get_abuse_info(incident.source_ip)
        if abuse and abuse.get("abuseConfidenceScore") is not None:
            incident.abuse_score = abuse["abuseConfidenceScore"]
            enrich_detail["abuse_score"] = incident.abuse_score
            if incident.abuse_score >= 75:
                before = incident.severity
                incident.severity = _bump_severity(incident.severity)
                enrich_detail["severity_escalated"] = f"{before} -> {incident.severity}"
            db.session.commit()

    if SocAnalysis.query.filter_by(incident_id=incident.id).first() is not None:
        flash("Este incidente ya tiene un análisis IA.", "info")
        return redirect(url_for("soc.detalle", incident_id=incident.id))

    from app.soc.services import analyze_incident

    analysis = analyze_incident(
        incident, ignore_threshold=True, origin="manual", reason=reason or None
    )

    log_audit(
        "soc.analysis.manual",
        resource_type="soc_incident",
        resource_name=str(incident.id),
        status="success" if analysis else "failure",
        detail={"ip": incident.source_ip, "reason": reason, **enrich_detail},
    )
    if analysis:
        flash(f"Análisis IA generado para el incidente #{incident.id}.", "success")
    else:
        flash(
            "No se pudo generar el análisis: proveedor LLM no configurado o la "
            "llamada falló — revisa la configuración.",
            "warning",
        )
    return redirect(url_for("soc.detalle", incident_id=incident.id))


@bp.get("/notifications/count")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER)
def notifications_count():
    if AppConfig.get("module_soc_enabled") != "1":
        return jsonify({"count": 0})
    count = db.session.query(func.count(SocIncident.id)).filter_by(status="nuevo").scalar()
    return jsonify({"count": count or 0})


@bp.get("/config")
@roles_required(ROLE_ADMIN)
def config():
    if (r := _soc_required()):
        return r

    masked = {}
    encryption_ok = True
    for field, config_key in _KEY_FIELDS.items():
        try:
            masked[field] = _mask(AppConfig.get_secret(config_key))
        except EncryptionNotConfigured:
            masked[field] = ""
            encryption_ok = False

    # Estado de la base CTI MITRE local.
    mitre_count = MitreAttackTechnique.query.count()
    mitre_last = (
        MitreAttackTechnique.query.order_by(MitreAttackTechnique.synced_at.desc())
        .first()
    )

    return render_template(
        "soc/config.html",
        provider=AppConfig.get("soc_llm_provider") or "openrouter",
        model=AppConfig.get("soc_llm_model") or "",
        default_models=DEFAULT_MODELS,
        min_severity=AppConfig.get("soc_analyze_min_severity") or "medium",
        interval=AppConfig.get("soc_worker_interval_min") or "5",
        optin=AppConfig.get("soc_data_optin") == "1",
        masked=masked,
        encryption_ok=encryption_ok,
        mitre_count=mitre_count,
        mitre_synced_at=mitre_last.synced_at if mitre_last else None,
        alerts_enabled=AppConfig.get("soc_alerts_enabled") == "1",
        alert_min_severity=AppConfig.get("soc_alert_min_severity") or "high",
        alert_email_to=AppConfig.get("soc_alert_email_to") or "",
        alert_telegram_chat_id=AppConfig.get("soc_alert_telegram_chat_id") or "",
        alert_cooldown=AppConfig.get("soc_alert_cooldown_min") or "60",
        ml_enabled=AppConfig.get("soc_ml_enabled") == "1",
        ml_retrain_hours=AppConfig.get("soc_ml_retrain_hours") or "24",
        ml_model=SocMlModel.query.order_by(SocMlModel.id.desc()).first(),
        daily_report_enabled=AppConfig.get("soc_daily_report_enabled") == "1",
        daily_report_email_to=AppConfig.get("soc_daily_report_email_to") or "",
        daily_report_hour=AppConfig.get("soc_daily_report_hour") or "8",
        active_tab=request.args.get("tab") or "ia",
    )


@bp.post("/config")
@roles_required(ROLE_ADMIN)
def config_save():
    if (r := _soc_required()):
        return r

    section = request.form.get("section", "")
    changed: list[str] = []

    handler = _SAVE_HANDLERS.get(section)
    if handler is None:
        flash("Sin cambios en la configuración.", "info")
        return redirect(url_for("soc.config"))

    ok = handler(changed)
    tab = _SECTION_TO_TAB.get(section, section)
    if not ok:
        # El handler ya emitió el flash de error apropiado.
        return redirect(url_for("soc.config", tab=tab))

    if changed:
        # Solo nombres de campos — jamás valores ni keys.
        log_audit(
            "soc.config.update",
            resource_type="soc_config",
            detail={"fields_changed": changed},
        )
        flash("Configuración del SOC guardada.", "success")
    else:
        flash("Sin cambios en la configuración.", "info")
    return redirect(url_for("soc.config", tab=tab))


@bp.get("/docs")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER)
def docs():
    """Documentación del flujo y lógica de decisiones del SOC (estática)."""
    if (r := _soc_required()):
        return r
    return render_template("soc/docs.html")


@bp.post("/ml-train")
@roles_required(ROLE_ADMIN)
def ml_train():
    if (r := _soc_required()):
        return r

    from app.soc.ml import train_model

    ok, msg = train_model()
    log_audit(
        "soc.ml.trained" if ok else "soc.ml.train_failed",
        resource_type="soc_config",
        status="success" if ok else "failure",
        detail={"result": msg},
    )
    if ok:
        AppConfig.set(
            "soc_ml_last_trained", datetime.now(timezone.utc).isoformat()
        )
        flash(f"Modelo ML entrenado — {msg}.", "success")
    else:
        flash(f"No se pudo entrenar el modelo ML: {msg}.", "warning")
    return redirect(url_for("soc.config", tab="mantenimiento"))


@bp.post("/mitre-sync")
@roles_required(ROLE_ADMIN)
def mitre_sync():
    if (r := _soc_required()):
        return r

    from app.soc.mitre_cti import sync_mitre_attack

    n, msg = sync_mitre_attack(force=True)
    log_audit(
        "soc.mitre.sync",
        resource_type="soc_config",
        status="success" if msg == "OK" else "failure",
        detail={"techniques": n, "result": msg},
    )
    if msg == "OK":
        flash(f"MITRE ATT&CK sincronizado: {n} técnicas actualizadas.", "success")
    else:
        flash(f"Error sincronizando MITRE ATT&CK: {msg}", "danger")
    return redirect(url_for("soc.config", tab="mantenimiento"))


@bp.post("/daily-report/test")
@roles_required(ROLE_ADMIN)
@limiter.limit("5 per hour")
def daily_report_test():
    """Fuerza el envío del reporte diario ahora (para pruebas del admin).

    No modifica soc_daily_report_last_sent — el envío programado de la hora
    configurada no se ve afectado.
    """
    if (r := _soc_required()):
        return r

    from app.soc.daily_report import send_daily_report

    ok = send_daily_report()
    log_audit(
        "soc.daily_report.test",
        resource_type="soc_config",
        status="success" if ok else "failure",
        detail={"manual": True},
    )
    if ok:
        flash("Reporte diario enviado correctamente.", "success")
    else:
        flash(
            "No se pudo enviar el reporte: SMTP no configurado, sin destinatarios "
            "o fallo de envío — revisa la configuración.",
            "warning",
        )
    return redirect(url_for("soc.config", tab="mantenimiento"))
