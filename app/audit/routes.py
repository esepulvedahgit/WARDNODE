import csv
import io
import json
from datetime import datetime, timedelta, timezone

from flask import Blueprint, Response, render_template, request
from sqlalchemy import func

from app.auth.decorators import roles_required
from app.extensions import db
from app.models import AuditLog, ROLE_ADMIN

bp = Blueprint("audit", __name__, url_prefix="/audit")


@bp.get("/")
@roles_required(ROLE_ADMIN)
def index():
    # ── Filtros ──────────────────────────────────────────────────
    try:
        days = max(1, min(int(request.args.get("days", 7)), 90))
    except (ValueError, TypeError):
        days = 7
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1

    severity_f = request.args.get("severity", "").strip()
    action_f   = request.args.get("action",   "").strip()
    per_page   = 50

    now     = datetime.now(timezone.utc)
    since   = now - timedelta(days=days)
    since_24h = now - timedelta(hours=24)
    since_7d  = now - timedelta(days=7)

    # ── KPI cards (ventana 24 h) ──────────────────────────────────
    total_24h      = AuditLog.query.filter(AuditLog.created_at >= since_24h).count()
    failures_24h   = AuditLog.query.filter(AuditLog.created_at >= since_24h,
                                           AuditLog.status == "failure").count()
    user_actions_24h  = AuditLog.query.filter(AuditLog.created_at >= since_24h,
                                              AuditLog.actor_id.isnot(None)).count()
    system_events_24h = AuditLog.query.filter(AuditLog.created_at >= since_24h,
                                              AuditLog.actor_id.is_(None)).count()

    # ── Timeline 7 días × severidad ──────────────────────────────
    tl_labels, tl_info, tl_warning, tl_error = [], [], [], []
    for i in range(6, -1, -1):
        day_start = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
        day_end   = day_start + timedelta(days=1)
        tl_labels.append(day_start.strftime("%d/%m"))
        rows = (db.session.query(AuditLog.severity, func.count())
                .filter(AuditLog.created_at >= day_start, AuditLog.created_at < day_end)
                .group_by(AuditLog.severity).all())
        counts = {sev: cnt for sev, cnt in rows}
        tl_info.append(counts.get("info", 0))
        tl_warning.append(counts.get("warning", 0))
        tl_error.append(counts.get("error", 0) + counts.get("critical", 0))

    # ── Donut por categoría (7 días) ──────────────────────────────
    cat_rows = (db.session.query(AuditLog.resource_type, func.count())
                .filter(AuditLog.created_at >= since_7d)
                .group_by(AuditLog.resource_type)
                .order_by(func.count().desc()).all())
    cat_labels = [r or "sistema" for r, _ in cat_rows]
    cat_values = [c for _, c in cat_rows]

    # ── Top actores (7 días) ──────────────────────────────────────
    actor_rows = (db.session.query(AuditLog.actor_email, func.count())
                  .filter(AuditLog.created_at >= since_7d,
                          AuditLog.actor_id.isnot(None))
                  .group_by(AuditLog.actor_email)
                  .order_by(func.count().desc()).limit(6).all())

    # ── Tabla filtrada ────────────────────────────────────────────
    q = AuditLog.query.filter(AuditLog.created_at >= since)
    if severity_f:
        q = q.filter(AuditLog.severity == severity_f)
    if action_f:
        q = q.filter(AuditLog.action.ilike(f"%{action_f}%"))
    total_rows = q.count()
    events = (q.order_by(AuditLog.created_at.desc())
               .offset((page - 1) * per_page).limit(per_page).all())
    total_pages = max(1, (total_rows + per_page - 1) // per_page)

    # Deserializar detail para la tabla
    for ev in events:
        try:
            ev._detail_obj = json.loads(ev.detail) if ev.detail else None
        except Exception:
            ev._detail_obj = None

    return render_template(
        "audit/index.html",
        # KPIs
        total_24h=total_24h,
        failures_24h=failures_24h,
        user_actions_24h=user_actions_24h,
        system_events_24h=system_events_24h,
        # Timeline
        tl_labels=tl_labels,
        tl_info=tl_info,
        tl_warning=tl_warning,
        tl_error=tl_error,
        # Donut
        cat_labels=cat_labels,
        cat_values=cat_values,
        # Top actores
        actor_rows=actor_rows,
        # Tabla
        events=events,
        total_rows=total_rows,
        total_pages=total_pages,
        page=page,
        per_page=per_page,
        # Filtros activos
        days=days,
        severity_f=severity_f,
        action_f=action_f,
    )


@bp.get("/export")
@roles_required(ROLE_ADMIN)
def export_csv():
    try:
        days = max(1, min(int(request.args.get("days", 30)), 365))
    except (ValueError, TypeError):
        days = 30

    since  = datetime.now(timezone.utc) - timedelta(days=days)
    events = (AuditLog.query
              .filter(AuditLog.created_at >= since)
              .order_by(AuditLog.created_at.desc()).all())

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["timestamp_utc", "actor", "action", "resource_type",
                "resource_name", "ip", "severity", "status", "detail"])
    for e in events:
        w.writerow([
            e.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            e.actor_email,
            e.action,
            e.resource_type or "",
            e.resource_name or "",
            e.ip_address or "",
            e.severity,
            e.status,
            e.detail or "",
        ])

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=wardnode_audit_{ts}.csv"},
    )
