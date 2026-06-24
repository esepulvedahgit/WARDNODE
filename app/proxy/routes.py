import base64
import hashlib
import hmac as _hmac_mod
import json as _json
import os
from datetime import datetime, timedelta, timezone
from math import ceil
from urllib.parse import quote as _url_quote

from flask import abort, current_app, flash, jsonify, redirect, render_template, request, send_file, url_for, Response
from sqlalchemy import distinct, func

from app.audit.helpers import log_audit
from app.auth.decorators import roles_required
from app.extensions import csrf, db, limiter
from app.models import (
    AppConfig,
    AttackEvent,
    CustomModSecurityRule,
    GeoBlocklistEntry,
    ModSecRawLog,
    ROLE_ADMIN,
    ROLE_OPERATOR,
    ROLE_READER,
    RuleCategory,
    Site,
    WafRuleExclusion,
)
from app.proxy import bp
from app.proxy.validators import is_valid_domain
from flask_login import current_user

from app.proxy.services import (
    attack_events_to_csv,
    clear_waf_events,
    ensure_default_rule_categories,
    ensure_site_bot_protection,
    ensure_site_traffic_policy,
    is_local_upstream,
    parse_upstream_host_port,
    provision_letsencrypt,
    render_nginx_configs,
    sync_site_rule_settings,
)
from app.proxy.nginx_extra import (
    ensure_site_nginx_extra_config,
    validate_nginx_extra_config,
)
from app.proxy.security_headers import (
    ensure_site_security_headers,
    validate_security_header,
)
from app.proxy.custom_rules import validate_custom_rule, validate_rule_exclusion
from app.proxy.geoip import download_geoip_db, geoip_db_status, get_country_code, read_maxmind_credentials
from app.proxy.geoip_blocklist import write_blocklist_conf, reload_nginx, COUNTRY_NAMES
from app.proxy.rawlog_service import (
    list_log_archives,
    resolve_log_archive_path,
    prune_and_archive,
)


_RESERVED_PORTS = {22, 80, 443, 5000}


@bp.before_app_request
def bootstrap_proxy_catalog():
    if not current_app.extensions.get("proxy_catalog_bootstrapped"):
        ensure_default_rule_categories()
        current_app.extensions["proxy_catalog_bootstrapped"] = True


def _get_service_states() -> dict:
    """Check Docker container states in a single API call. Returns dict with service info."""
    from app.models import AppConfig

    running = set()
    try:
        import docker as docker_sdk
        client = docker_sdk.from_env()
        running = {c.name for c in client.containers.list()}
    except Exception:
        pass

    return {
        "proxy":            "wardnode-proxy"               in running,
        "loki":             "wardnode-loki"                in running,
        "grafana":          "wardnode-grafana"             in running,
        "alloy":            "wardnode-alloy"               in running,
        "prometheus":       "wardnode-prometheus"          in running,
        "nginx-exporter":   "wardnode-nginx-exporter"      in running,
        "crowdsec":         "wardnode-crowdsec"            in running,
        "crowdsec-bouncer": "wardnode-crowdsec-bouncer"    in running,
        "syslog_enabled":   AppConfig.get("syslog_enabled") == "1",
        "syslog_forwarder": _syslog_forwarder_status(),
    }


@bp.get("/")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER)
def dashboard():
    sites = Site.query.order_by(Site.domain).all()
    categories = RuleCategory.query.order_by(RuleCategory.name).all()

    since_24h = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)
    events_24h = AttackEvent.query.filter(AttackEvent.created_at >= since_24h).all()

    blocked_24h = sum(1 for e in events_24h if e.action == "block")
    unique_ips = (
        db.session.query(func.count(func.distinct(AttackEvent.source_ip)))
        .filter(AttackEvent.created_at >= since_24h)
        .scalar() or 0
    )
    waf_active = sum(1 for s in sites if s.waf_enabled)

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    chart_labels, chart_attacks, chart_blocked = [], [], []
    for i in range(23, -1, -1):
        h_start = now - timedelta(hours=i + 1)
        h_end = now - timedelta(hours=i)
        chart_labels.append((now - timedelta(hours=i)).strftime("%H:00"))
        atk = sum(1 for e in events_24h if h_start <= e.created_at < h_end)
        blk = sum(1 for e in events_24h if h_start <= e.created_at < h_end and e.action == "block")
        chart_attacks.append(atk)
        chart_blocked.append(blk)

    cat_counts: dict[str, int] = {}
    for e in events_24h:
        cat_counts[e.category or "Otro"] = cat_counts.get(e.category or "Otro", 0) + 1
    top_categories = sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)[:6]

    all_countries = (
        db.session.query(AttackEvent.country_code, func.count().label("cnt"))
        .filter(AttackEvent.country_code.isnot(None), AttackEvent.created_at >= since_24h)
        .group_by(AttackEvent.country_code)
        .order_by(func.count().desc())
        .all()
    )
    geo_data     = {code: cnt for code, cnt in all_countries}
    top_countries = all_countries[:8]

    # ── Dashboards CrowdSec (solo si el módulo DDoS está activo) ─────────
    ddos_tl_labels: list = []
    ddos_tl_counts: list = []
    ddos_cat_labels: list = []
    ddos_cat_values: list = []

    if AppConfig.get("module_ddos_enabled") == "1":
        try:
            from app.models import DdosBanEvent

            # Timeline: baneos por hora en las últimas 24h
            for i in range(23, -1, -1):
                h_start = now - timedelta(hours=i + 1)
                h_end   = now - timedelta(hours=i)
                ddos_tl_labels.append((now - timedelta(hours=i)).strftime("%H:00"))
                cnt = (
                    db.session.query(func.count())
                    .filter(
                        DdosBanEvent.created_at >= h_start,
                        DdosBanEvent.created_at < h_end,
                    )
                    .scalar() or 0
                )
                ddos_tl_counts.append(cnt)

            # Donut: top 6 escenarios (tipo de ataque)
            cat_rows = (
                db.session.query(DdosBanEvent.scenario, func.count())
                .group_by(DdosBanEvent.scenario)
                .order_by(func.count().desc())
                .limit(6)
                .all()
            )
            ddos_cat_labels = [row[0] or "unknown" for row in cat_rows]
            ddos_cat_values = [row[1] for row in cat_rows]
        except Exception:
            pass  # tabla puede no existir en dev sin migración aplicada

    return render_template(
        "proxy/dashboard.html",
        sites=sites,
        categories=categories,
        stats={
            "events_24h": len(events_24h),
            "blocked_24h": blocked_24h,
            "unique_ips": unique_ips,
            "waf_active": waf_active,
        },
        chart_labels=chart_labels,
        chart_attacks=chart_attacks,
        chart_blocked=chart_blocked,
        top_categories=top_categories,
        top_countries=top_countries,
        geo_data=geo_data,
        country_names=COUNTRY_NAMES,
        service_states=_get_service_states(),
        ddos_tl_labels=ddos_tl_labels,
        ddos_tl_counts=ddos_tl_counts,
        ddos_cat_labels=ddos_cat_labels,
        ddos_cat_values=ddos_cat_values,
    )


# Tope máximo de filas para el export CSV (evita OOM en tablas grandes)
_MAX_EXPORT_ROWS = 50_000

# Eventos por página en la vista paginada
_EVENTS_PER_PAGE = 50

# Logs crudos ModSecurity por página en la vista paginada
_LOGS_PER_PAGE = 100


def _ip_prefix_filter(q, ip: str):
    """Filtra AttackEvent por prefijo de IP con metacaracteres LIKE escapados.

    Usa LIKE 'ip%' (sargable) en lugar de LIKE '%ip%' (comodín inicial),
    lo que permite al motor usar el índice ix_attack_event_ip_created.
    Los metacaracteres % y _ se escapan para evitar over-match (CWE-150).
    """
    esc = ip.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return q.filter(AttackEvent.source_ip.like(f"{esc}%", escape="\\"))


def _parse_event_date(s: str):
    """Parsea una fecha en formato YYYY-MM-DD; devuelve None si inválida."""
    try:
        return datetime.strptime(s, "%Y-%m-%d")
    except (ValueError, TypeError):
        return None


def _build_filtered_events_query(args):
    """Construye la query de AttackEvent aplicando los filtros de la request.

    Reutilizado tanto por events_list (vista paginada) como por events_export (CSV).
    Devuelve la query ordenada por fecha descendente, lista para .limit().
    """
    severity  = args.get("severity", "")
    action    = args.get("action", "")
    domain    = args.get("domain", "").strip()
    ip        = args.get("ip", "").strip()
    date_from = args.get("date_from", "").strip()
    date_to   = args.get("date_to", "").strip()

    dt_from = _parse_event_date(date_from)
    dt_to   = _parse_event_date(date_to)

    q = AttackEvent.query
    if domain:
        q = q.filter(AttackEvent.domain == domain)
    if ip:
        q = _ip_prefix_filter(q, ip)
    if dt_from:
        q = q.filter(AttackEvent.created_at >= dt_from)
    if dt_to:
        q = q.filter(AttackEvent.created_at < dt_to + timedelta(days=1))
    if severity in {"critical", "high", "medium", "low"}:
        q = q.filter(AttackEvent.severity == severity)
    if action in {"block", "detect"}:
        q = q.filter(AttackEvent.action == action)
    return q.order_by(AttackEvent.created_at.desc())


@bp.get("/events")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER)
def events_list():
    severity  = request.args.get("severity", "")
    action    = request.args.get("action", "")
    domain    = request.args.get("domain", "").strip()
    ip        = request.args.get("ip", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to   = request.args.get("date_to", "").strip()
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1

    # Query paginada con todos los filtros activos.
    full_q      = _build_filtered_events_query(request.args)
    total       = full_q.count()
    total_pages = max(1, ceil(total / _EVENTS_PER_PAGE))
    page        = min(page, total_pages)
    events      = full_q.offset((page - 1) * _EVENTS_PER_PAGE).limit(_EVENTS_PER_PAGE).all()

    # Contadores coherentes con los filtros de dominio/IP/fechas (sin filtro sev/acción).
    base_args = {k: v for k, v in request.args.items() if k not in ("severity", "action", "page")}

    def _apply_base(q):
        """Aplica solo filtros de dominio, IP y fechas para contar por severidad/acción."""
        _domain    = base_args.get("domain", "").strip()
        _ip        = base_args.get("ip", "").strip()
        _date_from = _parse_event_date(base_args.get("date_from", ""))
        _date_to   = _parse_event_date(base_args.get("date_to", ""))
        if _domain:
            q = q.filter(AttackEvent.domain == _domain)
        if _ip:
            q = _ip_prefix_filter(q, _ip)
        if _date_from:
            q = q.filter(AttackEvent.created_at >= _date_from)
        if _date_to:
            q = q.filter(AttackEvent.created_at < _date_to + timedelta(days=1))
        return q

    # Conteos por severidad: un solo GROUP BY en lugar de 5 COUNT individuales.
    sev_rows = _apply_base(
        db.session.query(AttackEvent.severity, func.count(AttackEvent.id))
    ).group_by(AttackEvent.severity).all()
    sev_map = {s: c for s, c in sev_rows}
    counts = {sev: sev_map.get(sev, 0) for sev in ("critical", "high", "medium", "low")}
    counts["all"] = sum(sev_map.values())   # equivalente al count sin filtro sev/acción

    # Conteos por acción: un solo GROUP BY en lugar de 2 COUNT individuales.
    act_rows = _apply_base(
        db.session.query(AttackEvent.action, func.count(AttackEvent.id))
    ).group_by(AttackEvent.action).all()
    act_map = {a: c for a, c in act_rows}
    counts["block"]  = act_map.get("block", 0)
    counts["detect"] = act_map.get("detect", 0)

    # IPs únicas bajo filtros de dominio/IP/fechas (sin sev/acción).
    unique_ips = _apply_base(
        db.session.query(func.count(distinct(AttackEvent.source_ip)))
    ).scalar() or 0

    # Dominios distintos que tienen eventos (para el desplegable de filtro).
    domains = [
        row[0] for row in
        db.session.query(AttackEvent.domain).distinct().order_by(AttackEvent.domain).all()
    ]

    ctx = dict(
        events=events, severity=severity, action=action,
        domain=domain, ip=ip, date_from=date_from, date_to=date_to,
        domains=domains, counts=counts, unique_ips=unique_ips,
        page=page, total=total, total_pages=total_pages, per_page=_EVENTS_PER_PAGE,
    )

    # Respuesta parcial para swaps HTMX (solo la región de resultados).
    if request.headers.get("HX-Request"):
        return render_template("proxy/_events_results.html", **ctx)

    return render_template("proxy/events.html", **ctx)


@bp.get("/events/export.csv")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER)
def events_export():
    """Exporta eventos WAF a CSV con feature engineering para el SOC con IA.

    Parámetros de query:
      - Filtros estándar (domain, ip, date_from, date_to, severity, action):
        respetan la selección activa en la vista de eventos.
      - scope=all: ignora los filtros y exporta todos los eventos (dump completo
        para entrenamiento del modelo). Limitado a _MAX_EXPORT_ROWS filas.
    """
    scope = request.args.get("scope", "")

    if scope == "all":
        q = AttackEvent.query.order_by(AttackEvent.created_at.desc())
    else:
        q = _build_filtered_events_query(request.args)

    events = q.limit(_MAX_EXPORT_ROWS).all()

    csv_text = attack_events_to_csv(events)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    log_audit(
        action="export",
        resource_type="attack_events",
        resource_name=f"wardnode_waf_events_{ts}.csv",
        severity="info",
        status="success",
        detail={"rows": len(events), "scope": scope or "filtered", "filters": dict(request.args)},
    )

    return Response(
        csv_text,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=wardnode_waf_events_{ts}.csv"},
    )


@bp.get("/sites")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER)
def sites_list():
    sites = Site.query.order_by(Site.domain).all()
    return render_template("proxy/sites.html", sites=sites)


@bp.post("/sites")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("20 per minute")
def create_site():
    from app.modules.socket_client import send_command as _wf_send, SOCKET_PATH as _WF_SOCKET

    if not AppConfig.get("console_site_id"):
        flash(
            "Por motivos de seguridad, configura el dominio de acceso al panel "
            "(Ajustes → Acceso al panel) antes de crear sitios protegidos.",
            "danger",
        )
        return redirect(url_for("proxy.sites_list"))

    upstream_url = request.form["upstream_url"].strip()

    if is_local_upstream(upstream_url):
        if AppConfig.get("module_wf_enabled") != "1":
            flash(
                "Para proteger un upstream local (127.0.0.1) es necesario activar "
                "el módulo WardNode WF primero.",
                "danger",
            )
            return redirect(url_for("proxy.sites_list"))
        _, _port = parse_upstream_host_port(upstream_url)
        if _port in _RESERVED_PORTS:
            flash(
                f"El puerto {_port} está reservado (22, 80, 443, 5000) y no puede usarse "
                "como upstream local.",
                "danger",
            )
            return redirect(url_for("proxy.sites_list"))

    _domain = request.form["domain"].strip().lower()
    if not is_valid_domain(_domain):
        flash("El dominio no es válido. Usa un FQDN como ejemplo.com o sub.ejemplo.com.", "danger")
        return redirect(url_for("proxy.sites_list"))

    site = Site(
        name=request.form["name"].strip(),
        domain=_domain,
        upstream_url=upstream_url,
        waf_enabled=bool(request.form.get("waf_enabled")),
        letsencrypt_enabled=bool(request.form.get("letsencrypt_enabled")),
        custom_certificate_path=request.form.get("custom_certificate_path") or None,
        custom_certificate_key_path=request.form.get("custom_certificate_key_path") or None,
    )
    db.session.add(site)
    db.session.commit()
    sync_site_rule_settings(site)
    ensure_site_traffic_policy(site)
    ensure_site_security_headers(site)
    ensure_site_nginx_extra_config(site)
    _apply_nginx()
    log_audit("site.create", resource_type="site", resource_name=site.domain,
              detail={"upstream": site.upstream_url, "waf": site.waf_enabled})

    if is_local_upstream(upstream_url) and os.path.exists(_WF_SOCKET):
        _, _port = parse_upstream_host_port(upstream_url)
        _wf_result = _wf_send("protect_host_port", port=_port, timeout=15)
        _verified = _wf_result.get("blocked", _wf_result.get("ok"))
        if _wf_result.get("ok") and _verified:
            site.host_port_blocked = True
            db.session.commit()
            flash(
                f"Sitio agregado. Puerto {_port} verificado como bloqueado en iptables "
                "(acceso externo denegado, solo el proxy WAF entra).",
                "success",
            )
        elif _wf_result.get("ok"):
            flash(
                f"Sitio agregado. El bloqueo del puerto {_port} se ejecutó pero no pudo "
                "verificarse. Revisá el estado en Módulos → WardNode WF.",
                "warning",
            )
        else:
            flash(
                f"Sitio agregado. No se pudo bloquear el puerto {_port} "
                f"({_wf_result.get('error', '')}). Podés gestionarlo desde Módulos → WardNode WF.",
                "warning",
            )
    else:
        flash("Sitio agregado al proxy.", "success")

    return redirect(url_for("proxy.site_detail", site_id=site.id))


@bp.get("/sites/<int:site_id>")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER)
def site_detail(site_id):
    site = Site.query.get_or_404(site_id)
    sync_site_rule_settings(site)
    ensure_site_traffic_policy(site)
    ensure_site_security_headers(site)
    ensure_site_nginx_extra_config(site)
    ensure_site_bot_protection(site)
    _is_local = is_local_upstream(site.upstream_url)
    return render_template(
        "proxy/site_detail.html",
        site=site,
        country_names=COUNTRY_NAMES,
        upstream_is_local=_is_local,
    )


@bp.get("/bot-challenge-preview")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER)
def bot_challenge_preview():
    from flask import Response
    from app.proxy.services import _build_challenge_html
    resp = Response(_build_challenge_html(), mimetype="text/html")
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    return resp


@bp.get("/waf-block-preview")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER)
def waf_block_preview():
    from flask import Response
    from app.proxy.services import _build_waf_block_html
    resp = Response(_build_waf_block_html(), mimetype="text/html")
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    return resp


@bp.post("/sites/<int:site_id>/bot-protection")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("20 per minute")
def update_site_bot_protection(site_id):
    site = Site.query.get_or_404(site_id)
    cfg = ensure_site_bot_protection(site)
    cfg.enabled = bool(request.form.get("bot_protection_enabled"))
    db.session.commit()
    _apply_nginx()
    state = "activada" if cfg.enabled else "desactivada"
    flash(f"Protección contra bots {state}.", "success")
    return redirect(url_for("proxy.site_detail", site_id=site.id))


@bp.post("/sites/<int:site_id>/waf")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("30 per minute")
def update_site_waf(site_id):
    site = Site.query.get_or_404(site_id)
    site.waf_enabled = bool(request.form.get("waf_enabled"))
    db.session.commit()
    _apply_nginx()
    log_audit("site.waf_toggle", resource_type="site", resource_name=site.domain,
              detail={"waf_enabled": site.waf_enabled})
    state = "activado (bloqueo)" if site.waf_enabled else "desactivado (solo detección)"
    flash(f"WAF {state}.", "success")
    return redirect(url_for("proxy.site_detail", site_id=site.id))


@bp.post("/sites/<int:site_id>/rules")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("30 per minute")
def update_site_rules(site_id):
    site = Site.query.get_or_404(site_id)
    try:
        enabled_ids = {int(v) for v in request.form.getlist("category_ids")}
    except ValueError:
        flash("IDs de categorías inválidos.", "danger")
        return redirect(url_for("proxy.site_detail", site_id=site.id))
    for setting in site.rule_settings:
        setting.enabled = setting.category_id in enabled_ids
    db.session.commit()
    _apply_nginx()
    flash("Categorias actualizadas.", "success")
    return redirect(url_for("proxy.site_detail", site_id=site.id))


@bp.post("/sites/<int:site_id>/tls")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("20 per minute")
def update_site_tls(site_id):
    site = Site.query.get_or_404(site_id)
    le_was_enabled = site.letsencrypt_enabled
    site.letsencrypt_enabled = bool(request.form.get("letsencrypt_enabled"))
    site.custom_certificate_path = request.form.get("custom_certificate_path") or None
    site.custom_certificate_key_path = request.form.get("custom_certificate_key_path") or None
    site.force_https = bool(request.form.get("force_https"))
    hsts_mode = request.form.get("hsts_mode", "off")
    if hsts_mode not in ("off", "1y", "1y-sub", "1y-sub-preload"):
        hsts_mode = "off"
    site.hsts_mode = hsts_mode
    if site.letsencrypt_enabled and site.letsencrypt_status not in ("active",):
        site.letsencrypt_status = "pending"
        site.letsencrypt_error = None
    if not site.letsencrypt_enabled and le_was_enabled:
        site.letsencrypt_status = "none"
        site.letsencrypt_error = None
    db.session.commit()
    _apply_nginx()
    flash("Configuracion TLS actualizada.", "success")
    return redirect(url_for("proxy.site_detail", site_id=site.id))


@bp.post("/sites/<int:site_id>/provision-cert")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("5 per hour")
def provision_cert(site_id: int):
    from app.proxy.geoip_blocklist import reload_nginx
    site = db.get_or_404(Site, site_id)
    if not site.letsencrypt_enabled:
        return jsonify({"ok": False, "error": "Let's Encrypt no habilitado para este sitio"}), 400
    email = current_user.email or ""
    if not email:
        return jsonify({"ok": False, "error": "El usuario no tiene email configurado"}), 400

    site.letsencrypt_status = "pending"
    site.letsencrypt_error = None
    db.session.commit()

    ok, err = provision_letsencrypt(site, email)

    if ok:
        site.letsencrypt_status = "active"
        site.letsencrypt_error = None
        site.force_https = True
        db.session.commit()
        render_nginx_configs()
        ok_reload, err_reload = reload_nginx()
        if not ok_reload:
            site.letsencrypt_status = "error"
            site.letsencrypt_error = f"Certificado emitido pero nginx no cargó el config TLS: {err_reload}"
            db.session.commit()
            return jsonify({"ok": False, "error": site.letsencrypt_error}), 500
        return jsonify({"ok": True})

    site.letsencrypt_status = "error"
    site.letsencrypt_error = err
    db.session.commit()
    return jsonify({"ok": False, "error": err}), 500


@bp.post("/sites/<int:site_id>/traffic-policy")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("20 per minute")
def update_site_traffic_policy(site_id):
    site = Site.query.get_or_404(site_id)
    policy = ensure_site_traffic_policy(site)

    requests_per_second = _bounded_int("requests_per_second", 1, 5000)
    burst = _bounded_int("burst", 0, 20000)
    max_connections = _bounded_int("max_connections", 1, 50000)
    if None in {requests_per_second, burst, max_connections}:
        return redirect(url_for("proxy.site_detail", site_id=site.id))
    key_strategy = request.form.get("key_strategy", "ip")
    if key_strategy not in {"ip", "forwarded_for"}:
        flash("Estrategia de clave invalida.", "danger")
        return redirect(url_for("proxy.site_detail", site_id=site.id))

    policy.rate_limit_enabled = bool(request.form.get("rate_limit_enabled"))
    policy.requests_per_second = requests_per_second
    policy.burst = burst
    policy.nodelay = bool(request.form.get("nodelay"))
    policy.conn_limit_enabled = bool(request.form.get("conn_limit_enabled"))
    policy.max_connections = max_connections
    policy.key_strategy = key_strategy
    db.session.commit()
    _apply_nginx()
    flash("Politica de trafico actualizada.", "success")
    return redirect(url_for("proxy.site_detail", site_id=site.id))


@bp.post("/sites/<int:site_id>/security-headers")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("20 per minute")
def update_site_security_headers(site_id):
    site = Site.query.get_or_404(site_id)
    ensure_site_security_headers(site)

    updates = []
    errors = []
    try:
        enabled_ids = {int(v) for v in request.form.getlist("enabled_header_ids")}
        always_ids  = {int(v) for v in request.form.getlist("always_header_ids")}
        header_ids  = [int(v) for v in request.form.getlist("header_ids")]
    except ValueError:
        flash("IDs de headers inválidos.", "danger")
        return redirect(url_for("proxy.site_detail", site_id=site.id))

    headers_by_id = {header.id: header for header in site.security_headers}
    for header_id in header_ids:
        header = headers_by_id.get(header_id)
        if header is None:
            errors.append("Header desconocido.")
            continue
        name = request.form.get(f"header_name_{header_id}", "").strip()
        value = request.form.get(f"header_value_{header_id}", "").strip()
        enabled = header_id in enabled_ids
        always = enabled and header_id in always_ids
        errors.extend(validate_security_header(name, value))
        updates.append((header, name, value, enabled, always))

    new_headers = []
    custom_names = request.form.getlist("custom_header_name")
    custom_values = request.form.getlist("custom_header_value")
    custom_enabled = set(request.form.getlist("custom_header_enabled"))
    custom_always = set(request.form.getlist("custom_header_always"))
    for index, (name, value) in enumerate(zip(custom_names, custom_values)):
        name = name.strip()
        value = value.strip()
        enabled = str(index) in custom_enabled
        always = enabled and str(index) in custom_always
        if not name and not value and not enabled:
            continue
        errors.extend(validate_security_header(name, value))
        new_headers.append((name, value, enabled, always))

    if errors:
        for error in errors:
            flash(error, "danger")
        return redirect(url_for("proxy.site_detail", site_id=site.id))

    for header, name, value, enabled, always in updates:
        header.name = name
        header.value = value
        header.enabled = enabled
        header.always = always

    next_position = max((header.position for header in site.security_headers), default=0) + 1
    from app.models import SecurityHeader

    for name, value, enabled, always in new_headers:
        db.session.add(
            SecurityHeader(
                site=site,
                name=name,
                value=value,
                enabled=enabled,
                always=always,
                position=next_position,
                is_default=False,
            )
        )
        next_position += 1

    db.session.commit()
    _apply_nginx()
    flash("Headers de seguridad actualizados.", "success")
    return redirect(url_for("proxy.site_detail", site_id=site.id))


@bp.post("/sites/<int:site_id>/custom-rules")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("20 per minute")
def update_site_custom_rules(site_id):
    site = Site.query.get_or_404(site_id)
    updates = []
    errors = []
    try:
        enabled_ids = {int(v) for v in request.form.getlist("enabled_rule_ids")}
        rule_ids    = [int(v) for v in request.form.getlist("rule_ids")]
    except ValueError:
        flash("IDs de reglas inválidos.", "danger")
        return redirect(url_for("proxy.site_detail", site_id=site.id))

    rules_by_id = {rule.id: rule for rule in site.custom_rules}

    for rule_id in rule_ids:
        rule = rules_by_id.get(rule_id)
        if rule is None:
            errors.append("Regla personalizada desconocida.")
            continue
        name = request.form.get(f"rule_name_{rule_id}", "").strip()
        rule_text = request.form.get(f"rule_text_{rule_id}", "").strip()
        errors.extend(validate_custom_rule(name, rule_text))
        updates.append((rule, name, rule_text, rule_id in enabled_ids))

    new_name = request.form.get("new_rule_name", "").strip()
    new_rule_text = request.form.get("new_rule_text", "").strip()
    new_enabled = bool(request.form.get("new_rule_enabled"))
    create_new = bool(new_name or new_rule_text or new_enabled)
    if create_new:
        errors.extend(validate_custom_rule(new_name, new_rule_text))

    if errors:
        for error in errors:
            flash(error, "danger")
        return redirect(url_for("proxy.site_detail", site_id=site.id))

    for rule, name, rule_text, enabled in updates:
        rule.name = name
        rule.rule_text = rule_text
        rule.enabled = enabled

    if create_new:
        next_position = max((rule.position for rule in site.custom_rules), default=0) + 1
        db.session.add(
            CustomModSecurityRule(
                site=site,
                name=new_name,
                rule_text=new_rule_text,
                enabled=new_enabled,
                position=next_position,
            )
        )

    db.session.commit()
    _apply_nginx()
    flash("Reglas personalizadas actualizadas.", "success")
    return redirect(url_for("proxy.site_detail", site_id=site.id))


@bp.post("/sites/<int:site_id>/nginx-extra")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("20 per minute")
def update_site_nginx_extra(site_id):
    site = Site.query.get_or_404(site_id)
    config = ensure_site_nginx_extra_config(site)
    server_snippet = request.form.get("server_snippet", "").strip()
    location_snippet = request.form.get("location_snippet", "").strip()
    enabled = bool(request.form.get("enabled"))

    errors = validate_nginx_extra_config(server_snippet, location_snippet)
    if errors:
        for error in errors:
            flash(error, "danger")
        return redirect(url_for("proxy.site_detail", site_id=site.id))

    config.enabled = enabled
    config.server_snippet = server_snippet
    config.location_snippet = location_snippet
    db.session.commit()
    _apply_nginx()
    flash("Configuracion extra de Nginx actualizada.", "success")
    return redirect(url_for("proxy.site_detail", site_id=site.id))


@bp.post("/render")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("10 per minute")
def render_configs():
    from app.proxy.geoip_blocklist import reload_nginx
    rendered_files = render_nginx_configs()
    ok, err = reload_nginx()
    if ok:
        log_audit("system.nginx_render", resource_type="system", resource_name="nginx",
                  detail={"files": len(rendered_files)})
        return jsonify({"ok": True, "files": len(rendered_files)})
    log_audit("system.nginx_render", resource_type="system", resource_name="nginx",
              severity="error", status="failure", detail={"error": err})
    return jsonify({"ok": False, "error": err or "No se pudo recargar nginx"}), 500



@bp.post("/sites/<int:site_id>/delete")
@roles_required(ROLE_ADMIN)
@limiter.limit("10 per minute")
def delete_site(site_id):
    from app.modules.socket_client import send_command as _wf_send, SOCKET_PATH as _WF_SOCKET

    site = Site.query.get_or_404(site_id)
    if site.is_console:
        flash("El sitio de la consola no puede eliminarse desde aquí. Desvinculalo desde Ajustes.", "danger")
        return redirect(url_for("proxy.site_detail", site_id=site.id))
    name = site.name
    domain = site.domain
    if site.host_port_blocked and os.path.exists(_WF_SOCKET):
        _, _port = parse_upstream_host_port(site.upstream_url)
        if _port:
            _wf_send("unprotect_host_port", port=_port, timeout=15)
    db.session.delete(site)
    db.session.commit()
    _apply_nginx()
    log_audit("site.delete", resource_type="site", resource_name=domain,
              detail={"name": name}, severity="warning")
    flash(f'Sitio "{name}" eliminado correctamente.', "success")
    return redirect(url_for("proxy.dashboard"))


@bp.post("/sites/<int:site_id>/upstream")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("20 per minute")
def update_site_upstream(site_id):
    from app.modules.socket_client import send_command as _wf_send, SOCKET_PATH as _WF_SOCKET

    site = Site.query.get_or_404(site_id)

    if site.is_console:
        flash(
            "El upstream del sitio de la consola se gestiona desde "
            "Ajustes → Acceso al panel.",
            "danger",
        )
        return redirect(url_for("proxy.site_detail", site_id=site.id))

    new_upstream = request.form.get("upstream_url", "").strip()
    if not new_upstream:
        flash("La URL del upstream no puede estar vacía.", "danger")
        return redirect(url_for("proxy.site_detail", site_id=site.id))

    if is_local_upstream(new_upstream):
        if AppConfig.get("module_wf_enabled") != "1":
            flash(
                "Para usar un upstream local (127.0.0.1) es necesario activar "
                "el módulo WardNode WF primero.",
                "danger",
            )
            return redirect(url_for("proxy.site_detail", site_id=site.id))
        _, _new_port = parse_upstream_host_port(new_upstream)
        if _new_port in _RESERVED_PORTS:
            flash(
                f"El puerto {_new_port} está reservado (22, 80, 443, 5000) y no puede usarse "
                "como upstream local.",
                "danger",
            )
            return redirect(url_for("proxy.site_detail", site_id=site.id))

    if new_upstream == site.upstream_url:
        flash("El upstream no cambió.", "info")
        return redirect(url_for("proxy.site_detail", site_id=site.id))

    # Capturar estado previo antes de mutar
    old_upstream = site.upstream_url
    old_blocked = site.host_port_blocked
    _, old_port = parse_upstream_host_port(old_upstream)

    site.upstream_url = new_upstream
    site.host_port_blocked = False
    db.session.commit()

    _apply_nginx()
    log_audit(
        "site.upstream_update",
        resource_type="site",
        resource_name=site.domain,
        detail={"old": old_upstream, "new": new_upstream},
        severity="warning",
    )

    # Gestionar transición de protección de puerto WF
    _wf_flash_done = False
    if os.path.exists(_WF_SOCKET):
        # Desbloquear puerto viejo si estaba bloqueado
        if old_blocked and is_local_upstream(old_upstream):
            _wf_send("unprotect_host_port", port=old_port, timeout=15)

        # Bloquear puerto nuevo si aplica
        if is_local_upstream(new_upstream):
            _, _new_port = parse_upstream_host_port(new_upstream)
            _wf_result = _wf_send("protect_host_port", port=_new_port, timeout=15)
            _verified = _wf_result.get("blocked", _wf_result.get("ok"))
            if _wf_result.get("ok") and _verified:
                site.host_port_blocked = True
                db.session.commit()
                flash(
                    f"Upstream actualizado. Puerto {_new_port} verificado como bloqueado en iptables "
                    "(acceso externo denegado, solo el proxy WAF entra).",
                    "success",
                )
            elif _wf_result.get("ok"):
                flash(
                    f"Upstream actualizado. El bloqueo del puerto {_new_port} se ejecutó "
                    "pero no pudo verificarse. Revisá el estado en Módulos → WardNode WF.",
                    "warning",
                )
            else:
                flash(
                    f"Upstream actualizado. No se pudo bloquear el puerto {_new_port} "
                    f"({_wf_result.get('error', '')}). "
                    "Podés hacerlo desde esta misma página.",
                    "warning",
                )
            _wf_flash_done = True

    if not _wf_flash_done:
        flash("Upstream actualizado correctamente.", "success")

    return redirect(url_for("proxy.site_detail", site_id=site.id))


@bp.post("/sites/<int:site_id>/geo-blocklist/add")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("30 per minute")
def geo_blocklist_add(site_id):
    site = Site.query.get_or_404(site_id)
    code = request.form.get("country_code", "").strip().upper()
    if not code or len(code) != 2:
        flash("Código de país inválido.", "danger")
        return redirect(url_for("proxy.site_detail", site_id=site_id))
    name = COUNTRY_NAMES.get(code, code)
    existing = GeoBlocklistEntry.query.filter_by(site_id=site_id, country_code=code).first()
    if existing:
        existing.enabled = True
        flash(f"{name} ya estaba en la lista (reactivado).", "info")
    else:
        db.session.add(GeoBlocklistEntry(site_id=site_id, country_code=code, country_name=name))
        flash(f"{name} agregado a la lista de bloqueo.", "success")
    db.session.commit()
    write_blocklist_conf(site)
    ok, err = reload_nginx()
    if not ok:
        flash(f"Nginx no recargado: {err or 'socket no disponible en modo local'}", "warning")
    return redirect(url_for("proxy.site_detail", site_id=site_id))


@bp.post("/sites/<int:site_id>/geo-blocklist/<code>/remove")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("30 per minute")
def geo_blocklist_remove(site_id, code):
    site = Site.query.get_or_404(site_id)
    entry = GeoBlocklistEntry.query.filter_by(
        site_id=site_id, country_code=code.upper()
    ).first_or_404()
    name = entry.country_name
    db.session.delete(entry)
    db.session.commit()
    write_blocklist_conf(site)
    ok, err = reload_nginx()
    if not ok:
        flash(f"Nginx no recargado: {err or 'socket no disponible en modo local'}", "warning")
    flash(f"{name} eliminado de la lista de bloqueo.", "success")
    return redirect(url_for("proxy.site_detail", site_id=site_id))


@bp.post("/sites/<int:site_id>/rule-exclusions")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("20 per minute")
def update_site_rule_exclusions(site_id):
    """Añade una exclusión WAF por ID de regla CRS o actualiza el estado enabled de las existentes."""
    site = Site.query.get_or_404(site_id)

    # ── Actualizar estado enabled de exclusiones existentes ───────────────────
    try:
        enabled_ids = {int(v) for v in request.form.getlist("enabled_exclusion_ids")}
        exclusion_ids = [int(v) for v in request.form.getlist("exclusion_ids")]
    except ValueError:
        flash("IDs de exclusiones inválidos.", "danger")
        return redirect(url_for("proxy.site_detail", site_id=site.id))

    exclusions_by_id = {ex.id: ex for ex in site.rule_exclusions}
    toggled = []
    for ex_id in exclusion_ids:
        ex = exclusions_by_id.get(ex_id)
        if ex is None:
            flash("Exclusión desconocida.", "danger")
            return redirect(url_for("proxy.site_detail", site_id=site.id))
        new_enabled = ex_id in enabled_ids
        if ex.enabled != new_enabled:
            ex.enabled = new_enabled
            toggled.append(ex)

    if toggled:
        log_audit(
            actor_email=current_user.email,
            action="waf.rule_exclusion.toggle",
            resource_type="site",
            resource_name=site.domain,
            severity="warning",
            status="success",
            detail=str({"toggled": [{"rule_id": e.rule_id, "enabled": e.enabled} for e in toggled]}),
        )

    # ── Alta de nueva exclusión ───────────────────────────────────────────────
    new_id_raw = request.form.get("new_exclusion_rule_id", "").strip()
    new_comment = request.form.get("new_exclusion_comment", "").strip()
    if new_id_raw:
        rule_id, errs = validate_rule_exclusion(new_id_raw, new_comment)
        if errs:
            for e in errs:
                flash(e, "danger")
            return redirect(url_for("proxy.site_detail", site_id=site.id))

        # Verificar duplicado antes de insertar (mensaje amigable antes del IntegrityError)
        existing = WafRuleExclusion.query.filter_by(site_id=site.id, rule_id=rule_id).first()
        if existing:
            flash(
                f"La regla {rule_id} ya tiene una excepción configurada para este sitio.",
                "warning",
            )
            return redirect(url_for("proxy.site_detail", site_id=site.id))

        db.session.add(
            WafRuleExclusion(
                site=site,
                rule_id=rule_id,
                comment=new_comment[:200] if new_comment else None,
                enabled=True,
            )
        )
        log_audit(
            actor_email=current_user.email,
            action="waf.rule_exclusion.add",
            resource_type="site",
            resource_name=site.domain,
            severity="warning",
            status="success",
            detail=str({"rule_id": rule_id, "comment": new_comment}),
        )

    db.session.commit()
    _apply_nginx()
    flash("Excepciones WAF actualizadas.", "success")
    return redirect(url_for("proxy.site_detail", site_id=site.id))


@bp.post("/sites/<int:site_id>/rule-exclusions/<int:exclusion_id>/remove")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("20 per minute")
def remove_site_rule_exclusion(site_id, exclusion_id):
    """Elimina una exclusión WAF por ID de regla CRS."""
    site = Site.query.get_or_404(site_id)
    ex = WafRuleExclusion.query.filter_by(id=exclusion_id, site_id=site.id).first_or_404()
    rule_id = ex.rule_id
    db.session.delete(ex)
    db.session.commit()
    _apply_nginx()
    log_audit(
        actor_email=current_user.email,
        action="waf.rule_exclusion.remove",
        resource_type="site",
        resource_name=site.domain,
        severity="warning",
        status="success",
        detail=str({"rule_id": rule_id}),
    )
    flash(f"Exclusión de la regla {rule_id} eliminada.", "success")
    return redirect(url_for("proxy.site_detail", site_id=site.id))


@bp.get("/settings")
@roles_required(ROLE_ADMIN)
def settings():
    from app.models import AppConfig
    from app.encryption import decrypt_secret, EncryptionNotConfigured

    account_id_masked = ""
    license_configured = False
    try:
        enc_id = AppConfig.get("maxmind_account_id")
        enc_key = AppConfig.get("maxmind_license_key")
        if enc_id:
            raw = decrypt_secret(enc_id) or ""
            account_id_masked = ("*" * max(0, len(raw) - 4) + raw[-4:]) if raw else ""
        license_configured = bool(enc_key)
    except EncryptionNotConfigured:
        pass

    encryption_ready = bool(current_app.config.get("WARDNODE_SECRET_KEY"))

    secrets_broken = False
    if encryption_ready:
        try:
            from app.encryption import has_undecryptable_secrets
            secrets_broken = has_undecryptable_secrets()
        except Exception:
            pass

    console_site = None
    console_site_id = AppConfig.get("console_site_id")
    if console_site_id and console_site_id.isdigit():
        console_site = db.session.get(Site, int(console_site_id))

    smtp_host     = AppConfig.get("smtp_host") or ""
    smtp_port     = AppConfig.get("smtp_port") or "587"
    smtp_from     = AppConfig.get("smtp_from") or ""
    smtp_use_tls  = (AppConfig.get("smtp_use_tls") or "1") == "1"
    smtp_username_raw = AppConfig.get("smtp_username")
    smtp_username_masked = None
    if smtp_username_raw:
        try:
            raw = decrypt_secret(smtp_username_raw) or ""
            smtp_username_masked = ("*" * max(0, len(raw) - 4) + raw[-4:]) if raw else ""
        except EncryptionNotConfigured:
            smtp_username_masked = "***"

    syslog_enabled  = AppConfig.get("syslog_enabled") == "1"
    syslog_host     = AppConfig.get("syslog_host") or ""
    syslog_port     = AppConfig.get("syslog_port") or "514"
    syslog_protocol = AppConfig.get("syslog_protocol") or "udp"
    syslog_facility = AppConfig.get("syslog_facility") or "local7"
    syslog_sources  = (AppConfig.get("syslog_sources") or "modsecurity,audit").split(",")
    syslog_running  = _syslog_forwarder_status()

    # GeoIP: DB status + enrichment coverage (last 24h)
    db_path_str = current_app.config.get("GEOIP_DB_PATH", "")
    geoip_status = geoip_db_status(db_path_str)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    geoip_coverage_total = db.session.query(func.count(AttackEvent.id)).filter(
        AttackEvent.created_at >= cutoff
    ).scalar() or 0
    geoip_coverage_with = db.session.query(func.count(AttackEvent.id)).filter(
        AttackEvent.created_at >= cutoff,
        AttackEvent.country_code.isnot(None),
    ).scalar() or 0
    geoip_coverage = (
        round(geoip_coverage_with * 100 / geoip_coverage_total)
        if geoip_coverage_total > 0 else None
    )

    return render_template(
        "proxy/settings.html",
        account_id_masked=account_id_masked,
        license_configured=license_configured,
        encryption_ready=encryption_ready,
        console_site=console_site,
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_from=smtp_from,
        smtp_use_tls=smtp_use_tls,
        smtp_username_masked=smtp_username_masked,
        syslog_enabled=syslog_enabled,
        syslog_host=syslog_host,
        syslog_port=syslog_port,
        syslog_protocol=syslog_protocol,
        syslog_facility=syslog_facility,
        syslog_sources=syslog_sources,
        syslog_running=syslog_running,
        secrets_broken=secrets_broken,
        geoip_status=geoip_status,
        geoip_coverage=geoip_coverage,
        geoip_coverage_total=geoip_coverage_total,
        geoip_coverage_with=geoip_coverage_with,
    )


@bp.post("/settings/reset-secrets")
@roles_required(ROLE_ADMIN)
@limiter.limit("3 per minute")
def settings_reset_secrets():
    import json
    from app.encryption import reset_encrypted_secrets
    from app.audit.helpers import log_audit
    result = reset_encrypted_secrets()
    log_audit(
        "settings.reset_secrets",
        resource_type="config",
        severity="warning",
        detail=json.dumps({"cleared_keys": result["keys"], "totp_reset": result["totp"]}),
    )
    flash(
        f"Se borraron {result['secrets']} secreto(s) cifrado(s) y se restableció el 2FA de "
        f"{result['totp']} usuario(s). Vuelve a ingresar las credenciales y re-inscribir 2FA.",
        "warning",
    )
    return redirect(url_for("proxy.settings"))


@bp.post("/settings/clear-waf-events")
@roles_required(ROLE_ADMIN)
@limiter.limit("3 per minute")
def settings_clear_waf_events():
    """Borra todos los AttackEvent y reinicia los paneles del overview WAF."""
    n = clear_waf_events()
    log_audit(
        "settings.clear_waf_events",
        resource_type="attack_events",
        severity="warning",
        status="success",
        detail={"deleted": n},
    )
    flash(f"Overview WAF reiniciado: se borraron {n} evento(s).", "success")
    return redirect(url_for("proxy.settings"))


@bp.post("/dismiss-setup-prompt")
@roles_required(ROLE_ADMIN)
def dismiss_setup_prompt():
    AppConfig.set("setup_prompt_shown", "1")
    return jsonify({"ok": True})


@bp.post("/settings/console-site")
@roles_required(ROLE_ADMIN)
@limiter.limit("10 per minute")
def save_console_site():
    from app.models import AppConfig

    domain = request.form.get("console_domain", "").strip().lower()
    port = request.form.get("console_port", "5000").strip() or "5000"

    if not domain:
        flash("El dominio es requerido.", "danger")
        return redirect(url_for("proxy.settings"))

    if not is_valid_domain(domain):
        flash("El dominio no es válido. Usa un FQDN como panel.midominio.com.", "danger")
        return redirect(url_for("proxy.settings"))

    upstream = f"http://console:{port}"

    console_site_id = AppConfig.get("console_site_id")
    site = None
    if console_site_id and console_site_id.isdigit():
        site = db.session.get(Site, int(console_site_id))

    if site is None:
        site = Site.query.filter_by(is_console=True).first()

    # Detectar puesta en marcha inicial ANTES de crear el Site.
    # Si sigue siendo None tras ambas búsquedas es la primera configuración real.
    is_first_setup = site is None

    if site is None:
        site = Site(name="WardNode Console", is_console=True)
        db.session.add(site)

    site.domain = domain
    site.upstream_url = upstream
    site.is_console = True
    db.session.commit()

    AppConfig.set("console_site_id", str(site.id))

    # Limpiar eventos WAF acumulados antes de la puesta en marcha real.
    # Solo se dispara la primera vez; editar el dominio después no borra datos.
    if is_first_setup:
        n = clear_waf_events()
        log_audit(
            "console.first_setup_waf_reset",
            resource_type="attack_events",
            severity="info",
            status="success",
            detail={"deleted": n},
        )

    # Si WF está activo bloquear el puerto 5000 de forma diferida para que este
    # redirect llegue al cliente antes de que iptables corte TCP:5000.
    if AppConfig.get("module_wf_enabled") == "1":
        from app.modules.routes import _secure_port_async
        from app.modules.socket_client import SOCKET_PATH as _WF_SOCK
        if os.path.exists(_WF_SOCK):
            _secure_port_async(delay=5)
            flash(
                "Dominio de consola configurado. El acceso por el puerto 5000 quedará bloqueado "
                f"en segundos — usa http://{domain} para continuar.",
                "warning",
            )
            return redirect(f"http://{domain}" + url_for("auth.login") + "?reason=port_secured")

    flash("Sitio de consola configurado correctamente.", "success")
    return redirect(url_for("proxy.site_detail", site_id=site.id))


@bp.post("/settings")
@roles_required(ROLE_ADMIN)
@limiter.limit("10 per minute")
def settings_save():
    from app.models import AppConfig
    from app.encryption import encrypt_secret, EncryptionNotConfigured

    if not current_app.config.get("WARDNODE_SECRET_KEY"):
        flash("WARDNODE_SECRET_KEY no configurado en .env.", "danger")
        return redirect(url_for("proxy.settings"))

    account_id = request.form.get("account_id", "").strip()
    license_key = request.form.get("license_key", "").strip()

    try:
        if account_id:
            AppConfig.set("maxmind_account_id", encrypt_secret(account_id), encrypted=True)
        if license_key:
            AppConfig.set("maxmind_license_key", encrypt_secret(license_key), encrypted=True)
    except EncryptionNotConfigured as exc:
        flash(str(exc), "danger")
        return redirect(url_for("proxy.settings"))

    if account_id or license_key:
        flash("Credenciales MaxMind guardadas correctamente.", "success")
    return redirect(url_for("proxy.settings"))


@bp.post("/settings/geoip-download")
@roles_required(ROLE_ADMIN)
@limiter.limit("5 per hour")
def geoip_download():
    """Descarga o actualiza la base GeoLite2-Country desde MaxMind bajo demanda."""
    if not current_app.config.get("WARDNODE_SECRET_KEY"):
        flash("WARDNODE_SECRET_KEY no configurado en .env.", "danger")
        return redirect(url_for("proxy.settings"))

    account_id, license_key = read_maxmind_credentials()
    if not account_id or not license_key:
        flash("Credenciales MaxMind no configuradas. Configúralas primero.", "warning")
        return redirect(url_for("proxy.settings"))

    db_path_str = current_app.config.get("GEOIP_DB_PATH", "")
    ok, msg = download_geoip_db(db_path_str, account_id, license_key)

    if ok:
        try:
            render_nginx_configs()
        except Exception:
            pass  # la regeneración de config es no-fatal; el proxy seguirá funcionando
        flash(msg, "success")
        log_audit(
            actor_email=current_user.email,
            action="geoip_db_download",
            resource_type="geoip",
            resource_name="GeoLite2-Country",
            severity="info",
            status="success",
            detail=msg,
        )
    else:
        flash(f"Error al descargar la base GeoIP: {msg}", "danger")
        log_audit(
            actor_email=current_user.email,
            action="geoip_db_download",
            resource_type="geoip",
            resource_name="GeoLite2-Country",
            severity="warning",
            status="failure",
            detail=msg,
        )

    return redirect(url_for("proxy.settings"))


@bp.post("/settings/smtp")
@roles_required(ROLE_ADMIN)
@limiter.limit("10 per minute")
def settings_save_smtp():
    from app.models import AppConfig
    from app.encryption import encrypt_secret, EncryptionNotConfigured

    host     = request.form.get("smtp_host", "").strip()
    port     = request.form.get("smtp_port", "587").strip() or "587"
    username = request.form.get("smtp_username", "").strip()
    password = request.form.get("smtp_password", "").strip()
    from_    = request.form.get("smtp_from", "").strip()
    use_tls  = "1" if request.form.get("smtp_use_tls") else "0"

    AppConfig.set("smtp_host", host)
    AppConfig.set("smtp_port", port)
    AppConfig.set("smtp_use_tls", use_tls)
    AppConfig.set("smtp_from", from_)
    try:
        if username:
            AppConfig.set("smtp_username", encrypt_secret(username), encrypted=True)
        if password:
            AppConfig.set("smtp_password", encrypt_secret(password), encrypted=True)
    except EncryptionNotConfigured as exc:
        flash(str(exc), "danger")
        return redirect(url_for("proxy.settings"))

    flash("Configuracion SMTP guardada.", "success")
    return redirect(url_for("proxy.settings"))


@bp.post("/settings/smtp-test")
@roles_required(ROLE_ADMIN)
@limiter.limit("5 per minute")
def settings_smtp_test():
    from app.email import send_password_reset_email
    try:
        send_password_reset_email(current_user.email, "https://example.com/test-wardnode")
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.post("/settings/syslog")
@roles_required(ROLE_ADMIN)
@limiter.limit("10 per minute")
def settings_save_syslog():
    from app.models import AppConfig

    enabled  = "1" if request.form.get("syslog_enabled") else "0"
    host     = request.form.get("syslog_host", "").strip()
    port     = request.form.get("syslog_port", "514").strip() or "514"
    protocol = request.form.get("syslog_protocol", "udp")
    facility = request.form.get("syslog_facility", "local7")
    sources  = ",".join(request.form.getlist("syslog_sources"))

    import re as _re
    if enabled == "1" and not host:
        flash("El host del servidor syslog es requerido.", "danger")
        return redirect(url_for("proxy.settings"))
    # Allowlist: hostname chars, IPv4 dots, IPv6 colons/brackets — no whitespace or control chars
    if host and not _re.fullmatch(r"[A-Za-z0-9.\-_:\[\]]{1,253}", host):
        flash("Host syslog inválido. Use un hostname o dirección IP válida.", "danger")
        return redirect(url_for("proxy.settings"))
    if protocol not in ("udp", "tcp"):
        protocol = "udp"
    _VALID_FACILITIES = {
        "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
        "kern", "user", "mail", "daemon", "auth", "syslog",
    }
    if facility not in _VALID_FACILITIES:
        facility = "local7"
    if not port.isdigit() or not (1 <= int(port) <= 65535):
        flash("Puerto syslog inválido.", "danger")
        return redirect(url_for("proxy.settings"))

    # Filtrar fuentes válidas (solo modsecurity y audit en el reenviador DB-based)
    _VALID_SOURCES = {"modsecurity", "audit"}
    filtered_sources = ",".join(s for s in sources.split(",") if s in _VALID_SOURCES)

    AppConfig.set("syslog_enabled",  enabled)
    AppConfig.set("syslog_host",     host)
    AppConfig.set("syslog_port",     port)
    AppConfig.set("syslog_protocol", protocol)
    AppConfig.set("syslog_facility", facility)
    AppConfig.set("syslog_sources",  filtered_sources or "modsecurity,audit")

    from app.audit.helpers import log_audit
    log_audit(
        "settings.syslog_save",
        resource_type="config",
        resource_name="syslog",
        severity="info" if enabled == "0" else "warning",
        detail=__import__("json").dumps({
            "enabled":  enabled,
            "host":     host,
            "port":     port,
            "protocol": protocol,
            "facility": facility,
            "sources":  filtered_sources,
        }),
    )

    flash("Configuración de syslog guardada. El reenviador aplicará los cambios en el próximo tick.", "success")
    return redirect(url_for("proxy.settings"))


@bp.post("/settings/syslog-test")
@roles_required(ROLE_ADMIN)
@limiter.limit("10 per minute")
def settings_syslog_test():
    import ipaddress
    import re as _re
    import socket
    import time

    data     = request.get_json(silent=True) or {}
    host     = data.get("host", "").strip()
    port_str = str(data.get("port", "514"))
    protocol = data.get("protocol", "udp")

    if not host:
        return jsonify({"ok": False, "error": "Host requerido"})

    # Same allowlist as the save route: hostname/IPv4/IPv6 chars only
    if not _re.fullmatch(r"[A-Za-z0-9.\-_:\[\]]{1,253}", host):
        return jsonify({"ok": False, "error": "Host inválido"})

    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "Puerto inválido"})

    # Resolve and block loopback / cloud-metadata targets
    try:
        resolved = socket.getaddrinfo(host, port)
        for *_, sockaddr in resolved:
            ip_str = sockaddr[0]
            addr = ipaddress.ip_address(ip_str)
            if addr.is_loopback or addr.is_link_local:
                return jsonify({"ok": False, "error": "Host no permitido"})
    except (socket.gaierror, ValueError):
        return jsonify({"ok": False, "error": f"No se pudo resolver el host: {host}"})

    try:
        from app.proxy.syslog_forwarder import SyslogSender
        sender = SyslogSender(host, port, protocol)
        ms = sender.send_test()
        sender.close()
        return jsonify({"ok": True, "latency_ms": ms})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)})


def _verify_challenge(token: str, choice: int) -> bool:
    """Verify a server-issued HMAC-signed challenge token against the submitted choice."""
    try:
        secret = current_app.config.get("SECRET_KEY", "")
        b64, sig = token.rsplit(".", 1)
        expected = _hmac_mod.new(secret.encode(), b64.encode(), hashlib.sha256).hexdigest()[:32]
        if not _hmac_mod.compare_digest(expected, sig):
            return False
        b64c = b64.rstrip("=")
        padded = b64c + "=" * ((-len(b64c)) % 4)
        data = _json.loads(base64.urlsafe_b64decode(padded))
        return int(data["a"]) == choice
    except Exception:
        return False


@bp.post("/bot-verify")
@csrf.exempt  # CSRF protection is provided by the HMAC-signed challenge token
@limiter.limit("10 per minute")
def bot_verify():
    """Verify bot-challenge answer and set HttpOnly cookie on success.

    This endpoint is proxied from the protected site's nginx via:
        location = /_wn_challenge/verify { proxy_pass ...; }
    """
    token     = request.form.get("token", "")
    choice_s  = request.form.get("choice", "")
    ret       = request.form.get("ret", "/")

    # Validate returnTo — must be a relative path (prevent open redirect)
    if not ret.startswith("/") or ret.startswith("//"):
        ret = "/"

    try:
        choice = int(choice_s)
    except (ValueError, TypeError):
        abort(400)

    if not _verify_challenge(token, choice):
        # Wrong answer: redirect back to challenge with error flag
        safe_ret = _url_quote(ret, safe="/")
        return redirect(f"/_wn_challenge/?ret={safe_ret}&error=1")

    resp = redirect(ret)
    is_https = request.headers.get("X-Forwarded-Proto", "http") == "https"
    resp.set_cookie(
        "wn_bot",
        "ward_cleared_v1",
        max_age=3600,
        path="/",
        httponly=True,
        secure=is_https,
        samesite="Lax",
    )
    return resp


def _apply_nginx() -> None:
    """Regenera configs nginx y recarga nginx. Falla silenciosamente si nginx no está disponible (dev sin Docker)."""
    try:
        render_nginx_configs()
        reload_nginx()
    except Exception:
        pass


# ── Syslog forwarder helpers ──────────────────────────────────────────────────

def _syslog_forwarder_status() -> bool:
    """Devuelve True si el reenviador syslog está habilitado y activo.

    'Activo' significa: enabled=1, host configurado, y el último envío
    fue exitoso (syslog_last_error vacío y syslog_last_sent_at presente).
    """
    from app.models import AppConfig
    if AppConfig.get("syslog_enabled") != "1":
        return False
    if not (AppConfig.get("syslog_host") or "").strip():
        return False
    # Si hay un error reciente el forwarder está configurado pero con fallos
    last_error = (AppConfig.get("syslog_last_error") or "").strip()
    last_sent  = (AppConfig.get("syslog_last_sent_at") or "").strip()
    return bool(last_sent) and not last_error


def _bounded_int(field_name: str, minimum: int, maximum: int) -> int | None:
    try:
        value = int(request.form[field_name])
    except (KeyError, TypeError, ValueError):
        flash(f"Valor invalido para {field_name}.", "danger")
        return None
    if value < minimum or value > maximum:
        flash(f"{field_name} debe estar entre {minimum} y {maximum}.", "danger")
        return None
    return value


# ── Raw ModSecurity log viewer ────────────────────────────────────────────────


def _logs_search_filter(q, frase: str):
    """Filtra ModSecRawLog por frase en raw_json (ILIKE, escapando metacaracteres).

    Cubre IP, rule_id y mensaje porque todos viven en el JSON crudo.
    No usa índice — aceptable con retención 30 días + LIMIT.
    """
    esc = frase.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return q.filter(ModSecRawLog.raw_json.ilike(f"%{esc}%", escape="\\"))


@bp.get("/logs")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER)
def logs_list():
    q_param = request.args.get("q", "").strip()
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1

    query = ModSecRawLog.query.order_by(ModSecRawLog.created_at.desc())
    if q_param:
        query = _logs_search_filter(query, q_param)

    total = query.count()
    total_pages = max(1, ceil(total / _LOGS_PER_PAGE))
    page = min(page, total_pages)
    offset = (page - 1) * _LOGS_PER_PAGE
    rows = query.limit(_LOGS_PER_PAGE).offset(offset).all()

    config_data = {
        "retention_days": AppConfig.get("modsec_rawlog_retention_days") or "30",
        "backup_before_prune": AppConfig.get("modsec_rawlog_backup_before_prune") or "0",
        "zip_password_set": bool(AppConfig.get("modsec_rawlog_zip_password")),
    }

    ctx = dict(rows=rows, page=page, total_pages=total_pages, total=total, q=q_param)

    if request.headers.get("HX-Request"):
        return render_template("proxy/_logs_results.html", **ctx)

    return render_template(
        "proxy/logs.html",
        **ctx,
        archives=list_log_archives(),
        config_data=config_data,
    )


@bp.post("/logs/config")
@roles_required(ROLE_ADMIN)
def logs_config_save():
    from app.encryption import EncryptionNotConfigured, encrypt_secret

    # retention_days — debe ser entero > 0
    raw_days = request.form.get("retention_days", "").strip()
    try:
        days = int(raw_days)
        if days <= 0:
            raise ValueError
    except (ValueError, TypeError):
        flash("La retención debe ser un entero mayor que 0.", "danger")
        return redirect(url_for("proxy.logs_list"))

    # zip_password — calcular máscara y verificar disponibilidad de cifrado
    # ANTES de tocar la DB (P8: fail-fast si WARDNODE_SECRET_KEY no está configurada)
    raw_pwd = request.form.get("zip_password", "")
    current_enc = AppConfig.get("modsec_rawlog_zip_password")
    current_masked = ""
    if current_enc:
        try:
            from app.encryption import decrypt_secret
            current_plain = decrypt_secret(current_enc) or ""
            current_masked = "*" * max(8, len(current_plain))
        except Exception:
            current_masked = ""

    zip_password_changed = bool(raw_pwd and raw_pwd != current_masked)
    if zip_password_changed and not current_app.config.get("WARDNODE_SECRET_KEY"):
        flash("WARDNODE_SECRET_KEY no configurada; no se pueden guardar secretos.", "danger")
        return redirect(url_for("proxy.logs_list"))

    AppConfig.set("modsec_rawlog_retention_days", str(days))

    # backup_before_prune — checkbox
    backup_flag = "1" if request.form.get("backup_before_prune") else "0"
    AppConfig.set("modsec_rawlog_backup_before_prune", backup_flag)

    if zip_password_changed:
        try:
            AppConfig.set("modsec_rawlog_zip_password", encrypt_secret(raw_pwd), encrypted=True)
        except EncryptionNotConfigured:
            flash("WARDNODE_SECRET_KEY no configurada; no se pueden guardar secretos.", "danger")
            return redirect(url_for("proxy.logs_list"))

    db.session.commit()
    log_audit(
        "rawlog.config_update",
        resource_type="rawlog_config",
        status="success",
    )

    if request.headers.get("HX-Request"):
        flash("Configuración de logs guardada.", "success")
        from flask import make_response
        resp = make_response(redirect(url_for("proxy.logs_list")))
        resp.headers["HX-Trigger"] = "rawlog-config-saved"
        return resp

    flash("Configuración de logs guardada.", "success")
    return redirect(url_for("proxy.logs_list"))


@bp.get("/logs/archives/download/<name>")
@roles_required(ROLE_ADMIN)
@limiter.limit("10 per minute")
def archive_download(name):
    try:
        path = resolve_log_archive_path(name)
    except ValueError:
        flash("Nombre de archive inválido.", "danger")
        return redirect(url_for("proxy.logs_list"))
    except FileNotFoundError:
        from flask import abort as _abort
        _abort(404)

    log_audit(
        "rawlog.archive_download",
        resource_type="rawlog_archive",
        resource_name=name,
    )
    return send_file(path, as_attachment=True, download_name=name, mimetype="application/zip")


@bp.post("/logs/prune-now")
@roles_required(ROLE_ADMIN)
@limiter.limit("5 per hour")
def rawlog_prune_now():
    result = prune_and_archive(datetime.now(timezone.utc))

    if result["skipped_reason"]:
        flash(
            f"La poda fue omitida: {result['skipped_reason']}. "
            "Revisa la configuración de password del archive.",
            "warning",
        )
    else:
        flash(
            f"Poda completada: {result['deleted_rows']} fila(s) eliminada(s).",
            "success",
        )

    log_audit(
        "rawlog.prune_now",
        resource_type="rawlog",
        status="success" if not result["skipped_reason"] else "failure",
        detail={
            "deleted_rows": result["deleted_rows"],
            "archived_rows": result["archived_rows"],
            "archive_file": result["archive_file"],
            "skipped_reason": result["skipped_reason"],
        },
    )

    return redirect(url_for("proxy.logs_list"))
