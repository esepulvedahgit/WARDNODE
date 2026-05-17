from datetime import datetime, timedelta, timezone

from flask import current_app, flash, jsonify, redirect, render_template, request, url_for
from sqlalchemy import func

from app.auth.decorators import roles_required
from app.extensions import db, limiter
from app.models import (
    AttackEvent,
    CustomModSecurityRule,
    GeoBlocklistEntry,
    ROLE_ADMIN,
    ROLE_OPERATOR,
    ROLE_READER,
    RuleCategory,
    Site,
)
from app.proxy import bp
from flask_login import current_user

from app.proxy.services import (
    ensure_default_rule_categories,
    ensure_site_bot_protection,
    ensure_site_traffic_policy,
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
from app.proxy.custom_rules import validate_custom_rule
from app.proxy.geoip import get_country_code
from app.proxy.geoip_blocklist import write_blocklist_conf, reload_nginx, COUNTRY_NAMES


@bp.before_app_request
def bootstrap_proxy_catalog():
    if not current_app.extensions.get("proxy_catalog_bootstrapped"):
        ensure_default_rule_categories()
        current_app.extensions["proxy_catalog_bootstrapped"] = True


@bp.get("/")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER)
def dashboard():
    sites = Site.query.order_by(Site.domain).all()
    categories = RuleCategory.query.order_by(RuleCategory.name).all()

    since_24h = datetime.utcnow() - timedelta(hours=24)
    events_24h = AttackEvent.query.filter(AttackEvent.created_at >= since_24h).all()

    blocked_24h = sum(1 for e in events_24h if e.action == "block")
    unique_ips = db.session.query(func.count(func.distinct(AttackEvent.source_ip))).scalar() or 0
    waf_active = sum(1 for s in sites if s.waf_enabled)

    now = datetime.utcnow()
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

    top_countries = (
        db.session.query(AttackEvent.country_code, func.count().label("cnt"))
        .filter(AttackEvent.country_code.isnot(None))
        .group_by(AttackEvent.country_code)
        .order_by(func.count().desc())
        .limit(8)
        .all()
    )

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
        country_names=COUNTRY_NAMES,
    )


@bp.get("/events")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER)
def events_list():
    severity = request.args.get("severity", "")
    action = request.args.get("action", "")

    q = AttackEvent.query.order_by(AttackEvent.created_at.desc())
    if severity in {"critical", "high", "warning", "medium", "low"}:
        q = q.filter(AttackEvent.severity == severity)
    if action in {"block", "detect"}:
        q = q.filter(AttackEvent.action == action)
    events = q.limit(500).all()

    counts = {"all": AttackEvent.query.count()}
    for sev in ("critical", "high", "warning", "medium", "low"):
        counts[sev] = AttackEvent.query.filter(AttackEvent.severity == sev).count()
    counts["block"] = AttackEvent.query.filter(AttackEvent.action == "block").count()
    counts["detect"] = AttackEvent.query.filter(AttackEvent.action == "detect").count()

    return render_template(
        "proxy/events.html",
        events=events,
        severity=severity,
        action=action,
        counts=counts,
    )


@bp.get("/sites")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER)
def sites_list():
    sites = Site.query.order_by(Site.domain).all()
    blocklist = GeoBlocklistEntry.query.order_by(GeoBlocklistEntry.country_name).all()
    return render_template(
        "proxy/sites.html",
        sites=sites,
        blocklist=blocklist,
        country_names=COUNTRY_NAMES,
    )


@bp.post("/sites")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("20 per minute")
def create_site():
    site = Site(
        name=request.form["name"].strip(),
        domain=request.form["domain"].strip().lower(),
        upstream_url=request.form["upstream_url"].strip(),
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
    return render_template("proxy/site_detail.html", site=site)


@bp.get("/bot-challenge-preview")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER)
def bot_challenge_preview():
    from flask import Response
    from app.proxy.services import _build_challenge_html
    return Response(_build_challenge_html(), mimetype="text/html")


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


@bp.post("/sites/<int:site_id>/rules")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("30 per minute")
def update_site_rules(site_id):
    site = Site.query.get_or_404(site_id)
    enabled_ids = {int(value) for value in request.form.getlist("category_ids")}
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
        reload_nginx()
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
    enabled_ids = {int(value) for value in request.form.getlist("enabled_header_ids")}
    always_ids = {int(value) for value in request.form.getlist("always_header_ids")}
    header_ids = [int(value) for value in request.form.getlist("header_ids")]

    headers_by_id = {header.id: header for header in site.security_headers}
    for header_id in header_ids:
        header = headers_by_id.get(header_id)
        if header is None:
            errors.append("Header desconocido.")
            continue
        name = request.form.get(f"header_name_{header_id}", "").strip()
        value = request.form.get(f"header_value_{header_id}", "").strip()
        errors.extend(validate_security_header(name, value))
        updates.append((header, name, value, header_id in enabled_ids, header_id in always_ids))

    new_headers = []
    custom_names = request.form.getlist("custom_header_name")
    custom_values = request.form.getlist("custom_header_value")
    custom_enabled = set(request.form.getlist("custom_header_enabled"))
    custom_always = set(request.form.getlist("custom_header_always"))
    for index, (name, value) in enumerate(zip(custom_names, custom_values)):
        name = name.strip()
        value = value.strip()
        enabled = str(index) in custom_enabled
        always = str(index) in custom_always
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
    enabled_ids = {int(value) for value in request.form.getlist("enabled_rule_ids")}
    rule_ids = [int(value) for value in request.form.getlist("rule_ids")]
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
        return jsonify({"ok": True, "files": len(rendered_files)})
    return jsonify({"ok": False, "error": err or "No se pudo recargar nginx"}), 500


@bp.post("/events/demo")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("10 per minute")
def create_demo_event():
    site = Site.query.order_by(Site.id).first()
    demo_ip = "8.8.8.8"
    domain = site.domain if site else request.form.get("domain", "demo.local")
    country = get_country_code(demo_ip)

    block_event = AttackEvent(
        site=site,
        domain=domain,
        source_ip=demo_ip,
        country_code=country,
        method="GET",
        path="/search?q=' OR 1=1--",
        status_code=403,
        action="block",
        category="SQL injection",
        rule_id="942100",
        severity="critical",
        message="Demo: WAF bloqueó intento de SQL injection (request nunca llegó al upstream).",
    )
    detect_event = AttackEvent(
        site=site,
        domain=domain,
        source_ip=demo_ip,
        country_code=country,
        method="POST",
        path="/login",
        status_code=200,
        action="detect",
        category="brute-force",
        rule_id="913100",
        severity="warning",
        message="Demo: WAF detectó actividad sospechosa pero dejó pasar la solicitud.",
    )
    db.session.add_all([block_event, detect_event])
    db.session.commit()
    flash("2 eventos demo registrados (1 bloqueo + 1 detección).", "success")
    return redirect(url_for("proxy.dashboard"))


@bp.post("/sites/<int:site_id>/delete")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("10 per minute")
def delete_site(site_id):
    site = Site.query.get_or_404(site_id)
    if site.is_console:
        flash("El sitio de la consola no puede eliminarse desde aquí. Desvinculalo desde Ajustes.", "danger")
        return redirect(url_for("proxy.site_detail", site_id=site.id))
    name = site.name
    db.session.delete(site)
    db.session.commit()
    _apply_nginx()
    flash(f'Sitio "{name}" eliminado correctamente.', "success")
    return redirect(url_for("proxy.dashboard"))


@bp.post("/geo-blocklist/add")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("30 per minute")
def geo_blocklist_add():
    code = request.form.get("country_code", "").strip().upper()
    if not code or len(code) != 2:
        flash("Código de país inválido.", "danger")
        return redirect(url_for("proxy.sites_list"))
    name = COUNTRY_NAMES.get(code, code)
    existing = GeoBlocklistEntry.query.filter_by(country_code=code).first()
    if existing:
        existing.enabled = True
        flash(f"{name} ya estaba en la lista (reactivado).", "info")
    else:
        db.session.add(GeoBlocklistEntry(country_code=code, country_name=name))
        flash(f"{name} agregado a la lista de bloqueo.", "success")
    db.session.commit()
    write_blocklist_conf()
    ok, err = reload_nginx()
    if not ok:
        flash(f"Nginx no recargado: {err or 'socket no disponible en modo local'}", "warning")
    return redirect(url_for("proxy.sites_list"))


@bp.post("/geo-blocklist/<code>/remove")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("30 per minute")
def geo_blocklist_remove(code):
    entry = GeoBlocklistEntry.query.filter_by(country_code=code.upper()).first_or_404()
    name = entry.country_name
    db.session.delete(entry)
    db.session.commit()
    write_blocklist_conf()
    ok, err = reload_nginx()
    if not ok:
        flash(f"Nginx no recargado: {err or 'socket no disponible en modo local'}", "warning")
    flash(f"{name} eliminado de la lista de bloqueo.", "success")
    return redirect(url_for("proxy.sites_list"))


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
    )


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

    upstream = f"http://console:{port}"

    console_site_id = AppConfig.get("console_site_id")
    site = None
    if console_site_id and console_site_id.isdigit():
        site = db.session.get(Site, int(console_site_id))

    if site is None:
        site = Site.query.filter_by(is_console=True).first()

    if site is None:
        site = Site(name="WardNode Console", is_console=True)
        db.session.add(site)

    site.domain = domain
    site.upstream_url = upstream
    site.is_console = True
    db.session.commit()

    AppConfig.set("console_site_id", str(site.id))
    flash("Sitio de consola configurado. Ajusta TLS y WAF desde la configuración del sitio.", "success")
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


def _apply_nginx() -> None:
    """Regenera configs nginx y recarga nginx. Falla silenciosamente si nginx no está disponible (dev sin Docker)."""
    try:
        render_nginx_configs()
        reload_nginx()
    except Exception:
        pass


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
