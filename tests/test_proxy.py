from app.models import (
    AppConfig,
    AttackEvent,
    AuditLog,
    CustomModSecurityRule,
    NginxExtraConfig,
    ROLE_ADMIN,
    ROLE_OPERATOR,
    ROLE_READER,
    RuleCategory,
    SecurityHeader,
    Site,
    WafRuleExclusion,
)
from app.proxy.services import (
    clear_waf_events,
    ensure_site_traffic_policy,
    is_host_docker_internal,
    is_local_upstream,
    parse_upstream_host_port,
    render_nginx_configs,
    sync_site_rule_settings,
)


def test_create_site_and_render_nginx_config(app, tmp_path):
    app.config["PROXY_CONFIG_DIR"] = str(tmp_path)

    with app.app_context():
        category = RuleCategory(
            key="sqli",
            name="SQL injection",
            description="SQLi",
            crs_tag="attack-sqli",
        )
        site = Site(
            name="Demo",
            domain="demo.local",
            upstream_url="http://demo:8080",
            waf_enabled=True,
        )
        from app.extensions import db

        db.session.add_all([category, site])
        db.session.commit()
        sync_site_rule_settings(site)
        policy = ensure_site_traffic_policy(site)
        policy.requests_per_second = 7
        policy.burst = 14
        policy.max_connections = 3
        extra = NginxExtraConfig(
            site=site,
            enabled=True,
            server_snippet="client_max_body_size 20m;",
            location_snippet="proxy_buffering off;",
        )
        custom_rule = CustomModSecurityRule(
            site=site,
            name="Block bad bot",
            rule_text='SecRule REQUEST_HEADERS:User-Agent "@contains badbot" "id:1000001,phase:1,deny,status:403,msg:\"Bad bot\""',
            enabled=True,
        )
        db.session.add(custom_rule)
        db.session.add(extra)
        site.rule_settings[0].enabled = False
        db.session.commit()

        rendered = render_nginx_configs()

    zones = (tmp_path / "00-zones.conf").read_text(encoding="utf-8")
    content = next(tmp_path.glob("site-*.conf")).read_text(encoding="utf-8")
    assert "limit_req_zone $binary_remote_addr zone=req_site_" in zones
    assert "rate=7r/s" in zones
    assert "limit_conn_zone $binary_remote_addr zone=conn_site_" in zones
    assert "server_name demo.local" in content
    assert "client_max_body_size 20m;" in content
    assert 'add_header X-Content-Type-Options "nosniff" always;' in content
    assert 'add_header X-Frame-Options "DENY" always;' in content
    assert "proxy_pass http://demo:8080" in content
    assert "limit_req zone=req_site_" in content
    assert "burst=14 nodelay" in content
    assert "limit_conn conn_site_" in content
    assert " 3;" in content
    assert "proxy_buffering off;" in content
    assert "id:1000001" in content
    assert 'SecRuleRemoveByTag "attack-sqli"' in content


def test_obs_location_is_rendered_before_catch_all_location(app, tmp_path):
    app.config["PROXY_CONFIG_DIR"] = str(tmp_path)

    with app.app_context():
        from app.extensions import db

        site = Site(
            name="Console",
            domain="wardnode.example",
            upstream_url="http://console:5000",
            waf_enabled=True,
            is_console=True,
        )
        db.session.add(site)
        db.session.commit()
        AppConfig.set("module_obs_enabled", "1")

        render_nginx_configs()

    content = next(tmp_path.glob("site-*.conf")).read_text(encoding="utf-8")
    assert "location /obs/" in content
    assert "auth_request /_wardnode_obs_auth;" in content
    assert "location = /_wardnode_obs_auth" in content
    assert "proxy_pass http://127.0.0.1:3000$request_uri;" in content
    assert "proxy_set_header X-WEBAUTH-USER $wn_user;" in content
    assert "proxy_hide_header X-Frame-Options;" in content
    assert 'add_header X-Frame-Options "SAMEORIGIN" always;' in content
    assert content.index("location /obs/") < content.index("\n    location / {\n")


def test_obs_location_is_not_rendered_for_non_console_site(app, tmp_path):
    app.config["PROXY_CONFIG_DIR"] = str(tmp_path)

    with app.app_context():
        from app.extensions import db

        site = Site(
            name="App",
            domain="app.example",
            upstream_url="http://app:8080",
            waf_enabled=True,
        )
        db.session.add(site)
        db.session.commit()
        AppConfig.set("module_obs_enabled", "1")

        render_nginx_configs()

    content = next(tmp_path.glob("site-*.conf")).read_text(encoding="utf-8")
    assert "location /obs/" not in content


def test_operator_can_update_site_traffic_policy(client, login_as):
    login_as(ROLE_OPERATOR)
    response = client.post(
        "/proxy/sites",
        data={
            "name": "Demo",
            "domain": "demo.local",
            "upstream_url": "http://demo:8080",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    response = client.post(
        "/proxy/sites/1/traffic-policy",
        data={
            "rate_limit_enabled": "on",
            "requests_per_second": "11",
            "burst": "22",
            "nodelay": "on",
            "conn_limit_enabled": "on",
            "max_connections": "8",
            "key_strategy": "forwarded_for",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "Politica de trafico actualizada" in response.get_data(as_text=True)


def test_site_detail_has_dynamic_crs_filter(client, login_as):
    login_as(ROLE_OPERATOR)
    client.post(
        "/proxy/sites",
        data={
            "name": "Demo",
            "domain": "demo.local",
            "upstream_url": "http://demo:8080",
        },
        follow_redirects=True,
    )

    response = client.get("/proxy/sites/1")
    body = response.get_data(as_text=True)

    assert "crs-rules-form" in body
    assert "crs-accordion-btn" in body
    assert "Activar todas" in body
    assert "Desactivar todas" in body


def test_operator_can_update_security_headers_by_line(client, login_as):
    login_as(ROLE_OPERATOR)
    response = client.post(
        "/proxy/sites",
        data={
            "name": "Demo",
            "domain": "demo.local",
            "upstream_url": "http://demo:8080",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    header = SecurityHeader.query.filter_by(name="X-Frame-Options").first()
    response = client.post(
        "/proxy/sites/1/security-headers",
        data={
            "header_ids": [str(header.id)],
            f"header_name_{header.id}": "X-Frame-Options",
            f"header_value_{header.id}": "SAMEORIGIN",
            "enabled_header_ids": [str(header.id)],
            "always_header_ids": [str(header.id)],
            "custom_header_name": ["X-Test-Header", "", ""],
            "custom_header_value": ["ok", "", ""],
            "custom_header_enabled": ["0"],
            "custom_header_always": ["0"],
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "Headers de seguridad actualizados" in response.get_data(as_text=True)
    assert SecurityHeader.query.filter_by(name="X-Frame-Options").first().value == "SAMEORIGIN"
    assert SecurityHeader.query.filter_by(name="X-Test-Header").first().value == "ok"


def test_security_header_always_requires_enabled(client, login_as):
    login_as(ROLE_OPERATOR)
    client.post(
        "/proxy/sites",
        data={
            "name": "Demo",
            "domain": "demo.local",
            "upstream_url": "http://demo:8080",
        },
        follow_redirects=True,
    )
    header = SecurityHeader.query.filter_by(name="X-Frame-Options").first()

    response = client.post(
        "/proxy/sites/1/security-headers",
        data={
            "header_ids": [str(header.id)],
            f"header_name_{header.id}": "X-Frame-Options",
            f"header_value_{header.id}": "DENY",
            "always_header_ids": [str(header.id)],
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    updated = SecurityHeader.query.get(header.id)
    assert updated.enabled is False
    assert updated.always is False


def test_invalid_security_header_is_not_saved(client, login_as):
    login_as(ROLE_OPERATOR)
    client.post(
        "/proxy/sites",
        data={
            "name": "Demo",
            "domain": "demo.local",
            "upstream_url": "http://demo:8080",
        },
        follow_redirects=True,
    )
    header = SecurityHeader.query.filter_by(name="X-Frame-Options").first()

    response = client.post(
        "/proxy/sites/1/security-headers",
        data={
            "header_ids": [str(header.id)],
            f"header_name_{header.id}": "Bad Header",
            f"header_value_{header.id}": "SAMEORIGIN",
            "enabled_header_ids": [str(header.id)],
            "always_header_ids": [str(header.id)],
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "Header invalido" in response.get_data(as_text=True)
    assert SecurityHeader.query.get(header.id).name == "X-Frame-Options"


def test_operator_can_update_nginx_extra_config(client, login_as):
    login_as(ROLE_OPERATOR)
    client.post(
        "/proxy/sites",
        data={
            "name": "Demo",
            "domain": "demo.local",
            "upstream_url": "http://demo:8080",
        },
        follow_redirects=True,
    )

    response = client.post(
        "/proxy/sites/1/nginx-extra",
        data={
            "enabled": "on",
            "server_snippet": "client_max_body_size 20m;",
            "location_snippet": "proxy_buffering off;",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "Configuracion extra de Nginx actualizada" in response.get_data(as_text=True)
    config = NginxExtraConfig.query.filter_by(site_id=1).first()
    assert config.enabled is True
    assert config.server_snippet == "client_max_body_size 20m;"
    assert config.location_snippet == "proxy_buffering off;"


def test_invalid_nginx_extra_config_is_not_saved(client, login_as):
    login_as(ROLE_OPERATOR)
    client.post(
        "/proxy/sites",
        data={
            "name": "Demo",
            "domain": "demo.local",
            "upstream_url": "http://demo:8080",
        },
        follow_redirects=True,
    )

    response = client.post(
        "/proxy/sites/1/nginx-extra",
        data={
            "enabled": "on",
            "server_snippet": "client_max_body_size 20m",
            "location_snippet": "",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "debe terminar con punto y coma" in response.get_data(as_text=True)
    config = NginxExtraConfig.query.filter_by(site_id=1).first()
    assert config.enabled is False
    assert config.server_snippet == ""


def test_operator_can_create_custom_modsecurity_rule(client, login_as):
    login_as(ROLE_OPERATOR)
    client.post(
        "/proxy/sites",
        data={
            "name": "Demo",
            "domain": "demo.local",
            "upstream_url": "http://demo:8080",
        },
        follow_redirects=True,
    )

    response = client.post(
        "/proxy/sites/1/custom-rules",
        data={
            "new_rule_enabled": "on",
            "new_rule_name": "Block bad bot",
            "new_rule_text": 'SecRule REQUEST_HEADERS:User-Agent "@contains badbot" "id:1000001,phase:1,deny,status:403,msg:\\"Bad bot\\""',
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "Reglas personalizadas actualizadas" in response.get_data(as_text=True)
    assert CustomModSecurityRule.query.filter_by(name="Block bad bot").first() is not None


def test_invalid_custom_modsecurity_rule_is_not_saved(client, login_as):
    login_as(ROLE_OPERATOR)
    client.post(
        "/proxy/sites",
        data={
            "name": "Demo",
            "domain": "demo.local",
            "upstream_url": "http://demo:8080",
        },
        follow_redirects=True,
    )

    response = client.post(
        "/proxy/sites/1/custom-rules",
        data={
            "new_rule_enabled": "on",
            "new_rule_name": "Bad rule",
            "new_rule_text": 'SecRule ARGS "@contains test" "id:42,phase:2,deny"',
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "reserva 1000000-1999999" in response.get_data(as_text=True)
    assert CustomModSecurityRule.query.filter_by(name="Bad rule").first() is None


# ── Ingest pipeline ───────────────────────────────────────────────────────────

_SAMPLE_LOG_LINE = """{
  "transaction": {
    "time": "2024-01-01T00:00:00Z",
    "id": "abc123xyz",
    "request": {
      "method": "GET",
      "http_version": 1.1,
      "uri": "/search?q=test",
      "headers": {"Host": "example.com"},
      "remote_address": "1.2.3.4"
    },
    "response": {"http_code": 403, "headers": {}},
    "messages": [
      {
        "message": "SQL injection attempt detected",
        "details": {
          "ruleId": "942100",
          "severity": "CRITICAL",
          "tags": ["OWASP_CRS/WEB_ATTACK/SQL_INJECTION"]
        }
      }
    ]
  }
}"""


def test_ingest_parses_modsecurity_json_correctly():
    from app.proxy.ingest import _parse_line

    result = _parse_line(_SAMPLE_LOG_LINE)

    assert result is not None
    assert result["transaction_id"] == "abc123xyz"
    assert result["domain"] == "example.com"
    assert result["source_ip"] == "1.2.3.4"
    assert result["method"] == "GET"
    assert result["path"] == "/search?q=test"
    assert result["status_code"] == 403
    assert result["action"] == "block"
    assert result["rule_id"] == "942100"
    assert result["severity"] == "critical"
    assert result["category"] == "sql-injection"
    assert "SQL injection" in result["message"]


_SAMPLE_LOG_LINE_CRS4 = """{
  "transaction": {
    "time": "2024-01-01T00:00:00Z",
    "id": "crs4xyz456",
    "client_ip": "5.6.7.8",
    "request": {
      "method": "GET",
      "http_version": 1.1,
      "uri": "/search?q=test",
      "headers": {"Host": "example.com"}
    },
    "response": {"http_code": 403, "headers": {}},
    "messages": [
      {
        "message": "SQL Injection Attack Detected via libinjection",
        "details": {
          "ruleId": "942100",
          "severity": "CRITICAL",
          "tags": ["attack-sqli", "OWASP_CRS", "paranoia-level/1", "capec/1000/152/248/66"]
        }
      }
    ]
  }
}"""


def test_ingest_parses_crs4_tags_correctly():
    from app.proxy.ingest import _parse_line

    result = _parse_line(_SAMPLE_LOG_LINE_CRS4)

    assert result is not None
    assert result["category"] == "sql-injection"
    assert result["source_ip"] == "5.6.7.8"
    assert result["transaction_id"] == "crs4xyz456"


def test_ingest_handles_malformed_json():
    from app.proxy.ingest import _parse_line

    assert _parse_line("not json at all {{{") is None
    assert _parse_line('{"transaction": {}}') is None
    assert _parse_line("") is None
    assert _parse_line('{"transaction": {"messages": []}}') is None


# libmodsecurity v3 con SecAuditLogFormat JSON emite severity como nivel syslog
# numérico en string ("0".."7"), no como texto. Este test cubre el formato real
# que produce el proxy en producción.
_SAMPLE_LOG_LINE_V3_NUMERIC = """{
  "transaction": {
    "time": "2024-01-01T00:00:00Z",
    "id": "v3numeric789",
    "request": {
      "method": "POST",
      "http_version": 1.1,
      "uri": "/login",
      "headers": {"Host": "example.com"},
      "remote_address": "9.10.11.12"
    },
    "response": {"http_code": 403, "headers": {}},
    "messages": [
      {
        "message": "XSS Attack Detected",
        "details": {
          "ruleId": "941100",
          "severity": "2",
          "tags": ["OWASP_CRS/WEB_ATTACK/XSS"]
        }
      }
    ]
  }
}"""


def test_ingest_parses_v3_numeric_severity():
    """libmodsecurity v3 emite severity como número syslog ("0".."7").
    El map debe reconocerlo: "2" (CRITICAL) → "critical".
    """
    from app.proxy.ingest import _parse_line

    result = _parse_line(_SAMPLE_LOG_LINE_V3_NUMERIC)

    assert result is not None
    assert result["severity"] == "critical"   # syslog 2 = CRITICAL
    assert result["category"] == "xss"
    assert result["transaction_id"] == "v3numeric789"


def test_ingest_v3_numeric_all_severity_levels():
    """Verifica que todos los niveles syslog numéricos mapeen correctamente."""
    from app.proxy.ingest import _SEVERITY_MAP

    assert _SEVERITY_MAP["0"] == "critical"  # EMERGENCY
    assert _SEVERITY_MAP["1"] == "critical"  # ALERT
    assert _SEVERITY_MAP["2"] == "critical"  # CRITICAL
    assert _SEVERITY_MAP["3"] == "high"      # ERROR
    assert _SEVERITY_MAP["4"] == "medium"    # WARNING
    assert _SEVERITY_MAP["5"] == "low"       # NOTICE
    assert _SEVERITY_MAP["6"] == "low"       # INFO
    assert _SEVERITY_MAP["7"] == "low"       # DEBUG


# ── Categorización robusta (multi-mensaje + fallback por ID de regla) ──────────

# messages[0] es el bloqueo por anomaly score (949110, solo tags meta); el tag de
# ataque real (attack-sqli) viene en un mensaje posterior. La categoría debe salir
# del mensaje real, no "unknown".
_SAMPLE_LOG_ANOMALY_FIRST = """{
  "transaction": {
    "id": "anomalyfirst1",
    "request": {"method": "GET", "uri": "/x", "headers": {"Host": "example.com"}, "remote_address": "1.1.1.1"},
    "response": {"http_code": 403, "headers": {}},
    "messages": [
      {"message": "Inbound Anomaly Score Exceeded", "details": {"ruleId": "949110", "severity": "2", "tags": ["OWASP_CRS", "anomaly-evaluation"]}},
      {"message": "SQL Injection Attack Detected", "details": {"ruleId": "942100", "severity": "2", "tags": ["attack-sqli", "paranoia-level/1"]}}
    ]
  }
}"""


def test_ingest_categorizes_from_later_message():
    from app.proxy.ingest import _parse_line

    result = _parse_line(_SAMPLE_LOG_ANOMALY_FIRST)
    assert result is not None
    assert result["category"] == "sql-injection"
    # rule_id/message siguen siendo los del primer mensaje (representativo)
    assert result["rule_id"] == "949110"


def test_ingest_crs4_real_tag_names():
    """Tags reales de CRS 4.x que antes caían en 'unknown'."""
    from app.proxy.ingest import _parse_line

    def _line(tag, rid):
        return (
            '{"transaction": {"id": "t-%s", "request": {"method": "GET", "uri": "/x",'
            ' "headers": {"Host": "example.com"}, "remote_address": "2.2.2.2"},'
            ' "response": {"http_code": 403, "headers": {}},'
            ' "messages": [{"message": "x", "details": {"ruleId": "%s", "severity": "2",'
            ' "tags": ["%s", "OWASP_CRS"]}}]}}' % (rid, rid, tag)
        )

    assert _parse_line(_line("attack-injection-php", "933100"))["category"] == "php-injection"
    assert _parse_line(_line("attack-injection-java", "944100"))["category"] == "java-injection"
    assert _parse_line(_line("attack-reputation-scanner", "913100"))["category"] == "scanner"
    assert _parse_line(_line("attack-fixation", "943100"))["category"] == "session-fixation"


def test_ingest_category_fallback_by_rule_id():
    """Sin tag reconocido, la categoría se deriva del prefijo del ID de regla CRS."""
    from app.proxy.ingest import _parse_line

    line = (
        '{"transaction": {"id": "ridfallback1", "request": {"method": "GET", "uri": "/x",'
        ' "headers": {"Host": "example.com"}, "remote_address": "3.3.3.3"},'
        ' "response": {"http_code": 403, "headers": {}},'
        ' "messages": [{"message": "x", "details": {"ruleId": "941100", "severity": "2",'
        ' "tags": ["OWASP_CRS", "paranoia-level/1"]}}]}}'
    )
    assert _parse_line(line)["category"] == "xss"


def test_ingest_category_residual_unknown():
    """Anomaly score puro (949) sin regla específica ni tag → 'unknown' residual."""
    from app.proxy.ingest import _parse_line

    line = (
        '{"transaction": {"id": "residual1", "request": {"method": "GET", "uri": "/x",'
        ' "headers": {"Host": "example.com"}, "remote_address": "4.4.4.4"},'
        ' "response": {"http_code": 403, "headers": {}},'
        ' "messages": [{"message": "x", "details": {"ruleId": "949110", "severity": "2",'
        ' "tags": ["OWASP_CRS", "anomaly-evaluation"]}}]}}'
    )
    assert _parse_line(line)["category"] == "unknown"


def test_ingest_resolves_site_by_domain(app, monkeypatch):
    from app.proxy.ingest import _process_line
    from app.extensions import db
    from app.models import AttackEvent

    monkeypatch.setattr("app.proxy.geoip.get_country_code", lambda ip: "US")

    with app.app_context():
        site = Site(name="Test", domain="example.com", upstream_url="http://upstream:8080")
        db.session.add(site)
        db.session.commit()
        site_id = site.id

    _process_line(app, _SAMPLE_LOG_LINE)

    with app.app_context():
        event = AttackEvent.query.filter_by(transaction_id="abc123xyz").first()
        assert event is not None
        assert event.site_id == site_id
        assert event.country_code == "US"


def test_ingest_skips_duplicate_transaction_ids(app, monkeypatch):
    from app.proxy.ingest import _process_line
    from app.models import AttackEvent

    monkeypatch.setattr("app.proxy.geoip.get_country_code", lambda ip: None)

    _process_line(app, _SAMPLE_LOG_LINE)
    _process_line(app, _SAMPLE_LOG_LINE)

    with app.app_context():
        count = AttackEvent.query.filter_by(transaction_id="abc123xyz").count()
        assert count == 1


# ---------------------------------------------------------------------------
# parse_upstream_host_port / is_local_upstream helpers
# ---------------------------------------------------------------------------

def test_parse_upstream_host_port_explicit():
    host, port = parse_upstream_host_port("http://host.docker.internal:8081")
    assert host == "host.docker.internal"
    assert port == 8081


def test_parse_upstream_host_port_https_default():
    host, port = parse_upstream_host_port("https://host.docker.internal")
    assert host == "host.docker.internal"
    assert port == 443


def test_parse_upstream_host_port_http_default():
    host, port = parse_upstream_host_port("http://host.docker.internal")
    assert host == "host.docker.internal"
    assert port == 80


def test_parse_upstream_host_port_non_hdi():
    host, port = parse_upstream_host_port("http://app:8080")
    assert host == "app"
    assert port == 8080


def test_parse_upstream_host_port_ip():
    host, port = parse_upstream_host_port("http://192.168.1.1:8081")
    assert host == "192.168.1.1"
    assert port == 8081


# is_local_upstream reconoce host.docker.internal, 127.0.0.1 y localhost
def test_is_local_upstream_hdi():
    assert is_local_upstream("http://host.docker.internal:3000") is True


def test_is_local_upstream_loopback():
    assert is_local_upstream("http://127.0.0.1:3000") is True


def test_is_local_upstream_localhost():
    assert is_local_upstream("http://localhost:8080") is True


def test_is_local_upstream_false_container():
    assert is_local_upstream("http://myapp:8080") is False


def test_is_local_upstream_false_external_ip():
    assert is_local_upstream("http://10.0.0.1:8080") is False


# is_host_docker_internal es alias de compatibilidad — sigue funcionando
def test_is_host_docker_internal_true():
    assert is_host_docker_internal("http://host.docker.internal:3000") is True


def test_is_host_docker_internal_false_container():
    assert is_host_docker_internal("http://myapp:8080") is False


def test_is_host_docker_internal_loopback_now_true():
    """Tras la migración, 127.0.0.1 se reconoce como upstream local."""
    assert is_host_docker_internal("http://127.0.0.1:3000") is True


# ---------------------------------------------------------------------------
# create_site gating: upstream local sin módulo WF activo
# ---------------------------------------------------------------------------

def test_create_site_local_blocked_without_wf_hdi(client, login_as):
    """host.docker.internal sin WF activo → rechazado."""
    login_as(ROLE_OPERATOR)
    response = client.post(
        "/proxy/sites",
        data={
            "name": "HostApp",
            "domain": "hostapp.local",
            "upstream_url": "http://host.docker.internal:8081",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "WardNode WF" in body

    with client.application.app_context():
        assert Site.query.filter_by(domain="hostapp.local").first() is None


def test_create_site_local_blocked_without_wf_loopback(client, login_as):
    """127.0.0.1 sin WF activo → rechazado (nueva validación)."""
    login_as(ROLE_OPERATOR)
    response = client.post(
        "/proxy/sites",
        data={
            "name": "LoopApp",
            "domain": "loopapp.local",
            "upstream_url": "http://127.0.0.1:8081",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "WardNode WF" in body

    with client.application.app_context():
        assert Site.query.filter_by(domain="loopapp.local").first() is None


def test_create_site_docker_container_allowed_without_wf(client, login_as):
    login_as(ROLE_OPERATOR)
    response = client.post(
        "/proxy/sites",
        data={
            "name": "ContainerApp",
            "domain": "containerapp.local",
            "upstream_url": "http://myapp:8080",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    with client.application.app_context():
        assert Site.query.filter_by(domain="containerapp.local").first() is not None


def test_create_site_local_reserved_port_blocked_hdi(client, login_as):
    """Puerto reservado en host.docker.internal → rechazado."""
    login_as(ROLE_OPERATOR)
    with client.application.app_context():
        AppConfig.set("module_wf_enabled", "1")

    response = client.post(
        "/proxy/sites",
        data={
            "name": "BadPort",
            "domain": "badport.local",
            "upstream_url": "http://host.docker.internal:80",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "reservado" in body

    with client.application.app_context():
        assert Site.query.filter_by(domain="badport.local").first() is None


def test_create_site_local_reserved_port_blocked_loopback(client, login_as):
    """Puerto reservado en 127.0.0.1 → rechazado (nueva validación)."""
    login_as(ROLE_OPERATOR)
    with client.application.app_context():
        AppConfig.set("module_wf_enabled", "1")

    response = client.post(
        "/proxy/sites",
        data={
            "name": "BadPortLoop",
            "domain": "badportloop.local",
            "upstream_url": "http://127.0.0.1:5000",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "reservado" in body

    with client.application.app_context():
        assert Site.query.filter_by(domain="badportloop.local").first() is None


def test_create_site_local_calls_send_command_verified(client, login_as, monkeypatch):
    """Upstream 127.0.0.1: llama protect_host_port; con blocked=True → host_port_blocked=True."""
    login_as(ROLE_OPERATOR)
    with client.application.app_context():
        AppConfig.set("module_wf_enabled", "1")

    captured = {}

    def fake_send(action, **kwargs):
        captured["action"] = action
        captured["kwargs"] = kwargs
        return {"ok": True, "blocked": True, "output": "ok"}

    monkeypatch.setattr("app.proxy.routes.os.path.exists", lambda p: True)
    monkeypatch.setattr("app.modules.socket_client.send_command", fake_send)

    response = client.post(
        "/proxy/sites",
        data={
            "name": "LoopApp2",
            "domain": "loopapp2.local",
            "upstream_url": "http://127.0.0.1:8082",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert captured.get("action") == "protect_host_port"
    assert captured["kwargs"].get("port") == 8082

    body = response.get_data(as_text=True)
    assert "verificado" in body

    with client.application.app_context():
        site = Site.query.filter_by(domain="loopapp2.local").first()
        assert site is not None
        assert site.host_port_blocked is True


def test_create_site_local_calls_send_command_unverified(client, login_as, monkeypatch):
    """protect_host_port ok pero blocked=False → advertencia 'no pudo verificarse'."""
    login_as(ROLE_OPERATOR)
    with client.application.app_context():
        AppConfig.set("module_wf_enabled", "1")

    def fake_send(action, **kwargs):
        return {"ok": True, "blocked": False, "output": "reglas insertadas sin verificación"}

    monkeypatch.setattr("app.proxy.routes.os.path.exists", lambda p: True)
    monkeypatch.setattr("app.modules.socket_client.send_command", fake_send)

    response = client.post(
        "/proxy/sites",
        data={
            "name": "LoopApp3",
            "domain": "loopapp3.local",
            "upstream_url": "http://127.0.0.1:8083",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "verificarse" in body or "WardNode WF" in body

    with client.application.app_context():
        site = Site.query.filter_by(domain="loopapp3.local").first()
        assert site is not None
        assert site.host_port_blocked is False


# Mantener alias para compatibilidad — verifica que hdi sigue llamando send_command
def test_create_site_hdi_calls_send_command(client, login_as, monkeypatch):
    login_as(ROLE_OPERATOR)
    with client.application.app_context():
        AppConfig.set("module_wf_enabled", "1")

    captured = {}

    def fake_send(action, **kwargs):
        captured["action"] = action
        captured["kwargs"] = kwargs
        return {"ok": True, "blocked": True, "output": "ok"}

    monkeypatch.setattr("app.proxy.routes.os.path.exists", lambda p: True)
    monkeypatch.setattr("app.modules.socket_client.send_command", fake_send)

    response = client.post(
        "/proxy/sites",
        data={
            "name": "HostApp",
            "domain": "hostapp2.local",
            "upstream_url": "http://host.docker.internal:8082",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert captured.get("action") == "protect_host_port"
    assert captured["kwargs"].get("port") == 8082

    with client.application.app_context():
        site = Site.query.filter_by(domain="hostapp2.local").first()
        assert site is not None
        assert site.host_port_blocked is True


# ---------------------------------------------------------------------------
# Guard create_site: requiere dominio de consola configurado
# ---------------------------------------------------------------------------

def test_create_site_blocked_without_console_domain(client, login_as):
    from app.models import AppConfig, Site
    login_as(ROLE_OPERATOR)
    with client.application.app_context():
        AppConfig.set("console_site_id", None)

    response = client.post(
        "/proxy/sites",
        data={"name": "Test", "domain": "test.local", "upstream_url": "http://app:8080"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "dominio" in body or "consola" in body or "Ajustes" in body

    with client.application.app_context():
        assert Site.query.filter_by(domain="test.local").first() is None


def test_default_server_conf_is_generated(app, tmp_path):
    """render_nginx_configs genera 01-default-server.conf con default_server y modsecurity."""
    app.config["PROXY_CONFIG_DIR"] = str(tmp_path)

    with app.app_context():
        render_nginx_configs()

    content = (tmp_path / "01-default-server.conf").read_text(encoding="utf-8")
    assert "listen 80 default_server" in content
    assert "server_name _" in content
    assert "modsecurity on" in content
    assert "SecRuleEngine On" in content
    assert "return 444" in content
    assert "access_log" in content


def test_dismiss_setup_prompt_sets_flag(client, login_as):
    from app.models import AppConfig
    login_as("admin")
    with client.application.app_context():
        AppConfig.set("setup_prompt_shown", None)

    response = client.post("/proxy/dismiss-setup-prompt")
    assert response.status_code == 200
    assert response.get_json()["ok"] is True

    with client.application.app_context():
        assert AppConfig.get("setup_prompt_shown") == "1"


# ---------------------------------------------------------------------------
# update_site_upstream — edición del upstream desde site_detail
# ---------------------------------------------------------------------------

def test_update_site_upstream_normal(client, login_as):
    """Un operator puede cambiar el upstream; el nuevo valor queda persistido."""
    login_as(ROLE_OPERATOR)

    with client.application.app_context():
        from app.extensions import db
        site = Site(name="EditUpstream", domain="edit2.local", upstream_url="http://app:8080")
        db.session.add(site)
        db.session.commit()
        AppConfig.set("console_site_id", "9999")
        site_id = site.id

    response = client.post(
        f"/proxy/sites/{site_id}/upstream",
        data={"upstream_url": "http://app:9090"},
        follow_redirects=True,
    )
    assert response.status_code == 200

    with client.application.app_context():
        updated = Site.query.get(site_id)
        assert updated.upstream_url == "http://app:9090"


def test_update_site_upstream_renders_nginx_config(app, tmp_path):
    """Tras actualizar el upstream el config nginx generado usa el nuevo proxy_pass."""
    from app.extensions import db
    from app.proxy.services import (
        ensure_site_nginx_extra_config,
        ensure_site_security_headers,
    )

    app.config["PROXY_CONFIG_DIR"] = str(tmp_path)

    with app.app_context():
        site = Site(name="EditNginx", domain="editnginx.local", upstream_url="http://app:8080")
        db.session.add(site)
        db.session.commit()
        sync_site_rule_settings(site)
        ensure_site_traffic_policy(site)
        ensure_site_security_headers(site)
        ensure_site_nginx_extra_config(site)
        AppConfig.set("console_site_id", "9999")

        # Simular el cambio que haría la ruta
        site.upstream_url = "http://app:9090"
        db.session.commit()
        render_nginx_configs()

    conf = next(tmp_path.glob("site-*.conf")).read_text(encoding="utf-8")
    assert "proxy_pass http://app:9090" in conf
    assert "proxy_pass http://app:8080" not in conf


def test_update_site_upstream_console_rejected(client, login_as):
    """El upstream del sitio consola no puede modificarse desde esta ruta."""
    login_as(ROLE_OPERATOR)

    with client.application.app_context():
        from app.extensions import db
        site = Site(
            name="Console",
            domain="console.local",
            upstream_url="http://console:5000",
            is_console=True,
        )
        db.session.add(site)
        db.session.commit()
        AppConfig.set("console_site_id", str(site.id))
        site_id = site.id

    response = client.post(
        f"/proxy/sites/{site_id}/upstream",
        data={"upstream_url": "http://console:9999"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "consola" in body.lower() or "Ajustes" in body

    with client.application.app_context():
        unchanged = Site.query.get(site_id)
        assert unchanged.upstream_url == "http://console:5000"


def test_update_site_upstream_reader_rejected(client, login_as):
    """Un reader recibe 403 al intentar editar el upstream."""
    from app.models import ROLE_READER
    login_as(ROLE_READER)

    with client.application.app_context():
        from app.extensions import db
        site = Site(name="ReadOnly", domain="readonly.local", upstream_url="http://app:8080")
        db.session.add(site)
        db.session.commit()
        AppConfig.set("console_site_id", "9999")
        site_id = site.id

    response = client.post(
        f"/proxy/sites/{site_id}/upstream",
        data={"upstream_url": "http://app:9000"},
        follow_redirects=False,
    )
    assert response.status_code == 403


def test_update_site_upstream_hdi_reserved_port_rejected(client, login_as):
    """Un puerto reservado en host.docker.internal es rechazado."""
    login_as(ROLE_OPERATOR)

    with client.application.app_context():
        from app.extensions import db
        AppConfig.set("module_wf_enabled", "1")
        site = Site(name="HDIApp", domain="hdi.local", upstream_url="http://app:8080")
        db.session.add(site)
        db.session.commit()
        AppConfig.set("console_site_id", "9999")
        site_id = site.id

    response = client.post(
        f"/proxy/sites/{site_id}/upstream",
        data={"upstream_url": "http://host.docker.internal:443"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "reservado" in body

    with client.application.app_context():
        unchanged = Site.query.get(site_id)
        assert unchanged.upstream_url == "http://app:8080"


def test_update_site_upstream_loopback_reserved_port_rejected(client, login_as):
    """Un puerto reservado en 127.0.0.1 también es rechazado (nueva validación)."""
    login_as(ROLE_OPERATOR)

    with client.application.app_context():
        from app.extensions import db
        AppConfig.set("module_wf_enabled", "1")
        site = Site(name="LoopRes", domain="loopres.local", upstream_url="http://app:8080")
        db.session.add(site)
        db.session.commit()
        AppConfig.set("console_site_id", "9999")
        site_id = site.id

    response = client.post(
        f"/proxy/sites/{site_id}/upstream",
        data={"upstream_url": "http://127.0.0.1:5000"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "reservado" in body

    with client.application.app_context():
        unchanged = Site.query.get(site_id)
        assert unchanged.upstream_url == "http://app:8080"


def test_update_site_upstream_no_change(client, login_as):
    """Si el upstream es idéntico al actual, no se produce ningún cambio."""
    login_as(ROLE_OPERATOR)

    with client.application.app_context():
        from app.extensions import db
        site = Site(name="NoChange", domain="nochange.local", upstream_url="http://app:8080")
        db.session.add(site)
        db.session.commit()
        AppConfig.set("console_site_id", "9999")
        site_id = site.id

    response = client.post(
        f"/proxy/sites/{site_id}/upstream",
        data={"upstream_url": "http://app:8080"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "cambió" in body or "cambio" in body


# ---------------------------------------------------------------------------
# events_list — filtros por dominio, IP y rango de fechas
# ---------------------------------------------------------------------------

def _seed_attack_events(app):
    """Siembra tres AttackEvents con dominios, IPs y fechas distintas."""
    from app.extensions import db
    from app.models import AttackEvent
    from datetime import datetime, timezone

    events = [
        AttackEvent(
            domain="alpha.local",
            source_ip="10.0.0.1",
            method="GET",
            path="/admin",
            status_code=403,
            action="block",
            severity="high",
            message="SQLi attempt",
            created_at=datetime(2026, 1, 10, 12, 0, 0, tzinfo=timezone.utc),
        ),
        AttackEvent(
            domain="beta.local",
            source_ip="203.0.113.55",
            method="POST",
            path="/login",
            status_code=403,
            action="detect",
            severity="medium",
            message="XSS attempt",
            created_at=datetime(2026, 2, 15, 8, 0, 0, tzinfo=timezone.utc),
        ),
        AttackEvent(
            domain="alpha.local",
            source_ip="10.0.0.2",
            method="GET",
            path="/etc/passwd",
            status_code=403,
            action="block",
            severity="critical",
            message="Path traversal",
            created_at=datetime(2026, 3, 20, 18, 0, 0, tzinfo=timezone.utc),
        ),
    ]
    with app.app_context():
        for ev in events:
            db.session.add(ev)
        db.session.commit()


def test_events_filter_by_domain(client, login_as, app):
    """Filtrar por dominio devuelve solo eventos de ese dominio."""
    login_as(ROLE_ADMIN)
    _seed_attack_events(app)

    resp = client.get("/proxy/events?domain=alpha.local")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # IPs de alpha.local deben aparecer en la tabla
    assert "10.0.0.1" in body or "10.0.0.2" in body
    # La IP exclusiva de beta.local NO debe aparecer en la tabla (no es placeholder ni dropdown)
    assert "203.0.113.55" not in body


def test_events_filter_by_ip_partial(client, login_as, app):
    """Filtrar por IP parcial devuelve coincidencias de prefijo de subred."""
    login_as(ROLE_ADMIN)
    _seed_attack_events(app)

    # "10.0.0" debe coincidir con 10.0.0.1 y 10.0.0.2 pero no con 203.0.113.55
    resp = client.get("/proxy/events?ip=10.0.0")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # La IP filtrada aparece en la tabla
    assert "10.0.0.1" in body or "10.0.0.2" in body
    # La IP completa del evento excluido no debe aparecer en tabla
    # (nota: el placeholder del campo IP puede contener "203.0.113"; usamos la IP completa)
    assert "203.0.113.55" not in body


def test_events_filter_by_date_range(client, login_as, app):
    """Filtrar por rango de fechas acota los resultados incluyendo el día completo de date_to."""
    login_as(ROLE_ADMIN)
    _seed_attack_events(app)

    # Solo el evento del 2026-02-15 debería quedar dentro de [2026-02-01, 2026-02-28]
    resp = client.get("/proxy/events?date_from=2026-02-01&date_to=2026-02-28")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # La IP exclusiva de beta.local (el evento de Feb) debe estar en la tabla
    assert "203.0.113.55" in body
    # Las IPs exclusivas de alpha.local (Jan y Mar) NO deben aparecer en la tabla
    assert "10.0.0.1" not in body
    assert "10.0.0.2" not in body


def test_events_filter_invalid_date_ignored(client, login_as, app):
    """Una fecha inválida se ignora sin provocar error 500."""
    login_as(ROLE_ADMIN)
    _seed_attack_events(app)

    resp = client.get("/proxy/events?date_from=not-a-date&date_to=also-bad")
    assert resp.status_code == 200


def test_events_filter_combined_domain_and_severity(client, login_as, app):
    """Dominio + severidad se intersecan correctamente."""
    login_as(ROLE_ADMIN)
    _seed_attack_events(app)

    # alpha.local tiene un evento high y uno critical; filtrar por high debe devolver solo ese
    resp = client.get("/proxy/events?domain=alpha.local&severity=high")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "alpha.local" in body
    # El evento critical de alpha.local no debe aparecer
    assert "critical" not in body.lower().split("sev-badge")[-1][:50]


def test_events_filter_domains_list_in_context(client, login_as, app):
    """El desplegable de dominios incluye los dominios distintos con eventos."""
    login_as(ROLE_ADMIN)
    _seed_attack_events(app)

    resp = client.get("/proxy/events")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "alpha.local" in body
    assert "beta.local" in body


# ── Tests de export CSV ──────────────────────────────────────────────────────

def _seed_rich_attack_events(app):
    """Siembra AttackEvents con paths que activan múltiples indicadores de ataque."""
    from app.extensions import db
    from app.models import AttackEvent
    from datetime import datetime, timezone

    events = [
        AttackEvent(
            domain="attack.local",
            source_ip="203.0.113.10",
            country_code="US",
            method="GET",
            path="/index.php?id=1%27+OR+1=1--",
            status_code=403,
            action="block",
            severity="high",
            category="sql-injection",
            rule_id="942100",
            message="SQL Injection Attack Detected via libinjection",
            created_at=datetime(2026, 5, 7, 14, 30, 0, tzinfo=timezone.utc),
        ),
        AttackEvent(
            domain="attack.local",
            source_ip="198.51.100.7",
            country_code="DE",
            method="GET",
            path="/../../etc/passwd",
            status_code=403,
            action="block",
            severity="critical",
            category="lfi",
            rule_id="930100",
            message="Path Traversal Attack",
            created_at=datetime(2026, 5, 8, 22, 0, 0, tzinfo=timezone.utc),
        ),
        AttackEvent(
            domain="other.local",
            source_ip="10.0.0.5",
            country_code=None,
            method="POST",
            path="/search?q=<script>alert(1)</script>",
            status_code=200,
            action="detect",
            severity="medium",
            category="xss",
            rule_id="941100",
            message="XSS Attack Detected via libinjection",
            created_at=datetime(2026, 5, 9, 9, 15, 0, tzinfo=timezone.utc),
        ),
    ]
    with app.app_context():
        for ev in events:
            db.session.add(ev)
        db.session.commit()


def test_events_export_csv_returns_csv(client, login_as, app):
    """El endpoint devuelve un CSV válido con las columnas de feature engineering."""
    login_as(ROLE_ADMIN)
    _seed_rich_attack_events(app)

    resp = client.get("/proxy/events/export.csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.content_type
    cd = resp.headers.get("Content-Disposition", "")
    assert "attachment" in cd
    assert "wardnode_waf_events_" in cd
    assert ".csv" in cd

    body = resp.get_data(as_text=True)
    lines = [l for l in body.splitlines() if l.strip()]
    # Cabecera + al menos 3 filas de datos
    assert len(lines) >= 4

    header = lines[0]
    # Columnas clave de feature engineering presentes en la cabecera
    for col in (
        "event_id", "timestamp_utc", "domain", "source_ip", "country_code",
        "path_shannon_entropy", "has_sql_keyword", "has_xss_pattern",
        "has_path_traversal", "has_lfi_pattern", "has_null_byte",
        "ip_version", "ip_is_private", "pct_encoded_count",
        "has_file_extension", "file_extension", "label_source",
    ):
        assert col in header, f"Columna '{col}' ausente en la cabecera del CSV"

    # Verificar que al menos una fila contiene datos de los eventos sembrados
    assert "attack.local" in body
    assert "sql-injection" in body
    assert "crs" in body  # label_source siempre es "crs"


def test_events_export_feature_flags(app):
    """build_attack_event_features activa los flags correctos según el URI del ataque."""
    from app.proxy.services import build_attack_event_features, ATTACK_EVENT_CSV_COLUMNS
    from app.models import AttackEvent
    from datetime import datetime, timezone

    with app.app_context():
        # SQLi + path traversal en la misma URL
        ev = AttackEvent(
            domain="test.local",
            source_ip="1.2.3.4",
            method="GET",
            path="/../admin?id=1 UNION SELECT 1--",
            status_code=403,
            action="block",
            severity="critical",
            category="sql-injection",
            rule_id="942100",
            message="SQLi detected",
            created_at=datetime(2026, 6, 9, 10, 0, 0, tzinfo=timezone.utc),
        )
        ev.id = 999
        ev.transaction_id = "txn-test"

        features = build_attack_event_features(ev)

        assert features["has_sql_keyword"] == 1
        assert features["has_path_traversal"] == 1
        assert features["has_xss_pattern"] == 0
        assert features["label_source"] == "crs"
        assert features["domain"] == "test.local"
        assert features["hour"] == 10
        assert features["day_of_week"] == 1           # 2026-06-09 es martes
        assert features["is_weekend"] == 0
        assert features["is_business_hours"] == 1     # 10h laborable
        # path_depth > 0 (hay barras)
        assert features["path_depth"] > 0
        # Todas las columnas del schema deben estar presentes
        for col in ATTACK_EVENT_CSV_COLUMNS:
            assert col in features, f"Feature '{col}' ausente en el dict"

    # XSS
    with app.app_context():
        ev_xss = AttackEvent(
            domain="test.local",
            source_ip="5.6.7.8",
            method="GET",
            path="/search?q=<script>alert(1)</script>",
            status_code=200,
            action="detect",
            severity="medium",
            category="xss",
            rule_id="941100",
            message="XSS",
            created_at=datetime(2026, 6, 7, 20, 0, 0, tzinfo=timezone.utc),
        )
        ev_xss.id = 998
        ev_xss.transaction_id = "txn-xss"
        feats_xss = build_attack_event_features(ev_xss)
        assert feats_xss["has_xss_pattern"] == 1
        assert feats_xss["is_weekend"] == 1           # domingo
        assert feats_xss["is_business_hours"] == 0    # 20h + fin de semana

    # LFI + null byte
    with app.app_context():
        ev_lfi = AttackEvent(
            domain="test.local",
            source_ip="9.8.7.6",
            method="GET",
            path="/etc/passwd%00.jpg",
            status_code=403,
            action="block",
            severity="critical",
            category="lfi",
            rule_id="930100",
            message="LFI",
            created_at=datetime(2026, 6, 9, 3, 0, 0, tzinfo=timezone.utc),
        )
        ev_lfi.id = 997
        ev_lfi.transaction_id = "txn-lfi"
        feats_lfi = build_attack_event_features(ev_lfi)
        assert feats_lfi["has_lfi_pattern"] == 1
        assert feats_lfi["has_null_byte"] == 1
        assert feats_lfi["has_file_extension"] == 1
        assert feats_lfi["file_extension"] == "jpg"
        assert feats_lfi["is_business_hours"] == 0    # 3h madrugada

    # IP privada vs. pública
    with app.app_context():
        ev_priv = AttackEvent(
            domain="test.local",
            source_ip="192.168.1.100",
            method="GET",
            path="/admin",
            status_code=403,
            action="block",
            severity="medium",
            category="unknown",
            message="test",
            created_at=datetime(2026, 6, 9, 12, 0, 0, tzinfo=timezone.utc),
        )
        ev_priv.id = 996
        ev_priv.transaction_id = None
        feats_priv = build_attack_event_features(ev_priv)
        assert feats_priv["ip_version"] == 4
        assert feats_priv["ip_is_private"] == 1

    with app.app_context():
        ev_pub = AttackEvent(
            domain="test.local",
            source_ip="8.8.8.8",
            method="GET",
            path="/admin",
            status_code=403,
            action="block",
            severity="medium",
            category="unknown",
            message="test",
            created_at=datetime(2026, 6, 9, 12, 0, 0, tzinfo=timezone.utc),
        )
        ev_pub.id = 995
        ev_pub.transaction_id = None
        feats_pub = build_attack_event_features(ev_pub)
        assert feats_pub["ip_is_private"] == 0


def test_events_export_respects_filters(client, login_as, app):
    """El CSV solo contiene eventos que coinciden con los filtros activos."""
    login_as(ROLE_ADMIN)
    _seed_rich_attack_events(app)

    # Filtrar por dominio=attack.local — other.local no debe aparecer
    resp = client.get("/proxy/events/export.csv?domain=attack.local")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "attack.local" in body
    assert "other.local" not in body

    # Filtrar por severidad=critical — solo el path traversal (LFI)
    resp2 = client.get("/proxy/events/export.csv?severity=critical")
    assert resp2.status_code == 200
    body2 = resp2.get_data(as_text=True)
    # El evento LFI (rule_id=930100) debe estar
    assert "930100" in body2
    # El evento XSS (rule_id=941100, severity=medium) NO debe estar
    assert "941100" not in body2


def test_events_export_scope_all(client, login_as, app):
    """scope=all exporta todos los eventos sin importar filtros adicionales."""
    login_as(ROLE_ADMIN)
    _seed_rich_attack_events(app)

    # Con scope=all + domain=attack.local — ambos dominios deben aparecer
    resp = client.get("/proxy/events/export.csv?scope=all&domain=attack.local")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "attack.local" in body
    assert "other.local" in body


def test_events_export_operator_allowed(client, login_as, app):
    """Un usuario con rol ROLE_OPERATOR puede acceder al endpoint de export."""
    from app.models import ROLE_OPERATOR
    login_as(ROLE_OPERATOR)
    _seed_rich_attack_events(app)

    resp = client.get("/proxy/events/export.csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.content_type


def test_events_export_empty_returns_header_only(client, login_as, app):
    """Cuando no hay eventos el CSV devuelve solo la fila de cabecera."""
    login_as(ROLE_ADMIN)
    # No sembramos eventos — BD vacía para AttackEvent

    resp = client.get("/proxy/events/export.csv")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    lines = [l for l in body.splitlines() if l.strip()]
    assert len(lines) == 1   # solo cabecera
    assert "event_id" in lines[0]
    assert "label_source" in lines[0]


# ── Limpieza de eventos WAF ────────────────────────────────────────────────────

def _seed_waf_events(n=5):
    """Inserta n AttackEvent sintéticos con transaction_id único (para tests de limpieza)."""
    from app.extensions import db
    for i in range(n):
        db.session.add(AttackEvent(
            domain="test.example.com",
            source_ip=f"10.0.0.{i + 1}",
            method="GET",
            path="/",
            status_code=403,
            action="block",
            rule_id="942100",
            severity="high",
            message="sql injection test",
            category="sql-injection",
            transaction_id=f"clear-test-txn-{i}",
        ))
    db.session.commit()


def test_clear_waf_events_helper_returns_count(app):
    """clear_waf_events() retorna el número de filas borradas."""
    with app.app_context():
        _seed_waf_events(4)
        n = clear_waf_events()
        assert n == 4
        assert AttackEvent.query.count() == 0


def test_clear_waf_events_helper_idempotent(app):
    """clear_waf_events() en tabla vacía retorna 0 sin error."""
    with app.app_context():
        assert AttackEvent.query.count() == 0
        n = clear_waf_events()
        assert n == 0


def test_settings_clear_waf_events_admin(client, login_as, app):
    """Admin puede limpiar los eventos WAF via POST /proxy/settings/clear-waf-events."""
    login_as(ROLE_ADMIN)
    with app.app_context():
        _seed_waf_events(3)
        assert AttackEvent.query.count() == 3

    resp = client.post("/proxy/settings/clear-waf-events", follow_redirects=True)
    assert resp.status_code == 200
    assert "reiniciado" in resp.get_data(as_text=True).lower()

    with app.app_context():
        assert AttackEvent.query.count() == 0


def test_settings_clear_waf_events_audit_logged(client, login_as, app):
    """La limpieza queda registrada en el audit log."""
    login_as(ROLE_ADMIN)
    with app.app_context():
        _seed_waf_events(2)

    client.post("/proxy/settings/clear-waf-events", follow_redirects=True)

    with app.app_context():
        entry = AuditLog.query.filter_by(action="settings.clear_waf_events").first()
        assert entry is not None
        assert entry.severity == "warning"


def test_settings_clear_waf_events_reader_rejected(client, login_as):
    """Un lector (ROLE_READER) no puede acceder a la ruta de limpieza."""
    login_as(ROLE_READER)
    resp = client.post("/proxy/settings/clear-waf-events", follow_redirects=True)
    # Redirige a login o devuelve 403 — en cualquier caso no ejecuta el borrado
    assert resp.status_code in (200, 403)
    # La respuesta no debe contener el flash de éxito
    assert "reiniciado" not in resp.get_data(as_text=True).lower()


def test_save_console_site_first_setup_clears_events(client, login_as, app):
    """Al crear el console_site por primera vez NO se borran los eventos;
    en su lugar se activa la oferta de reseteo (waf_reset_offer_pending=1)
    para que el operador decida de forma explícita."""
    login_as(ROLE_ADMIN)
    with app.app_context():
        # Asegurarse de que no existe console_site previo
        AppConfig.set("console_site_id", "")
        AppConfig.set("waf_reset_offer_pending", "0")
        _seed_waf_events(6)
        assert AttackEvent.query.count() == 6

    resp = client.post(
        "/proxy/settings/console-site",
        data={"console_domain": "console.test.local", "console_port": "5000"},
        follow_redirects=True,
    )
    assert resp.status_code == 200

    with app.app_context():
        # Los eventos NO deben borrarse — el operador decide luego.
        assert AttackEvent.query.count() == 6, (
            "El primer setup ya NO debe borrar eventos automáticamente"
        )
        # La bandera de oferta debe estar activa.
        assert AppConfig.get("waf_reset_offer_pending") == "1", (
            "Debe activarse waf_reset_offer_pending para mostrar el banner al operador"
        )


def test_save_console_site_edit_does_not_clear_events(client, login_as, app):
    """Editar el dominio de la consola (no primera vez) NO borra los eventos."""
    login_as(ROLE_ADMIN)
    with app.app_context():
        from app.extensions import db
        # Crear un Site de consola preexistente
        existing = Site(
            name="WardNode Console",
            domain="old.test.local",
            upstream_url="http://console:5000",
            is_console=True,
        )
        db.session.add(existing)
        db.session.commit()
        AppConfig.set("console_site_id", str(existing.id))
        _seed_waf_events(4)
        assert AttackEvent.query.count() == 4

    resp = client.post(
        "/proxy/settings/console-site",
        data={"console_domain": "new.test.local", "console_port": "5000"},
        follow_redirects=True,
    )
    assert resp.status_code == 200

    with app.app_context():
        # Los eventos deben mantenerse — no fue primera configuración
        assert AttackEvent.query.count() == 4, (
            "Editar el dominio de consola no debe borrar eventos existentes"
        )


# ── Excepciones WAF por ID de regla CRS ───────────────────────────────────────


def _create_site_for_exclusion(db, domain="exclusion.local"):
    """Helper: crea un Site mínimo para tests de exclusión WAF."""
    site = Site(
        name="Exclusion Test",
        domain=domain,
        upstream_url="http://backend:8080",
        waf_enabled=True,
    )
    db.session.add(site)
    db.session.commit()
    return site


def test_waf_exclusion_renders_in_nginx_config(app, tmp_path):
    """SecRuleRemoveById aparece en el .conf del sitio cuando hay una exclusión activa."""
    app.config["PROXY_CONFIG_DIR"] = str(tmp_path)

    with app.app_context():
        from app.extensions import db

        site = _create_site_for_exclusion(db)
        ex = WafRuleExclusion(site=site, rule_id=942100, comment="falso positivo", enabled=True)
        db.session.add(ex)
        db.session.commit()

        render_nginx_configs()

    content = next(tmp_path.glob("site-*.conf")).read_text(encoding="utf-8")
    assert "SecRuleRemoveById 942100" in content


def test_waf_exclusion_disabled_not_rendered(app, tmp_path):
    """Una exclusión deshabilitada no aparece en el .conf."""
    app.config["PROXY_CONFIG_DIR"] = str(tmp_path)

    with app.app_context():
        from app.extensions import db

        site = _create_site_for_exclusion(db)
        ex = WafRuleExclusion(site=site, rule_id=942100, comment="inactiva", enabled=False)
        db.session.add(ex)
        db.session.commit()

        render_nginx_configs()

    content = next(tmp_path.glob("site-*.conf")).read_text(encoding="utf-8")
    assert "SecRuleRemoveById 942100" not in content


def test_waf_exclusion_isolated_per_site(app, tmp_path):
    """La exclusión de un sitio NO aparece en el .conf de otro sitio."""
    app.config["PROXY_CONFIG_DIR"] = str(tmp_path)

    with app.app_context():
        from app.extensions import db

        site_a = _create_site_for_exclusion(db, domain="site-a.local")
        site_b = _create_site_for_exclusion(db, domain="site-b.local")
        ex = WafRuleExclusion(site=site_a, rule_id=942100, comment="solo A", enabled=True)
        db.session.add(ex)
        db.session.commit()

        render_nginx_configs()

    confs = sorted(tmp_path.glob("site-*.conf"))
    assert len(confs) == 2
    conf_a = next(c for c in confs if "site-a" in c.name).read_text(encoding="utf-8")
    conf_b = next(c for c in confs if "site-b" in c.name).read_text(encoding="utf-8")
    assert "SecRuleRemoveById 942100" in conf_a
    assert "SecRuleRemoveById 942100" not in conf_b


def test_waf_exclusion_add_via_http(client, login_as, app, tmp_path):
    """Un operador puede añadir una exclusión WAF por ID vía POST."""
    app.config["PROXY_CONFIG_DIR"] = str(tmp_path)
    login_as(ROLE_OPERATOR)

    # Crear sitio
    client.post(
        "/proxy/sites",
        data={"name": "Demo", "domain": "demo.local", "upstream_url": "http://demo:8080"},
        follow_redirects=True,
    )

    resp = client.post(
        "/proxy/sites/1/rule-exclusions",
        data={"new_exclusion_rule_id": "942100", "new_exclusion_comment": "FP en token"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert "Excepciones WAF actualizadas" in resp.get_data(as_text=True)

    with app.app_context():
        ex = WafRuleExclusion.query.filter_by(site_id=1, rule_id=942100).first()
        assert ex is not None
        assert ex.enabled is True
        assert ex.comment == "FP en token"


def test_waf_exclusion_add_critical_rule_rejected(client, login_as):
    """No se puede añadir una exclusión para una regla CRS crítica."""
    login_as(ROLE_OPERATOR)
    client.post(
        "/proxy/sites",
        data={"name": "Demo", "domain": "demo.local", "upstream_url": "http://demo:8080"},
        follow_redirects=True,
    )

    resp = client.post(
        "/proxy/sites/1/rule-exclusions",
        data={"new_exclusion_rule_id": "949110", "new_exclusion_comment": ""},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert "crítica" in resp.get_data(as_text=True)

    with client.application.app_context():
        assert WafRuleExclusion.query.count() == 0


def test_waf_exclusion_reader_cannot_add(client, login_as):
    """Un reader recibe 403 al intentar añadir una exclusión WAF."""
    login_as(ROLE_READER)
    resp = client.post(
        "/proxy/sites/1/rule-exclusions",
        data={"new_exclusion_rule_id": "942100"},
    )
    assert resp.status_code == 403


def test_waf_exclusion_remove_via_http(client, login_as, app, tmp_path):
    """Un operador puede eliminar una exclusión existente."""
    app.config["PROXY_CONFIG_DIR"] = str(tmp_path)
    login_as(ROLE_OPERATOR)

    client.post(
        "/proxy/sites",
        data={"name": "Demo", "domain": "demo.local", "upstream_url": "http://demo:8080"},
        follow_redirects=True,
    )
    # Añadir exclusión
    client.post(
        "/proxy/sites/1/rule-exclusions",
        data={"new_exclusion_rule_id": "942100", "new_exclusion_comment": ""},
        follow_redirects=True,
    )
    with app.app_context():
        ex = WafRuleExclusion.query.first()
        ex_id = ex.id

    # Eliminar exclusión
    resp = client.post(
        f"/proxy/sites/1/rule-exclusions/{ex_id}/remove",
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert "eliminada" in resp.get_data(as_text=True)

    with app.app_context():
        assert WafRuleExclusion.query.count() == 0


def test_waf_exclusion_duplicate_rejected(client, login_as, app, tmp_path):
    """Añadir la misma regla dos veces muestra aviso sin duplicar."""
    app.config["PROXY_CONFIG_DIR"] = str(tmp_path)
    login_as(ROLE_OPERATOR)

    client.post(
        "/proxy/sites",
        data={"name": "Demo", "domain": "demo.local", "upstream_url": "http://demo:8080"},
        follow_redirects=True,
    )
    for _ in range(2):
        client.post(
            "/proxy/sites/1/rule-exclusions",
            data={"new_exclusion_rule_id": "942100", "new_exclusion_comment": ""},
            follow_redirects=True,
        )

    with app.app_context():
        assert WafRuleExclusion.query.count() == 1


def test_security_headers_dedup_with_allowlist(app, tmp_path):
    """Las cabeceras de la allowlist generan proxy_hide_header; las custom no."""
    app.config["PROXY_CONFIG_DIR"] = str(tmp_path)

    with app.app_context():
        from app.extensions import db
        from app.models import SecurityHeader

        site = Site(
            name="Dedup",
            domain="dedup.local",
            upstream_url="http://dedup:9000",
            waf_enabled=True,
        )
        db.session.add(site)
        db.session.commit()

        # Cabecera custom fuera de la allowlist
        custom_h = SecurityHeader(
            site=site,
            name="X-Mi-Header-Custom",
            value="test",
            enabled=True,
            always=True,
            position=99,
            is_default=False,
        )
        db.session.add(custom_h)
        db.session.commit()

        render_nginx_configs()

    content = next(tmp_path.glob("site-*.conf")).read_text(encoding="utf-8")

    # Las cabeceras de la allowlist deben tener proxy_hide_header (dedup)
    assert "proxy_hide_header X-Frame-Options;" in content
    assert "proxy_hide_header X-Content-Type-Options;" in content
    assert "proxy_hide_header Referrer-Policy;" in content
    assert "proxy_hide_header Permissions-Policy;" in content

    # Las cabeceras custom (fuera de la allowlist) solo add_header, nunca proxy_hide_header
    assert 'add_header X-Mi-Header-Custom "test" always;' in content
    assert "proxy_hide_header X-Mi-Header-Custom;" not in content


def test_editing_default_header_marks_is_default_false(client, login_as):
    """Editar un header default desde la UI pone is_default=False (la UI manda)."""
    login_as(ROLE_OPERATOR)
    client.post(
        "/proxy/sites",
        data={"name": "Demo", "domain": "demo.local", "upstream_url": "http://demo:8080"},
        follow_redirects=True,
    )

    header = SecurityHeader.query.filter_by(name="X-Frame-Options").first()
    assert header.is_default is True  # valor semilla

    client.post(
        "/proxy/sites/1/security-headers",
        data={
            "header_ids": [str(header.id)],
            f"header_name_{header.id}": "X-Frame-Options",
            f"header_value_{header.id}": "SAMEORIGIN",
            "enabled_header_ids": [str(header.id)],
            "always_header_ids": [str(header.id)],
        },
        follow_redirects=True,
    )

    updated = SecurityHeader.query.get(header.id)
    assert updated.value == "SAMEORIGIN"
    assert updated.is_default is False  # la UI marcó como editado por operador


# ── Docs Settings / Events / Logs ────────────────────────────────────────────

def test_settings_docs_renders(client, login_as):
    login_as()
    r = client.get("/proxy/settings/docs")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Índice" in body
    for anchor in ("vision-general", "smtp", "syslog", "console-site", "secretos", "referencia"):
        assert f'id="{anchor}"' in body
        assert f'href="#{anchor}"' in body


def test_settings_docs_denied_operator(client, login_as):
    login_as(role=ROLE_OPERATOR)
    r = client.get("/proxy/settings/docs")
    assert r.status_code in (302, 403)


def test_events_docs_renders(client, login_as):
    login_as()
    r = client.get("/proxy/events/docs")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Índice" in body
    for anchor in ("vision-general", "deduplicacion", "severidades", "export", "referencia"):
        assert f'id="{anchor}"' in body
        assert f'href="#{anchor}"' in body


def test_events_docs_accessible_reader(client, login_as):
    login_as(role=ROLE_READER)
    assert client.get("/proxy/events/docs").status_code == 200


def test_events_docs_button(client, login_as):
    login_as()
    body = client.get("/proxy/events").get_data(as_text=True)
    assert "/proxy/events/docs" in body


def test_logs_docs_renders(client, login_as):
    login_as()
    r = client.get("/proxy/logs/docs")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Índice" in body
    for anchor in ("vision-general", "polling", "busqueda", "archivo", "diferencia", "referencia"):
        assert f'id="{anchor}"' in body
        assert f'href="#{anchor}"' in body


def test_logs_docs_accessible_reader(client, login_as):
    login_as(role=ROLE_READER)
    assert client.get("/proxy/logs/docs").status_code == 200
