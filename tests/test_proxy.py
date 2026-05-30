from app.models import (
    AppConfig,
    CustomModSecurityRule,
    NginxExtraConfig,
    ROLE_OPERATOR,
    RuleCategory,
    SecurityHeader,
    Site,
)
from app.proxy.services import (
    ensure_site_traffic_policy,
    is_host_docker_internal,
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
    assert "proxy_pass $grafana_upstream$request_uri;" in content
    assert "proxy_set_header X-WEBAUTH-USER admin;" in content
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
# parse_upstream_host_port / is_host_docker_internal helpers
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


def test_is_host_docker_internal_true():
    assert is_host_docker_internal("http://host.docker.internal:3000") is True


def test_is_host_docker_internal_false_container():
    assert is_host_docker_internal("http://myapp:8080") is False


def test_is_host_docker_internal_false_ip():
    assert is_host_docker_internal("http://10.0.0.1:8080") is False


# ---------------------------------------------------------------------------
# create_site gating: host.docker.internal sin módulo WF activo
# ---------------------------------------------------------------------------

def test_create_site_hdi_blocked_without_wf(client, login_as):
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


def test_create_site_hdi_reserved_port_blocked(client, login_as):
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


def test_create_site_hdi_calls_send_command(client, login_as, monkeypatch):
    login_as(ROLE_OPERATOR)
    with client.application.app_context():
        AppConfig.set("module_wf_enabled", "1")

    captured = {}

    def fake_send(action, **kwargs):
        captured["action"] = action
        captured["kwargs"] = kwargs
        return {"ok": True, "output": "ok"}

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
