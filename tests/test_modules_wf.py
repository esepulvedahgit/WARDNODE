from app.models import AppConfig, ROLE_OPERATOR, ROLE_READER


def _enable_wf():
    AppConfig.set("module_wf_enabled", "1")


def _fake_cmd_ok(action, **kwargs):
    return {"ok": True, "output": f"action={action}"}


# ── Status ────────────────────────────────────────────────────────────────────

def test_wf_status_returns_ok_when_agent_available(client, login_as, monkeypatch):
    login_as()
    _enable_wf()

    def fake_cmd(action, **kwargs):
        if action == "status":
            return {"ok": True, "output": "Status: active"}
        if action == "check_defaults":
            return {"ok": True, "output": "Default: deny (incoming)\nDefault: allow (outgoing)"}
        return {"ok": True, "output": ""}

    monkeypatch.setattr("app.modules.routes.send_command", fake_cmd)
    response = client.post("/modules/wf/status")

    assert response.status_code == 200
    data = response.get_json()
    assert data["ok"] is True
    assert data["initialized"] is True


def test_wf_status_requires_wf_enabled(client, login_as, monkeypatch):
    login_as()
    monkeypatch.setattr("app.modules.routes.send_command", _fake_cmd_ok)

    response = client.post("/modules/wf/status")

    assert response.status_code == 403
    assert response.get_json()["ok"] is False


# ── Allow port ────────────────────────────────────────────────────────────────

def test_wf_allow_port_valid(client, login_as, monkeypatch):
    login_as()
    _enable_wf()
    calls = []

    def fake_cmd(action, **kwargs):
        calls.append({"action": action, **kwargs})
        return {"ok": True, "output": "Rule added"}

    monkeypatch.setattr("app.modules.routes.send_command", fake_cmd)
    response = client.post("/modules/wf/allow", data={"type": "port", "port": "80", "proto": "tcp"})

    assert response.status_code == 200
    assert response.get_json()["ok"] is True
    assert calls[0]["action"] == "allow_port"
    assert calls[0]["port"] == "80"
    assert calls[0]["proto"] == "tcp"


def test_wf_allow_port_invalid_zero(client, login_as, monkeypatch):
    login_as()
    _enable_wf()
    monkeypatch.setattr("app.modules.routes.send_command", _fake_cmd_ok)

    response = client.post("/modules/wf/allow", data={"type": "port", "port": "0", "proto": "tcp"})

    assert response.status_code == 400
    assert response.get_json()["ok"] is False


def test_wf_allow_port_invalid_above_max(client, login_as, monkeypatch):
    login_as()
    _enable_wf()
    monkeypatch.setattr("app.modules.routes.send_command", _fake_cmd_ok)

    response = client.post("/modules/wf/allow", data={"type": "port", "port": "99999", "proto": "tcp"})

    assert response.status_code == 400
    assert response.get_json()["ok"] is False


# ── Deny IP ───────────────────────────────────────────────────────────────────

def test_wf_deny_ip_valid(client, login_as, monkeypatch):
    login_as()
    _enable_wf()
    calls = []

    def fake_cmd(action, **kwargs):
        calls.append({"action": action, **kwargs})
        return {"ok": True, "output": "Rule added"}

    monkeypatch.setattr("app.modules.routes.send_command", fake_cmd)
    response = client.post("/modules/wf/deny", data={"type": "ip", "ip": "192.168.1.1"})

    assert response.status_code == 200
    assert response.get_json()["ok"] is True
    assert calls[0]["action"] == "deny_ip"
    assert calls[0]["ip"] == "192.168.1.1"


def test_wf_deny_ip_invalid(client, login_as, monkeypatch):
    login_as()
    _enable_wf()
    monkeypatch.setattr("app.modules.routes.send_command", _fake_cmd_ok)

    response = client.post("/modules/wf/deny", data={"type": "ip", "ip": "not-an-ip"})

    assert response.status_code == 400
    assert response.get_json()["ok"] is False


# ── Delete rule ───────────────────────────────────────────────────────────────

def test_wf_delete_rule_valid(client, login_as, monkeypatch):
    login_as()
    _enable_wf()
    calls = []

    def fake_cmd(action, **kwargs):
        calls.append({"action": action, **kwargs})
        return {"ok": True, "output": "Rule deleted"}

    monkeypatch.setattr("app.modules.routes.send_command", fake_cmd)
    response = client.post("/modules/wf/delete", data={"rule_num": "3"})

    assert response.status_code == 200
    assert calls[0]["action"] == "delete_rule"
    assert calls[0]["rule_num"] == "3"


# ── Init ──────────────────────────────────────────────────────────────────────

def test_wf_init_calls_init_firewall(client, login_as, monkeypatch):
    login_as()
    _enable_wf()
    calls = []

    def fake_cmd(action, **kwargs):
        calls.append({"action": action, **kwargs})
        return {"ok": True, "output": "Firewall initialized"}

    monkeypatch.setattr("app.modules.routes.send_command", fake_cmd)
    response = client.post("/modules/wf/init", data={"ssh_port": "22"})

    assert response.status_code == 200
    assert calls[0]["action"] == "init_firewall"
    assert calls[0]["ssh_port"] == "22"


# ── RBAC ──────────────────────────────────────────────────────────────────────

def test_wf_operator_can_access_status(client, login_as, monkeypatch):
    """Operador tiene acceso completo a WF (sin restricción de rol)."""
    _enable_wf()
    login_as(role=ROLE_OPERATOR)
    monkeypatch.setattr("app.modules.routes.send_command", _fake_cmd_ok)

    response = client.post("/modules/wf/status")

    assert response.status_code == 200


def test_wf_reader_cannot_access_status(client, login_as, monkeypatch):
    """Reader no tiene acceso a WF."""
    _enable_wf()
    login_as(role=ROLE_READER)
    monkeypatch.setattr("app.modules.routes.send_command", _fake_cmd_ok)

    response = client.post("/modules/wf/status")

    assert response.status_code == 403


def test_wf_reader_cannot_access_docker_ports(client, login_as, monkeypatch):
    """Reader no puede enumerar puertos Docker del host vía WF."""
    _enable_wf()
    login_as(role=ROLE_READER)
    monkeypatch.setattr("app.modules.routes.send_command", _fake_cmd_ok)

    response = client.post("/modules/wf/docker-ports")

    assert response.status_code == 403


def test_wf_requires_module_enabled_for_allow(client, login_as, monkeypatch):
    login_as()
    monkeypatch.setattr("app.modules.routes.send_command", _fake_cmd_ok)

    response = client.post("/modules/wf/allow", data={"type": "port", "port": "80", "proto": "tcp"})

    assert response.status_code == 403
    assert response.get_json()["ok"] is False


# ---------------------------------------------------------------------------
# toggle() guard: WF no puede activarse sin dominio de consola configurado
# ---------------------------------------------------------------------------

def test_toggle_wf_blocked_without_console_domain(client, login_as):
    from app.models import AppConfig
    login_as("admin")
    AppConfig.set("module_wf_enabled", "0")
    AppConfig.set("console_site_id", None)

    response = client.post("/modules/wf/toggle", follow_redirects=True)
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Ajustes" in body or "dominio" in body or "consola" in body

    with client.application.app_context():
        assert AppConfig.get("module_wf_enabled") != "1"


def test_toggle_wf_allowed_with_console_domain(client, login_as, monkeypatch):
    from app.models import AppConfig, Site
    from app.extensions import db

    login_as("admin")

    with client.application.app_context():
        site = Site(name="Console", domain="ward.example", upstream_url="http://console:5000", is_console=True)
        db.session.add(site)
        db.session.commit()
        AppConfig.set("console_site_id", str(site.id))
        AppConfig.set("module_wf_enabled", "0")

    monkeypatch.setattr("app.modules.routes.os.path.exists", lambda p: False)

    response = client.post("/modules/wf/toggle", follow_redirects=True)
    assert response.status_code == 200

    with client.application.app_context():
        assert AppConfig.get("module_wf_enabled") == "1"


def test_toggle_wf_disable_works_without_console_domain(client, login_as):
    from app.models import AppConfig
    login_as("admin")
    AppConfig.set("module_wf_enabled", "1")
    AppConfig.set("console_site_id", None)

    response = client.post("/modules/wf/toggle", follow_redirects=True)
    assert response.status_code == 200

    with client.application.app_context():
        assert AppConfig.get("module_wf_enabled") == "0"
