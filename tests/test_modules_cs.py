from app.models import AppConfig, ROLE_OPERATOR


def _enable_wf_and_cs():
    AppConfig.set("module_wf_enabled", "1")
    AppConfig.set("module_cs_enabled", "1")


def _fake_cmd_ok(action, **kwargs):
    return {"ok": True, "output": f"action={action}"}


# ── Status ────────────────────────────────────────────────────────────────────

def test_cs_status_ok(client, login_as, monkeypatch):
    login_as()
    _enable_wf_and_cs()

    def fake_cmd(action, **kwargs):
        return {"ok": True, "output": "CrowdSec running. Alerts: 5."}

    monkeypatch.setattr("app.modules.routes.send_command", fake_cmd)
    response = client.post("/modules/cs/status")

    assert response.status_code == 200
    assert response.get_json()["ok"] is True


# ── Ban ───────────────────────────────────────────────────────────────────────

def test_cs_ban_ip_valid(client, login_as, monkeypatch):
    login_as()
    _enable_wf_and_cs()
    calls = []

    def fake_cmd(action, **kwargs):
        calls.append({"action": action, **kwargs})
        return {"ok": True, "output": "Banned"}

    monkeypatch.setattr("app.modules.routes.send_command", fake_cmd)
    response = client.post("/modules/cs/ban", data={"ip": "10.0.0.1", "duration": "24h", "reason": "manual"})

    assert response.status_code == 200
    assert response.get_json()["ok"] is True
    assert calls[0]["action"] == "cs_ban"
    assert calls[0]["ip"] == "10.0.0.1"
    assert calls[0]["duration"] == "24h"


def test_cs_ban_ip_invalid_duration(client, login_as, monkeypatch):
    login_as()
    _enable_wf_and_cs()
    monkeypatch.setattr("app.modules.routes.send_command", _fake_cmd_ok)

    response = client.post("/modules/cs/ban", data={"ip": "10.0.0.1", "duration": "999y", "reason": "test"})

    assert response.status_code == 400
    assert response.get_json()["ok"] is False


def test_cs_ban_reason_invalid(client, login_as, monkeypatch):
    login_as()
    _enable_wf_and_cs()
    monkeypatch.setattr("app.modules.routes.send_command", _fake_cmd_ok)

    response = client.post("/modules/cs/ban", data={"ip": "10.0.0.1", "duration": "24h", "reason": "bad; reason!"})

    assert response.status_code == 400
    assert response.get_json()["ok"] is False


# ── Unban ─────────────────────────────────────────────────────────────────────

def test_cs_unban_ip_valid(client, login_as, monkeypatch):
    login_as()
    _enable_wf_and_cs()
    calls = []

    def fake_cmd(action, **kwargs):
        calls.append({"action": action, **kwargs})
        return {"ok": True, "output": "Unbanned"}

    monkeypatch.setattr("app.modules.routes.send_command", fake_cmd)
    response = client.post("/modules/cs/unban", data={"ip": "10.0.0.1"})

    assert response.status_code == 200
    assert response.get_json()["ok"] is True
    assert calls[0]["action"] == "cs_unban"
    assert calls[0]["ip"] == "10.0.0.1"


# ── Requires WF ───────────────────────────────────────────────────────────────

def test_cs_requires_wf_enabled(client, login_as, monkeypatch):
    login_as()
    AppConfig.set("module_wf_enabled", "0")
    AppConfig.set("module_cs_enabled", "1")
    monkeypatch.setattr("app.modules.routes.send_command", _fake_cmd_ok)

    response = client.post("/modules/cs/status")

    assert response.status_code == 403
    assert response.get_json()["ok"] is False


# ── RBAC ──────────────────────────────────────────────────────────────────────

def test_cs_requires_admin_role(client, login_as, monkeypatch):
    _enable_wf_and_cs()
    login_as(role=ROLE_OPERATOR)
    monkeypatch.setattr("app.modules.routes.send_command", _fake_cmd_ok)

    response = client.post("/modules/cs/status")

    assert response.status_code == 403
