import subprocess
import sys
from types import SimpleNamespace

from app.models import AppConfig, ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER


def test_obs_activate_starts_only_obs_services(client, login_as, monkeypatch, tmp_path):
    login_as()
    AppConfig.set("module_wf_enabled", "1")  # gate: WF debe estar activo
    monkeypatch.setattr("app.modules.socket_client.ufw_is_operational", lambda **kw: True)
    compose_file = tmp_path / "docker-compose.vps.yml"
    compose_file.write_text("services: {}\n")

    state = {"created": False, "cmd": None, "cwd": None}

    class NotFound(Exception):
        pass

    class ImageNotFound(Exception):
        pass

    class FakeContainers:
        def get(self, name):
            if not state["created"]:
                raise NotFound(name)
            return SimpleNamespace(status="running")

    class FakeImages:
        """Simula que todas las imágenes OBS están presentes localmente."""
        def get(self, ref):
            return SimpleNamespace(id=ref)

    fake_docker = SimpleNamespace(
        from_env=lambda: SimpleNamespace(containers=FakeContainers(), images=FakeImages()),
        errors=SimpleNamespace(NotFound=NotFound, ImageNotFound=ImageNotFound),
    )

    def fake_run(cmd, **kwargs):
        state["created"] = True
        state["cmd"] = cmd
        state["cwd"] = kwargs.get("cwd")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setitem(sys.modules, "docker", fake_docker)
    monkeypatch.setenv("WARDNODE_PROJECT_DIR", str(tmp_path))
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("app.modules.routes._inject_obs_nginx_conf", lambda client: True)
    monkeypatch.setattr("app.proxy.services.render_nginx_configs", lambda: [])
    monkeypatch.setattr("app.proxy.geoip_blocklist.reload_nginx", lambda: (True, ""))

    response = client.post("/modules/obs/activate")

    assert response.status_code == 200
    assert response.json == {"ok": True}
    assert state["cwd"] == str(tmp_path)
    assert "--no-deps" in state["cmd"]
    assert "--no-recreate" in state["cmd"]
    # Solo Grafana (visualización): Loki/Alloy/Prometheus arrancan siempre con el stack base.
    assert state["cmd"][-1] == "grafana"
    assert "loki" not in state["cmd"]
    assert "alloy" not in state["cmd"]
    assert "prometheus" not in state["cmd"]
    assert "nginx-exporter" not in state["cmd"]


def test_obs_fullscreen_renders_minimal_embedded_view(client, login_as):
    login_as()
    AppConfig.set("module_obs_enabled", "1")

    response = client.get("/modules/obs/fullscreen")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Grafana fullscreen" in body
    # El iframe se inyecta dinámicamente vía JS después del probe HTTP;
    # verificamos que el scaffolding de readiness esté presente en lugar del tag estático.
    assert "obs/grafana-ready" in body
    assert "Iniciando Grafana" in body
    assert "sidebar" not in body


def test_obs_auth_anon_is_rejected(client):
    AppConfig.set("module_obs_enabled", "1")
    response = client.get("/modules/obs/auth")
    assert response.status_code == 401


def test_obs_auth_operator_gets_viewer_role(client, login_as):
    AppConfig.set("module_obs_enabled", "1")
    op = login_as(ROLE_OPERATOR)
    response = client.get("/modules/obs/auth")
    assert response.status_code == 204
    assert response.headers.get("X-WEBAUTH-USER") == f"wn-{op.id}"
    assert response.headers.get("X-WEBAUTH-ROLE") == "Viewer"


def test_obs_auth_reader_gets_viewer_role(client, login_as):
    AppConfig.set("module_obs_enabled", "1")
    rd = login_as(ROLE_READER)
    response = client.get("/modules/obs/auth")
    assert response.status_code == 204
    assert response.headers.get("X-WEBAUTH-USER") == f"wn-{rd.id}"
    assert response.headers.get("X-WEBAUTH-ROLE") == "Viewer"


def test_obs_auth_admin_gets_editor_role(client, login_as):
    AppConfig.set("module_obs_enabled", "1")
    adm = login_as(email="admin-obs@example.com")
    response = client.get("/modules/obs/auth")
    assert response.status_code == 204
    assert response.headers.get("X-WEBAUTH-USER") == f"wn-{adm.id}"
    assert response.headers.get("X-WEBAUTH-ROLE") == "Editor"


def test_obs_auth_is_exempt_from_rate_limit(app, client, login_as):
    app.config["RATELIMIT_ENABLED"] = True
    app.config["RATELIMIT_DEFAULT"] = "1 per hour"
    login_as(email="admin-obs-ratelimit@example.com")
    AppConfig.set("module_obs_enabled", "1")

    responses = [client.get("/modules/obs/auth") for _ in range(3)]

    assert [response.status_code for response in responses] == [204, 204, 204]


def test_status_is_exempt_from_rate_limit(app, client):
    app.config["RATELIMIT_ENABLED"] = True
    app.config["RATELIMIT_DEFAULT"] = "1 per hour"

    responses = [client.get("/status") for _ in range(3)]

    assert [response.status_code for response in responses] == [200, 200, 200]


def test_obs_status_all_running(client, login_as, monkeypatch):
    from app.models import AppConfig

    login_as()
    AppConfig.set("module_obs_enabled", "1")

    class FakeContainers:
        def get(self, name):
            return SimpleNamespace(status="running")

    fake_docker = SimpleNamespace(
        from_env=lambda: SimpleNamespace(containers=FakeContainers()),
        errors=SimpleNamespace(NotFound=Exception),
    )
    monkeypatch.setitem(sys.modules, "docker", fake_docker)
    monkeypatch.setattr("app.modules.routes._inject_obs_nginx_conf", lambda c: True)
    monkeypatch.setattr("app.proxy.services.render_nginx_configs", lambda: [])
    monkeypatch.setattr("app.proxy.geoip_blocklist.reload_nginx", lambda: (True, ""))

    response = client.post("/modules/obs/status")

    assert response.status_code == 200
    data = response.get_json()
    assert data["ok"] is True
    assert data["loki"] is True
    assert data["grafana"] is True
    assert data["alloy"] is True
    assert data["prometheus"] is True


def test_obs_grafana_ready_true(client, login_as, monkeypatch):
    """obs_grafana_ready devuelve ready=True cuando el probe HTTP tiene éxito."""
    login_as()
    AppConfig.set("module_obs_enabled", "1")
    monkeypatch.setattr("app.modules.routes._grafana_http_ready", lambda timeout=2.0: True)

    response = client.post("/modules/obs/grafana-ready")

    assert response.status_code == 200
    data = response.get_json()
    assert data["ready"] is True


def test_obs_grafana_ready_false(client, login_as, monkeypatch):
    """obs_grafana_ready devuelve ready=False cuando Grafana aún no responde HTTP."""
    login_as()
    AppConfig.set("module_obs_enabled", "1")
    monkeypatch.setattr("app.modules.routes._grafana_http_ready", lambda timeout=2.0: False)

    response = client.post("/modules/obs/grafana-ready")

    assert response.status_code == 200
    data = response.get_json()
    assert data["ready"] is False


def test_obs_grafana_ready_requires_module(client, login_as):
    """obs_grafana_ready devuelve 403 si el módulo OBS no está habilitado."""
    login_as()
    AppConfig.set("module_obs_enabled", "0")

    response = client.post("/modules/obs/grafana-ready")

    assert response.status_code == 403
    data = response.get_json()
    assert data["ready"] is False



def test_obs_activate_handles_docker_unavailable(client, login_as, monkeypatch):
    login_as()
    AppConfig.set("module_wf_enabled", "1")  # gate: WF debe estar activo
    monkeypatch.setattr("app.modules.socket_client.ufw_is_operational", lambda **kw: True)

    def fail_from_env():
        raise Exception("Docker daemon not available")

    fake_docker = SimpleNamespace(
        from_env=fail_from_env,
        errors=SimpleNamespace(NotFound=Exception),
    )
    monkeypatch.setitem(sys.modules, "docker", fake_docker)

    response = client.post("/modules/obs/activate")

    assert response.status_code == 500
    data = response.get_json()
    assert data["ok"] is False
    assert data["step"] == "docker"


def test_obs_activate_missing_project_dir(client, login_as, monkeypatch):
    login_as()
    AppConfig.set("module_wf_enabled", "1")  # gate: WF debe estar activo
    monkeypatch.setattr("app.modules.socket_client.ufw_is_operational", lambda **kw: True)

    class NotFound(Exception):
        pass

    class FakeContainersNotFound:
        def get(self, name):
            raise NotFound(name)

    fake_docker = SimpleNamespace(
        from_env=lambda: SimpleNamespace(containers=FakeContainersNotFound()),
        errors=SimpleNamespace(NotFound=NotFound),
    )
    monkeypatch.setitem(sys.modules, "docker", fake_docker)
    monkeypatch.delenv("WARDNODE_PROJECT_DIR", raising=False)

    response = client.post("/modules/obs/activate")

    assert response.status_code == 500
    data = response.get_json()
    assert data["ok"] is False
    assert data["step"] == "compose"
    assert "WARDNODE_PROJECT_DIR" in data["error"]


# ── Tests de gate de dependencia (WF requerido) ───────────────────────────────

def test_obs_activate_blocked_without_wf(client, login_as, monkeypatch):
    """obs_activate debe rechazar la petición si WF no está activo."""
    login_as()
    AppConfig.set("module_wf_enabled", "0")

    fake_docker = SimpleNamespace(
        from_env=lambda: SimpleNamespace(containers=SimpleNamespace(get=lambda n: None)),
        errors=SimpleNamespace(NotFound=Exception, ImageNotFound=Exception),
    )
    monkeypatch.setitem(sys.modules, "docker", fake_docker)

    response = client.post("/modules/obs/activate")

    assert response.status_code == 400
    data = response.get_json()
    assert data["ok"] is False
    assert data["step"] == "dependency"
    assert "WF" in data["error"] or "wf" in data["error"].lower()
    # OBS no debe haberse activado
    assert AppConfig.get("module_obs_enabled") != "1"


def test_ddos_activate_blocked_without_wf(client, login_as, monkeypatch):
    """ddos_activate debe rechazar la petición si WF no está activo."""
    login_as()
    AppConfig.set("module_wf_enabled", "0")

    fake_docker = SimpleNamespace(
        from_env=lambda: SimpleNamespace(containers=SimpleNamespace(get=lambda n: None)),
        errors=SimpleNamespace(NotFound=Exception, ImageNotFound=Exception),
    )
    monkeypatch.setitem(sys.modules, "docker", fake_docker)

    response = client.post("/modules/ddos/activate")

    assert response.status_code == 400
    data = response.get_json()
    assert data["ok"] is False
    assert data["step"] == "dependency"
    assert AppConfig.get("module_ddos_enabled") != "1"


def test_soc_toggle_blocked_without_wf(client, login_as):
    """toggle de SOC debe no activar el módulo si WF no está activo."""
    login_as()
    AppConfig.set("module_wf_enabled", "0")

    response = client.post("/modules/soc/toggle")

    assert response.status_code == 302  # redirige con flash
    assert AppConfig.get("module_soc_enabled") != "1"


def test_modules_index_locked_cards_without_wf(client, login_as):
    """La página de módulos muestra tarjetas bloqueadas para obs/soc/ddos cuando WF está inactivo."""
    login_as()
    AppConfig.set("module_wf_enabled", "0")

    response = client.get("/modules/")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    # El aviso de bloqueo debe aparecer 3 veces (obs, soc, ddos)
    assert body.count("Requiere WardNode WF activo") == 3
    # El botón Activar debe estar deshabilitado en las tarjetas bloqueadas
    assert "cursor:not-allowed" in body


# ── Tests del gate de UFW real (firewall activo en el host) ───────────────────

def test_obs_activate_blocked_when_ufw_not_operational(client, login_as, monkeypatch):
    """obs_activate rechaza si WF está habilitado pero UFW no está activo en el host."""
    login_as()
    AppConfig.set("module_wf_enabled", "1")
    monkeypatch.setattr("app.modules.socket_client.ufw_is_operational", lambda **kw: False)

    response = client.post("/modules/obs/activate")

    assert response.status_code == 400
    data = response.get_json()
    assert data["ok"] is False
    assert data["step"] == "firewall"
    assert "UFW" in data["error"]
    assert AppConfig.get("module_obs_enabled") != "1"


def test_ddos_activate_blocked_when_ufw_not_operational(client, login_as, monkeypatch):
    """ddos_activate rechaza si WF está habilitado pero UFW no está activo en el host."""
    login_as()
    AppConfig.set("module_wf_enabled", "1")
    monkeypatch.setattr("app.modules.socket_client.ufw_is_operational", lambda **kw: False)

    response = client.post("/modules/ddos/activate")

    assert response.status_code == 400
    data = response.get_json()
    assert data["ok"] is False
    assert data["step"] == "firewall"
    assert AppConfig.get("module_ddos_enabled") != "1"


def test_soc_toggle_blocked_when_ufw_not_operational(client, login_as, monkeypatch):
    """toggle de SOC rechaza si WF está habilitado pero UFW no está activo en el host."""
    login_as()
    AppConfig.set("module_wf_enabled", "1")
    monkeypatch.setattr("app.modules.socket_client.ufw_is_operational", lambda **kw: False)

    response = client.post("/modules/soc/toggle")

    assert response.status_code == 302  # redirige con flash de advertencia
    assert AppConfig.get("module_soc_enabled") != "1"


def test_obs_activate_dependency_gate_wins_over_firewall_gate(client, login_as, monkeypatch):
    """El gate de dependencia (WF no habilitado) tiene precedencia sobre el gate de firewall."""
    login_as()
    AppConfig.set("module_wf_enabled", "0")
    # ufw_is_operational nunca debería llamarse — el gate de dependencia para antes
    monkeypatch.setattr(
        "app.modules.socket_client.ufw_is_operational",
        lambda **kw: (_ for _ in ()).throw(AssertionError("No debería llamarse ufw_is_operational"))
    )

    response = client.post("/modules/obs/activate")

    assert response.status_code == 400
    data = response.get_json()
    assert data["step"] == "dependency"


def test_ufw_is_operational_fail_closed_on_unreachable_agent(monkeypatch):
    """ufw_is_operational devuelve False si el agente WF no responde (fail-closed)."""
    from app.modules.socket_client import ufw_is_operational
    monkeypatch.setattr(
        "app.modules.socket_client.send_command",
        lambda action, **kw: {"ok": False, "error": "socket no encontrado"},
    )
    assert ufw_is_operational() is False


def test_ufw_is_operational_false_when_inactive(monkeypatch):
    """ufw_is_operational devuelve False si UFW está inactive aunque el agente responde."""
    from app.modules.socket_client import ufw_is_operational

    def fake_send(action, **kw):
        if action == "status":
            return {"ok": True, "output": "Status: inactive\n"}
        return {"ok": True, "output": "Status: inactive\nDefault: deny (incoming), allow (outgoing)"}

    monkeypatch.setattr("app.modules.socket_client.send_command", fake_send)
    assert ufw_is_operational() is False


def test_ufw_is_operational_true_when_active_and_initialized(monkeypatch):
    """ufw_is_operational devuelve True cuando UFW está activo e inicializado."""
    from app.modules.socket_client import ufw_is_operational

    def fake_send(action, **kw):
        if action == "status":
            return {"ok": True, "output": "Status: active\n"}
        return {
            "ok": True,
            "output": "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n",
        }

    monkeypatch.setattr("app.modules.socket_client.send_command", fake_send)
    assert ufw_is_operational() is True


def test_wf_status_returns_active_and_initialized_fields(client, login_as, monkeypatch):
    """wf_status devuelve los campos 'active' e 'initialized' además de 'output'."""
    login_as()
    AppConfig.set("module_wf_enabled", "1")

    def fake_send(action, **kw):
        if action == "status":
            return {"ok": True, "output": "Status: active\n1  ALLOW IN  22/tcp"}
        return {
            "ok": True,
            "output": "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n",
        }

    monkeypatch.setattr("app.modules.socket_client.send_command", fake_send)

    response = client.post("/modules/wf/status")

    assert response.status_code == 200
    data = response.get_json()
    assert data["ok"] is True
    assert data["initialized"] is True
    assert data["active"] is True
    assert "output" in data
    assert "defaults_output" in data
