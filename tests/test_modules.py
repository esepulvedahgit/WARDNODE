import subprocess
import sys
from types import SimpleNamespace

from app.models import AppConfig, ROLE_OPERATOR


def test_obs_activate_starts_only_obs_services(client, login_as, monkeypatch, tmp_path):
    login_as()
    compose_file = tmp_path / "docker-compose.vps.yml"
    compose_file.write_text("services: {}\n")

    state = {"created": False, "cmd": None, "cwd": None}

    class NotFound(Exception):
        pass

    class FakeContainers:
        def get(self, name):
            if not state["created"]:
                raise NotFound(name)
            return SimpleNamespace(status="running")

    fake_docker = SimpleNamespace(
        from_env=lambda: SimpleNamespace(containers=FakeContainers()),
        errors=SimpleNamespace(NotFound=NotFound),
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
    assert state["cmd"][-5:] == ["loki", "grafana", "alloy", "prometheus", "nginx-exporter"]


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


def test_obs_auth_requires_admin_session(client, login_as):
    AppConfig.set("module_obs_enabled", "1")

    response = client.get("/modules/obs/auth")
    assert response.status_code == 401

    login_as(ROLE_OPERATOR)
    response = client.get("/modules/obs/auth")
    assert response.status_code == 403

    login_as(email="admin-obs@example.com")
    response = client.get("/modules/obs/auth")
    assert response.status_code == 204


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
